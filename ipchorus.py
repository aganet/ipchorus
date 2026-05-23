#!/usr/bin/env python3
"""ipchorus — live per-IP network monitor with reverse DNS and WHOIS."""

from __future__ import annotations

import argparse
import getpass
import ipaddress
import os
import shutil
import socket
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

import psutil
from rich.text import Text
from scapy.all import ICMP, IP, IPv6, TCP, UDP, AsyncSniffer
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import DataTable, Footer, Header, Static


# colour palette: green = ingress (download), cyan = egress (upload)
ARROW_IN = "⬇"
ARROW_OUT = "⬆"
ARROW_BOTH = "⇅"
COLOR_IN = "green"
COLOR_OUT = "cyan"
COLOR_BOTH = "yellow"


# ---------- helpers ----------

def get_local_ips() -> set[str]:
    ips: set[str] = set()
    for addrs in psutil.net_if_addrs().values():
        for a in addrs:
            if a.family in (socket.AF_INET, socket.AF_INET6):
                ips.add(a.address.split("%")[0])
    return ips


def fmt_bytes(n: float) -> str:
    n = float(n)
    for unit in ("B", "K", "M", "G", "T"):
        if n < 1024:
            return f"{n:6.1f}{unit}"
        n /= 1024
    return f"{n:6.1f}P"


def fmt_rate(n: float) -> str:
    return fmt_bytes(n) + "/s"


_CGNAT_NET = ipaddress.IPv4Network("100.64.0.0/10")


def compute_local_broadcasts() -> set[str]:
    """Subnet broadcast addresses for every local IPv4 interface."""
    out: set[str] = set()
    for addrs in psutil.net_if_addrs().values():
        for a in addrs:
            if a.family == socket.AF_INET and a.netmask:
                try:
                    net = ipaddress.IPv4Network(f"{a.address}/{a.netmask}", strict=False)
                    if net.prefixlen < 32:
                        out.add(str(net.broadcast_address))
                except Exception:
                    pass
    return out


def classify_ip(ip: str, bcasts: frozenset[str] | set[str] = frozenset()) -> tuple[str, str]:
    """Return (label, rich-style) for an IP's network class."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ("?", "dim")
    if a.is_loopback:
        return ("local", "dim white")
    if a.is_multicast:
        return ("mcast", "magenta")
    if isinstance(a, ipaddress.IPv4Address):
        if str(a) == "255.255.255.255" or ip in bcasts:
            return ("bcast", "bold red")
        if a.is_link_local:
            return ("link", "orange3")
        if a in _CGNAT_NET:
            return ("cgnat", "magenta")
        if a.is_private:
            return ("lan", "yellow")
        if a.is_reserved or a.is_unspecified:
            return ("rsvd", "dim")
        return ("public", "white")
    # IPv6
    if a.is_link_local:
        return ("link", "orange3")
    if a.is_private:
        return ("lan", "yellow")
    if a.is_reserved or a.is_unspecified:
        return ("rsvd", "dim")
    return ("public", "white")


def dir_indicator(bytes_in: int, bytes_out: int) -> tuple[str, str, str]:
    """Return (arrow, color, label) for the dominant direction of a flow."""
    total = bytes_in + bytes_out
    if total == 0:
        return ("·", "dim", "idle")
    in_pct = bytes_in / total
    if in_pct >= 0.85:
        return (ARROW_IN, COLOR_IN, "ingress")
    if in_pct <= 0.15:
        return (ARROW_OUT, COLOR_OUT, "egress")
    return (ARROW_BOTH, COLOR_BOTH, "mixed")


# ---------- traffic tracking ----------

@dataclass
class FlowStats:
    bytes_in: int = 0
    bytes_out: int = 0
    pkts_in: int = 0
    pkts_out: int = 0
    last_seen: float = field(default_factory=time.time)
    prev_bytes_in: int = 0
    prev_bytes_out: int = 0
    rate_in: float = 0.0
    rate_out: float = 0.0
    protocols: set[str] = field(default_factory=set)


def _packet_proto(pkt) -> str | None:
    if TCP in pkt:
        return "TCP"
    if UDP in pkt:
        return "UDP"
    if ICMP in pkt:
        return "ICMP"
    return None


class TrafficTracker:
    def __init__(self) -> None:
        self.local_ips = get_local_ips()
        self.local_bcasts = compute_local_broadcasts()
        self.flows: dict[str, FlowStats] = defaultdict(FlowStats)
        self.lock = threading.Lock()

    def handle_packet(self, pkt) -> None:
        if IP in pkt:
            layer = pkt[IP]
        elif IPv6 in pkt:
            layer = pkt[IPv6]
        else:
            return
        src, dst = layer.src, layer.dst
        length = len(pkt)
        proto = _packet_proto(pkt)
        now = time.time()
        with self.lock:
            # outgoing: src is ours, dst isn't
            # incoming: dst is ours, src isn't
            # broadcast/multicast destinations always count as "out" from us
            remote = None
            direction = None
            if src in self.local_ips and dst not in self.local_ips:
                remote, direction = dst, "out"
            elif dst in self.local_ips and src not in self.local_ips:
                remote, direction = src, "in"
            if remote is None:
                return
            s = self.flows[remote]
            if direction == "out":
                s.bytes_out += length
                s.pkts_out += 1
            else:
                s.bytes_in += length
                s.pkts_in += 1
            s.last_seen = now
            if proto:
                s.protocols.add(proto)

    def tick_rates(self, interval: float) -> None:
        with self.lock:
            for s in self.flows.values():
                s.rate_in = (s.bytes_in - s.prev_bytes_in) / interval
                s.rate_out = (s.bytes_out - s.prev_bytes_out) / interval
                s.prev_bytes_in = s.bytes_in
                s.prev_bytes_out = s.bytes_out

    def snapshot(self) -> dict[str, FlowStats]:
        with self.lock:
            out: dict[str, FlowStats] = {}
            for ip, s in self.flows.items():
                d = vars(s).copy()
                d["protocols"] = set(s.protocols)
                out[ip] = FlowStats(**d)
            return out

    def clear(self) -> None:
        with self.lock:
            self.flows.clear()


# ---------- reverse DNS (async + cached) ----------

class DNSResolver:
    def __init__(self, max_workers: int = 4) -> None:
        self.cache: dict[str, str] = {}
        self.pending: set[str] = set()
        self.lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="dns")

    def get(self, ip: str) -> str:
        with self.lock:
            if ip in self.cache:
                return self.cache[ip]
            if ip in self.pending:
                return ""
            self.pending.add(ip)
        self.executor.submit(self._resolve, ip)
        return ""

    def _resolve(self, ip: str) -> None:
        try:
            host = socket.gethostbyaddr(ip)[0]
        except Exception:
            host = ""
        with self.lock:
            self.cache[ip] = host
            self.pending.discard(ip)

    def is_resolved(self, ip: str) -> bool:
        with self.lock:
            return ip in self.cache


# ---------- WHOIS / RDAP (lazy on selection) ----------

class WhoisLookup:
    def __init__(self, max_workers: int = 4) -> None:
        self.cache: dict[str, dict] = {}
        self.pending: set[str] = set()
        self.callbacks: dict[str, list] = {}
        self.lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="whois")

    def cached(self, ip: str) -> dict | None:
        with self.lock:
            return self.cache.get(ip)

    def fetch(self, ip: str, callback=None) -> None:
        """Idempotent async RDAP lookup. Callback fires once when result is in."""
        with self.lock:
            if ip in self.cache:
                if callback:
                    cb_result = self.cache[ip]
                else:
                    return
            else:
                if ip in self.pending:
                    if callback:
                        self.callbacks.setdefault(ip, []).append(callback)
                    return
                self.pending.add(ip)
                if callback:
                    self.callbacks.setdefault(ip, []).append(callback)
                self.executor.submit(self._run, ip)
                return
        callback(ip, cb_result)

    def _run(self, ip: str) -> None:
        try:
            from ipwhois import IPWhois
            result = IPWhois(ip).lookup_rdap(depth=1)
        except Exception as e:
            result = {"error": f"{type(e).__name__}: {e}"}
        with self.lock:
            self.cache[ip] = result
            self.pending.discard(ip)
            callbacks = self.callbacks.pop(ip, [])
        for cb in callbacks:
            try:
                cb(ip, result)
            except Exception:
                pass


GEOIP_DB_NAME = "GeoLite2-Country.mmdb"
GEOIP_DEFAULT_DIR = os.path.expanduser("~/.local/share/ipchorus")


def _find_geoip_db() -> str | None:
    for path in (
        os.environ.get("IPCHORUS_GEOIP_DB"),
        os.path.join(GEOIP_DEFAULT_DIR, GEOIP_DB_NAME),
        f"/usr/share/GeoIP/{GEOIP_DB_NAME}",
        f"/var/lib/GeoIP/{GEOIP_DB_NAME}",
    ):
        if path and os.path.isfile(path):
            return path
    return None


class GeoIPLookup:
    """Country lookup against a local MaxMind GeoLite2-Country .mmdb."""

    def __init__(self, db_path: str | None = None) -> None:
        self.path = db_path or _find_geoip_db()
        self.reader = None
        if self.path:
            try:
                import geoip2.database
                self.reader = geoip2.database.Reader(self.path)
            except Exception:
                self.reader = None
        self.cache: dict[str, tuple[str, str]] = {}
        self.lock = threading.Lock()

    @property
    def available(self) -> bool:
        return self.reader is not None

    def lookup(self, ip: str) -> tuple[str, str]:
        """Return (ISO-2 country code, country name); empty strings if unknown."""
        if not self.reader:
            return ("", "")
        with self.lock:
            if ip in self.cache:
                return self.cache[ip]
        try:
            r = self.reader.country(ip)
            result = (r.country.iso_code or "", r.country.name or "")
        except Exception:
            result = ("", "")
        with self.lock:
            self.cache[ip] = result
        return result


def setup_geoip(license_key: str | None = None) -> int:
    """Download MaxMind GeoLite2-Country DB into ~/.local/share/ipchorus/."""
    if not license_key:
        print("A free MaxMind license key is required.")
        print("  1) sign up: https://www.maxmind.com/en/geolite2/signup")
        print("  2) generate a license key in your account dashboard")
        try:
            license_key = getpass.getpass("Paste license key (hidden): ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 2
    if not license_key:
        print("No license key provided.")
        return 2

    url = (
        "https://download.maxmind.com/app/geoip_download"
        f"?edition_id=GeoLite2-Country&license_key={license_key}&suffix=tar.gz"
    )
    os.makedirs(GEOIP_DEFAULT_DIR, exist_ok=True)
    dest = os.path.join(GEOIP_DEFAULT_DIR, GEOIP_DB_NAME)

    print(f"Downloading GeoLite2-Country from MaxMind ...")
    tmp_path = ""
    try:
        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
            tmp_path = tmp.name
            try:
                with urllib.request.urlopen(url, timeout=60) as r:
                    shutil.copyfileobj(r, tmp)
            except urllib.error.HTTPError as e:
                msg = "invalid license key" if e.code == 401 else str(e)
                print(f"  ✗ download failed ({e.code}): {msg}")
                return 3
            except Exception as e:
                print(f"  ✗ download failed: {e}")
                return 3

        with tarfile.open(tmp_path) as tar:
            mmdb = next((m for m in tar.getmembers() if m.name.endswith(".mmdb")), None)
            if not mmdb:
                print("  ✗ no .mmdb file in archive")
                return 4
            extracted = tar.extractfile(mmdb)
            if extracted is None:
                print("  ✗ could not extract .mmdb")
                return 4
            with open(dest, "wb") as f:
                shutil.copyfileobj(extracted, f)

        size_mb = os.path.getsize(dest) / (1024 * 1024)
        print(f"  ✓ installed: {dest}  ({size_mb:.1f} MB)")
        print("ipchorus will use this database automatically.")
        return 0
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


def whois_org(result: dict | None) -> str:
    """Extract a friendly org name from an RDAP result."""
    if not result or "error" in result:
        return ""
    desc = (result.get("asn_description") or "").strip()
    if desc:
        if " - " in desc:
            desc = desc.split(" - ", 1)[1]
        return desc.split(",")[0].strip()
    net = result.get("network") or {}
    return (net.get("name") or "").strip()


def format_whois(
    ip: str,
    r: dict,
    stats: FlowStats | None = None,
    host: str = "",
    geo: tuple[str, str] | None = None,
) -> str:
    header = f"[b white on blue] {ip} [/b white on blue]"
    if host:
        header += f"  [i]{host}[/i]"
    if stats is not None:
        arrow, color, label = dir_indicator(stats.bytes_in, stats.bytes_out)
        header += (
            f"\n[{COLOR_IN}]{ARROW_IN} ingress[/{COLOR_IN}]  "
            f"[b]{fmt_rate(stats.rate_in)}[/b]  total [b]{fmt_bytes(stats.bytes_in)}[/b]   "
            f"[{COLOR_OUT}]{ARROW_OUT} egress [/{COLOR_OUT}]  "
            f"[b]{fmt_rate(stats.rate_out)}[/b]  total [b]{fmt_bytes(stats.bytes_out)}[/b]   "
            f"[{color}]{arrow} {label}[/{color}]"
        )
    if "error" in r:
        return f"{header}\n[red]WHOIS error:[/red] {r['error']}"
    net = r.get("network") or {}
    asn = r.get("asn") or "?"
    asn_desc = r.get("asn_description") or "?"
    country = r.get("asn_country_code") or net.get("country") or "?"
    name = net.get("name") or "?"
    cidr = net.get("cidr") or "?"
    registry = r.get("asn_registry") or "?"
    geo_line = ""
    if geo and geo[0]:
        cc, gname = geo
        geo_line = f"[b]Geo:[/b]      [bright_cyan]{gname or cc} ({cc})[/bright_cyan]\n"
    return (
        f"{header}\n"
        f"{geo_line}"
        f"[b]Org:[/b]      {asn_desc}    "
        f"[b]ASN:[/b] AS{asn} [dim]({registry})[/dim]    "
        f"[b]Registry country:[/b] {country}\n"
        f"[b]Network:[/b]  {name}  [dim]({cidr})[/dim]"
    )


# ---------- Textual UI ----------

SORT_KEYS = [
    ("rate_in",   f"{ARROW_IN} Ingress B/s"),
    ("rate_out",  f"{ARROW_OUT} Egress B/s"),
    ("bytes_in",  f"{ARROW_IN} Total ingress"),
    ("bytes_out", f"{ARROW_OUT} Total egress"),
    ("last_seen", "Last seen"),
    ("ip",        "IP"),
]


class SummaryBar(Static):
    """Top banner showing aggregate ingress/egress + rates + host counts."""

    def update_totals(self, snap: dict[str, FlowStats], n_local: int) -> None:
        total_in = sum(s.bytes_in for s in snap.values())
        total_out = sum(s.bytes_out for s in snap.values())
        rate_in = sum(s.rate_in for s in snap.values())
        rate_out = sum(s.rate_out for s in snap.values())
        n_in = sum(1 for s in snap.values() if s.bytes_in > 0)
        n_out = sum(1 for s in snap.values() if s.bytes_out > 0)
        self.update(
            f"[b {COLOR_IN}]{ARROW_IN} INGRESS[/b {COLOR_IN}]   "
            f"rate [b]{fmt_rate(rate_in):>12s}[/b]   "
            f"total [b]{fmt_bytes(total_in):>10s}[/b]   "
            f"from [b]{n_in:>3d}[/b] hosts\n"
            f"[b {COLOR_OUT}]{ARROW_OUT} EGRESS [/b {COLOR_OUT}]   "
            f"rate [b]{fmt_rate(rate_out):>12s}[/b]   "
            f"total [b]{fmt_bytes(total_out):>10s}[/b]   "
            f"to   [b]{n_out:>3d}[/b] hosts   "
            f"[dim](local: {n_local} IPs)[/dim]"
        )


class IPChorusApp(App):
    CSS = """
    Screen { layout: vertical; }
    #summary {
        height: 4;
        border: round $accent;
        padding: 0 1;
        background: $panel;
        content-align: left middle;
    }
    DataTable { height: 1fr; }
    DataTable > .datatable--header {
        background: $boost;
        text-style: bold;
    }
    #detail {
        height: 6;
        border: round $accent;
        padding: 0 1;
        background: $panel;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("s", "cycle_sort", "Sort"),
        Binding("r", "reverse", "Reverse"),
        Binding("c", "clear", "Clear stats"),
        Binding("w,enter", "lookup", "WHOIS"),
    ]

    def __init__(self, iface: str | None = None, bpf: str | None = None) -> None:
        super().__init__()
        self.tracker = TrafficTracker()
        self.dns = DNSResolver()
        self.whois = WhoisLookup()
        self.geoip = GeoIPLookup()
        self.iface = iface
        self.bpf = bpf
        self.sniffer: AsyncSniffer | None = None
        self.tick_interval = 1.0
        self.sort_idx = 0
        self.sort_reverse = True
        self.selected_ip: str | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield SummaryBar("", id="summary")
        yield DataTable(id="table", cursor_type="row", zebra_stripes=True)
        yield Static(
            f"Select a row and press [b]Enter[/b] or [b]w[/b] for WHOIS details.  "
            f"[{COLOR_IN}]{ARROW_IN}[/{COLOR_IN}] ingress   "
            f"[{COLOR_OUT}]{ARROW_OUT}[/{COLOR_OUT}] egress   "
            f"[{COLOR_BOTH}]{ARROW_BOTH}[/{COLOR_BOTH}] mixed",
            id="detail",
        )
        yield Footer()

    def on_mount(self) -> None:
        self.title = "ipchorus"
        table = self.query_one(DataTable)
        table.add_columns(
            "IP",
            "Hostname",
            "Type",
            "Dir",
            Text(f"{ARROW_IN} Ingress B/s", style=COLOR_IN),
            Text(f"{ARROW_OUT} Egress B/s", style=COLOR_OUT),
            Text(f"{ARROW_IN} Total", style=COLOR_IN),
            Text(f"{ARROW_OUT} Total", style=COLOR_OUT),
            "Pkts I/O",
        )

        kwargs: dict = {"prn": self.tracker.handle_packet, "store": False}
        if self.iface:
            kwargs["iface"] = self.iface
        if self.bpf:
            kwargs["filter"] = self.bpf
        try:
            self.sniffer = AsyncSniffer(**kwargs)
            self.sniffer.start()
        except Exception as e:
            self.query_one("#detail", Static).update(
                f"[red]Cannot start packet capture:[/red] {e}\n"
                "Run with sudo, or grant cap_net_raw to python."
            )

        self.set_interval(self.tick_interval, self.refresh_data)
        self._update_subtitle()

    def on_unmount(self) -> None:
        if self.sniffer and self.sniffer.running:
            try:
                self.sniffer.stop()
            except Exception:
                pass

    def _type_cell(self, ip: str, protocols: set[str]) -> Text:
        label, style = classify_ip(ip, self.tracker.local_bcasts)
        cell = Text(label, style=style)
        if self.geoip.available and label == "public":
            cc, _ = self.geoip.lookup(ip)
            if cc:
                cell.append(" ")
                cell.append(cc, style="bold bright_cyan")
        if protocols:
            cell.append(" ")
            cell.append("·".join(sorted(protocols)), style="dim")
        return cell

    def _host_cell(self, ip: str, host: str, auto_whois: bool) -> Text:
        if host:
            return Text(host, style="yellow")
        if self.dns.is_resolved(ip):
            org = whois_org(self.whois.cached(ip))
            if org:
                return Text(org, style=f"italic {COLOR_OUT}")
            if auto_whois:
                self.whois.fetch(ip)
            return Text("…", style="dim italic")
        return Text("…", style="dim")

    def _update_subtitle(self) -> None:
        key, label = SORT_KEYS[self.sort_idx]
        arrow = "↓" if self.sort_reverse else "↑"
        self.sub_title = f"sort: {label} {arrow}   local: {len(self.tracker.local_ips)} IPs"

    def refresh_data(self) -> None:
        self.tracker.tick_rates(self.tick_interval)
        snap = self.tracker.snapshot()
        key, _ = SORT_KEYS[self.sort_idx]
        if key == "ip":
            rows = sorted(snap.items(), key=lambda kv: kv[0], reverse=self.sort_reverse)
        else:
            rows = sorted(snap.items(), key=lambda kv: getattr(kv[1], key), reverse=self.sort_reverse)

        table = self.query_one(DataTable)
        # remember cursor row's IP to restore after rebuild
        cur_ip = self.selected_ip
        if table.row_count and table.cursor_row is not None and table.cursor_row < table.row_count:
            try:
                cur_ip = table.coordinate_to_cell_key((table.cursor_row, 0)).row_key.value
            except Exception:
                pass

        table.clear()
        ip_to_row: dict[str, int] = {}
        for idx, (ip, s) in enumerate(rows[:300]):
            host = self.dns.get(ip)
            host_cell = self._host_cell(ip, host, auto_whois=idx < 50)
            type_cell = self._type_cell(ip, s.protocols)
            arrow, color, _ = dir_indicator(s.bytes_in, s.bytes_out)
            in_style = COLOR_IN if s.rate_in > 0 else "dim"
            out_style = COLOR_OUT if s.rate_out > 0 else "dim"
            table.add_row(
                Text(ip, style="bold"),
                host_cell,
                type_cell,
                Text(arrow, style=f"bold {color}", justify="center"),
                Text(fmt_rate(s.rate_in), style=in_style),
                Text(fmt_rate(s.rate_out), style=out_style),
                Text(fmt_bytes(s.bytes_in), style=COLOR_IN if s.bytes_in else "dim"),
                Text(fmt_bytes(s.bytes_out), style=COLOR_OUT if s.bytes_out else "dim"),
                Text.assemble(
                    (str(s.pkts_in), COLOR_IN),
                    "/",
                    (str(s.pkts_out), COLOR_OUT),
                ),
                key=ip,
            )
            ip_to_row[ip] = idx

        if cur_ip and cur_ip in ip_to_row:
            try:
                table.move_cursor(row=ip_to_row[cur_ip])
            except Exception:
                pass

        self.query_one(SummaryBar).update_totals(snap, len(self.tracker.local_ips))
        self._update_subtitle()

    # ----- actions -----

    def action_cycle_sort(self) -> None:
        self.sort_idx = (self.sort_idx + 1) % len(SORT_KEYS)
        self._update_subtitle()

    def action_reverse(self) -> None:
        self.sort_reverse = not self.sort_reverse
        self._update_subtitle()

    def action_clear(self) -> None:
        self.tracker.clear()

    def _lookup_ip(self, ip: str) -> None:
        if not ip:
            return
        self.selected_ip = ip
        detail = self.query_one("#detail", Static)
        stats = self.tracker.snapshot().get(ip)
        host = self.dns.get(ip)
        geo = self.geoip.lookup(ip) if self.geoip.available else None
        cached = self.whois.cached(ip)
        if cached:
            detail.update(format_whois(ip, cached, stats, host, geo))
        else:
            detail.update(f"Looking up WHOIS for [b]{ip}[/b]…")
            self.whois.fetch(ip, lambda i, r: self.call_from_thread(self._whois_done, i, r))

    def action_lookup(self) -> None:
        table = self.query_one(DataTable)
        if not table.row_count or table.cursor_row is None:
            return
        try:
            ip = table.coordinate_to_cell_key((table.cursor_row, 0)).row_key.value
        except Exception:
            return
        self._lookup_ip(ip)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        ip = event.row_key.value if event.row_key else None
        self._lookup_ip(ip or "")

    def _whois_done(self, ip: str, result: dict) -> None:
        if self.selected_ip == ip:
            stats = self.tracker.snapshot().get(ip)
            host = self.dns.get(ip)
            geo = self.geoip.lookup(ip) if self.geoip.available else None
            self.query_one("#detail", Static).update(format_whois(ip, result, stats, host, geo))


# ---------- self-test (no TUI) ----------

def selftest(duration: float) -> int:
    print(f"Python {sys.version.split()[0]}")
    tr = TrafficTracker()
    print(f"Local IPs ({len(tr.local_ips)}): {', '.join(sorted(tr.local_ips)[:6])}{'…' if len(tr.local_ips) > 6 else ''}")

    print(f"Sniffing for {duration:.0f}s...")
    try:
        s = AsyncSniffer(prn=tr.handle_packet, store=False)
        s.start()
    except Exception as e:
        print(f"  ✗ capture failed: {e}  (need root / cap_net_raw)")
        return 1
    time.sleep(duration)
    try:
        s.stop()
    except Exception:
        pass

    tr.tick_rates(duration)
    snap = tr.snapshot()
    print(f"Captured flows: {len(snap)}")
    top = sorted(snap.items(), key=lambda kv: kv[1].bytes_in + kv[1].bytes_out, reverse=True)[:5]
    for ip, st in top:
        print(f"  {ip:40s}  in={fmt_bytes(st.bytes_in)}  out={fmt_bytes(st.bytes_out)}  pkts={st.pkts_in}/{st.pkts_out}")

    if top:
        ip = top[0][0]
        print(f"\nReverse DNS for {ip}: ", end="", flush=True)
        try:
            print(socket.gethostbyaddr(ip)[0])
        except Exception as e:
            print(f"(failed: {e})")

        print(f"RDAP for {ip}:")
        try:
            from ipwhois import IPWhois
            r = IPWhois(ip).lookup_rdap(depth=1)
            print(f"  ASN: AS{r.get('asn')}  {r.get('asn_description')}  [{r.get('asn_country_code')}]")
        except Exception as e:
            print(f"  RDAP failed: {e}")
    return 0


# ---------- entry point ----------

def main() -> int:
    p = argparse.ArgumentParser(description="ipchorus — live per-IP network monitor")
    p.add_argument("-i", "--iface", help="network interface to sniff (default: all)")
    p.add_argument("-f", "--filter", help="BPF filter (e.g. 'not port 22')")
    p.add_argument("--selftest", type=float, nargs="?", const=5.0,
                   help="run a non-UI sniff for N seconds (default 5) and exit")
    p.add_argument("--setup-geoip", action="store_true",
                   help="download MaxMind GeoLite2-Country DB (needs a free license key)")
    args = p.parse_args()

    if args.setup_geoip:
        return setup_geoip()
    if args.selftest is not None:
        return selftest(args.selftest)

    IPChorusApp(iface=args.iface, bpf=args.filter).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
