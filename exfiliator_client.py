#!/usr/bin/env python3
"""
Exfiliator Client - Purple-team network control test client with PSK + HTML report.

Features:
- TCP / UDP / HTTP tests driven by JSON config
- PSK required
- Progress bars (no third-party deps)
- Verbose logging (-v / -vv)
- Press 'Q' to quit monitor (still writes report with partial results)
- UDP modes:
    * reliable   : ACK every packet (slowest)
    * batched_ack: range/batch ACKs (faster)
    * firehose   : no DATA ACKs (fastest; reachability via HELLO_ACK)

Run controls:
- --allow-udp-modes reliable,batched_ack   (mode allowlist for this run)
- --udp-mode-override batched_ack          (force all UDP tests to a mode)

NEW:
- --server <ip|hostname> (default 127.0.0.1)
  * Used as default for TCP/UDP config entries missing "host"
- --force-server
  * Overrides all TCP/UDP hosts in config for this run
- Timestamped HTML report filename by default
- HTML report includes client host/device + network info + server parameter used + targets summary

Standard library only.
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import logging
import os
import platform
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

log = logging.getLogger("exfiliator_client")


# -------------------------
# Cross-platform "press Q to quit"
# -------------------------

class QuitMonitor:
    def __init__(self) -> None:
        self.stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self, enable: bool = True) -> None:
        if not enable:
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        try:
            if os.name == "nt":
                import msvcrt  # type: ignore
                while not self.stop_event.is_set():
                    if msvcrt.kbhit():
                        ch = msvcrt.getwch()
                        if ch in ("q", "Q"):
                            self.stop_event.set()
                            return
                    time.sleep(0.05)
            else:
                import select
                import termios
                import tty
                fd = sys.stdin.fileno()
                old = termios.tcgetattr(fd)
                try:
                    tty.setcbreak(fd)
                    while not self.stop_event.is_set():
                        r, _, _ = select.select([sys.stdin], [], [], 0.2)
                        if r:
                            ch = sys.stdin.read(1)
                            if ch in ("q", "Q"):
                                self.stop_event.set()
                                return
                finally:
                    termios.tcsetattr(fd, termios.TCSADRAIN, old)
        except Exception:
            # Non-interactive stdin etc.
            return


# -------------------------
# Progress bars
# -------------------------

def _fmt_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n/1024:.1f} KB"
    if n < 1024 * 1024 * 1024:
        return f"{n/(1024*1024):.1f} MB"
    return f"{n/(1024*1024*1024):.1f} GB"


def progress_bar(prefix: str, done: int, total: int, width: int = 26) -> str:
    total = max(1, int(total))
    ratio = max(0.0, min(1.0, done / total))
    filled = int(ratio * width)
    bar = "#" * filled + "-" * (width - filled)
    pct = int(ratio * 100)
    return f"{prefix} [{bar}] {pct:3d}% ({done}/{total})"


def print_progress_line(line: str) -> None:
    sys.stdout.write("\r" + line + " " * 10)
    sys.stdout.flush()


def end_progress_line() -> None:
    sys.stdout.write("\n")
    sys.stdout.flush()


# -------------------------
# Data models / config
# -------------------------

def rand_bytes(n: int) -> bytes:
    return os.urandom(n)


@dataclass
class TcpTest:
    host: str
    port: int
    bytes: int


@dataclass
class UdpTest:
    host: str
    port: int
    payload_size: int
    packets: int
    inter_packet_ms: int
    ack_timeout_ms: int
    udp_mode: str
    ack_every: int
    batch_size: int


@dataclass
class HttpTest:
    url: str
    bytes: int


def load_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# -------------------------
# Host / network info (best-effort)
# -------------------------

def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().isoformat(timespec="seconds")


def _timestamp_for_filename() -> str:
    # local time
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def collect_local_ips_best_effort() -> List[str]:
    """
    Best-effort list of local IPs without external deps.
    Includes:
      - getaddrinfo(hostname)
      - "default route" interface IP via UDP connect trick (no packets sent)
    """
    ips = set()

    # from hostname resolution
    try:
        hn = socket.gethostname()
        for res in socket.getaddrinfo(hn, None):
            ip = res[4][0]
            if ip and ":" not in ip:  # keep IPv4 only for readability
                ips.add(ip)
    except Exception:
        pass

    # "default route" IP trick
    for target in [("8.8.8.8", 80), ("1.1.1.1", 80)]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(target)  # no packets necessarily sent
            ip = s.getsockname()[0]
            if ip:
                ips.add(ip)
            s.close()
            break
        except Exception:
            try:
                s.close()
            except Exception:
                pass

    out = sorted(ips)
    return out


def run_command_capture(cmd: List[str], timeout: int = 5) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")
        return out.strip()
    except Exception as e:
        return f"Command failed: {cmd} ({type(e).__name__}: {e})"


def collect_network_diagnostics() -> Dict[str, str]:
    """
    Capture a small set of platform-specific network command outputs.
    Keep it best-effort and bounded.
    """
    info: Dict[str, str] = {}
    if os.name == "nt":
        info["ipconfig_all"] = run_command_capture(["ipconfig", "/all"], timeout=8)
        info["route_print"] = run_command_capture(["route", "print"], timeout=8)
        info["netsh_fw_profiles"] = run_command_capture(["netsh", "advfirewall", "show", "allprofiles"], timeout=8)
    else:
        # Try iproute2 first, fallback to ifconfig/route
        info["ip_addr"] = run_command_capture(["sh", "-lc", "ip addr || ifconfig -a"], timeout=8)
        info["ip_route"] = run_command_capture(["sh", "-lc", "ip route || route -n"], timeout=8)
    return info


def summarize_client_env(include_cmd_output: bool) -> Dict[str, Any]:
    hostname = socket.gethostname()
    fqdn = socket.getfqdn()
    ips = collect_local_ips_best_effort()

    env = {
        "timestamp_local": dt.datetime.now().isoformat(timespec="seconds"),
        "timestamp_iso": _now_iso(),
        "hostname": hostname,
        "fqdn": fqdn,
        "platform": platform.platform(),
        "python": sys.version.replace("\n", " "),
        "local_ips": ips,
        "user": os.environ.get("USERNAME") or os.environ.get("USER") or "",
    }

    if include_cmd_output:
        env["net_commands"] = collect_network_diagnostics()
    else:
        env["net_commands"] = {}

    return env


# -------------------------
# Outcome / inference helpers
# -------------------------

def classify_tcp_exception(e: BaseException) -> Tuple[str, str]:
    if isinstance(e, socket.gaierror):
        return ("NAME_RESOLUTION_FAILED", "Client DNS/name resolution failure")
    if isinstance(e, (socket.timeout, TimeoutError)):
        return ("BLOCKED_OR_DROPPED", "Timeout/no response — likely network ACL/firewall drop or route issue")
    if isinstance(e, ConnectionRefusedError):
        return ("NO_LISTENER", "Connection refused — host reachable but no server listening or host firewall rejecting")
    if isinstance(e, ConnectionResetError):
        return ("RESET", "Connection reset — server or middlebox actively closed the connection")
    if isinstance(e, PermissionError):
        return ("CLIENT_BLOCKED", "Client-side restriction (permissions/policy)")
    if isinstance(e, OSError):
        return ("ERROR", f"OS/network error (errno={getattr(e, 'errno', None)})")
    return ("ERROR", "Unknown error")


def classify_http(status_code: int) -> Tuple[str, str]:
    if 200 <= status_code <= 299:
        return ("SUCCESS", "Server responded OK")
    if status_code == 401:
        return ("AUTH_FAILED", "Server rejected request (401) — PSK missing/invalid")
    if status_code == 403:
        return ("BLOCKED_BY_SERVER", "Server rejected request (403) — server-side policy")
    if status_code == 404:
        return ("SERVER_MISCONFIG", "Server responded (404) — endpoint not found (server running, path mismatch)")
    if 400 <= status_code <= 499:
        return ("CLIENT_REQUEST_REJECTED", f"Server/client request rejected (HTTP {status_code})")
    if 500 <= status_code <= 599:
        return ("SERVER_ERROR", f"Server error (HTTP {status_code})")
    return ("ERROR", f"Unexpected HTTP status {status_code}")


# -------------------------
# TCP test
# -------------------------

def tcp_test(t: TcpTest, test_id: str, timeout_s: float, psk: str,
             stop_event: threading.Event, show_progress: bool) -> Dict[str, Any]:
    started = _now_iso()
    t0 = time.time()

    payload = rand_bytes(t.bytes)
    meta = {"test_id": test_id, "bytes": t.bytes, "psk": psk}
    header = (json.dumps(meta) + "\n").encode("utf-8")

    result: Dict[str, Any] = {
        "type": "tcp",
        "host": t.host,
        "port": t.port,
        "bytes_planned": t.bytes,
        "started": started,
    }

    try:
        if stop_event.is_set():
            raise KeyboardInterrupt("Aborted by user")

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout_s)
        s.connect((t.host, t.port))
        s.sendall(header)

        sent = 0
        total = len(payload)
        chunk_size = 64 * 1024

        while sent < total:
            if stop_event.is_set():
                raise KeyboardInterrupt("Aborted by user")
            end = min(total, sent + chunk_size)
            s.sendall(payload[sent:end])
            sent = end
            if show_progress:
                print_progress_line(progress_bar(f"TCP {t.host}:{t.port} {_fmt_bytes(total)}", sent, total))

        buf = b""
        while not buf.endswith(b"\n"):
            if stop_event.is_set():
                raise KeyboardInterrupt("Aborted by user")
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
            if len(buf) > 65536:
                break
        s.close()

        elapsed = max(1e-6, time.time() - t0)
        mbps = (t.bytes * 8) / elapsed / 1_000_000

        try:
            server_resp = json.loads(buf.decode("utf-8").strip())
        except Exception:
            server_resp = {"raw_response": buf.decode("utf-8", errors="replace")}

        if isinstance(server_resp, dict) and server_resp.get("ok") is False and "PSK" in str(server_resp.get("error", "")):
            status, inf = ("AUTH_FAILED", "Server rejected PSK (application-level auth)")
        else:
            status, inf = ("SUCCESS", "Connected and received server response")

        result.update({
            "status": status,
            "inference": inf,
            "bytes_sent": sent,
            "client_elapsed_s": elapsed,
            "client_mbps": mbps,
            "server_response": server_resp,
        })
        return result

    except KeyboardInterrupt as e:
        elapsed = max(1e-6, time.time() - t0)
        result.update({
            "status": "ABORTED",
            "inference": "User requested quit (Q) during test",
            "client_elapsed_s": elapsed,
            "error_type": "KeyboardInterrupt",
            "error": str(e),
        })
        return result

    except Exception as e:
        elapsed = max(1e-6, time.time() - t0)
        status, inf = classify_tcp_exception(e)
        result.update({
            "status": status,
            "inference": inf,
            "client_elapsed_s": elapsed,
            "error_type": type(e).__name__,
            "error": str(e),
        })
        return result

    finally:
        if show_progress:
            end_progress_line()


# -------------------------
# UDP test (3 modes)
# -------------------------

def _udp_send_hello(sock: socket.socket, addr: Tuple[str, int], test_id: str, psk: str,
                    udp_mode: str, ack_every: int) -> bool:
    hello_obj = {"test_id": test_id, "psk": psk, "udp_mode": udp_mode, "ack_every": ack_every}
    hello = b"HELLO " + json.dumps(hello_obj).encode("utf-8")
    sock.sendto(hello, addr)
    try:
        data, _ = sock.recvfrom(2048)
        return data.startswith(b"HELLO_ACK")
    except Exception:
        return False


def udp_test(u: UdpTest, test_id: str, timeout_s: float, psk: str,
             stop_event: threading.Event, show_progress: bool) -> Dict[str, Any]:
    started = _now_iso()
    t0 = time.time()

    result: Dict[str, Any] = {
        "type": "udp",
        "host": u.host,
        "port": u.port,
        "payload_size": u.payload_size,
        "packets_planned": u.packets,
        "udp_mode": u.udp_mode,
        "ack_every": u.ack_every,
        "batch_size": u.batch_size,
        "started": started,
    }

    addr = (u.host, u.port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout_s)

    seq_fmt = "!Q"
    payload = rand_bytes(max(0, u.payload_size))

    hello_acked = False
    had_icmp_error = False

    acked = 0
    sent = 0
    pending = set()

    try:
        if stop_event.is_set():
            raise KeyboardInterrupt("Aborted by user")

        hello_acked = _udp_send_hello(sock, addr, test_id, psk, u.udp_mode, u.ack_every)

        if show_progress:
            print_progress_line(f"UDP {u.host}:{u.port} mode={u.udp_mode} starting...")

        def drain_acks(deadline: float) -> None:
            nonlocal acked, had_icmp_error
            while time.time() < deadline:
                if stop_event.is_set():
                    raise KeyboardInterrupt("Aborted by user")
                try:
                    data, _a = sock.recvfrom(2048)
                except socket.timeout:
                    break
                except OSError:
                    had_icmp_error = True
                    break
                except Exception:
                    break

                if data.startswith(b"ACK ") and len(data) >= 4 + 8:
                    s = struct.unpack(seq_fmt, data[4:12])[0]
                    if s in pending:
                        pending.remove(s)
                        acked += 1
                    continue

                if data.startswith(b"ACKR ") and len(data) >= 5 + 16:
                    start, end = struct.unpack("!QQ", data[5:21])
                    to_remove = [x for x in pending if start <= x <= end]
                    for x in to_remove:
                        pending.remove(x)
                        acked += 1
                    continue

        # firehose: no data ACKs expected
        if u.udp_mode == "firehose":
            for i in range(u.packets):
                if stop_event.is_set():
                    raise KeyboardInterrupt("Aborted by user")
                seq = i + 1
                pkt = b"DATA " + struct.pack(seq_fmt, seq) + payload
                sock.sendto(pkt, addr)
                sent += 1
                if show_progress:
                    print_progress_line(progress_bar(f"UDP {u.host}:{u.port} firehose pkt", sent, u.packets))
                if u.inter_packet_ms > 0:
                    time.sleep(u.inter_packet_ms / 1000.0)

            elapsed = max(1e-6, time.time() - t0)
            bytes_sent = sent * (5 + 8 + len(payload))
            mbps = (bytes_sent * 8) / elapsed / 1_000_000

            if hello_acked:
                status, inf = ("SUCCESS", "Sent UDP packets (firehose). HELLO acknowledged by server.")
            else:
                status, inf = ("BLOCKED_OR_DROPPED", "No HELLO_ACK; UDP may be blocked/dropped or server not reachable.")

            result.update({
                "status": status,
                "inference": inf,
                "hello_acked": hello_acked,
                "icmp_error_observed": had_icmp_error,
                "packets_sent": sent,
                "packets_acked": 0,
                "loss_rate": None,
                "client_elapsed_s": elapsed,
                "approx_mbps": mbps,
            })
            return result

        # reliable / batched_ack: track pending ACKs
        for i in range(u.packets):
            if stop_event.is_set():
                raise KeyboardInterrupt("Aborted by user")
            seq = i + 1
            pending.add(seq)
            pkt = b"DATA " + struct.pack(seq_fmt, seq) + payload
            sock.sendto(pkt, addr)
            sent += 1

            if show_progress:
                print_progress_line(progress_bar(f"UDP {u.host}:{u.port} mode={u.udp_mode} pkt", sent, u.packets))

            if u.inter_packet_ms > 0:
                time.sleep(u.inter_packet_ms / 1000.0)

            if u.udp_mode == "reliable":
                deadline = time.time() + (u.ack_timeout_ms / 1000.0)
                drain_acks(deadline)
            else:
                if (sent % max(1, u.batch_size)) == 0:
                    deadline = time.time() + (u.ack_timeout_ms / 1000.0)
                    drain_acks(deadline)

        deadline = time.time() + (u.ack_timeout_ms / 1000.0)
        drain_acks(deadline)

        elapsed = max(1e-6, time.time() - t0)
        bytes_sent = sent * (5 + 8 + len(payload))
        mbps = (bytes_sent * 8) / elapsed / 1_000_000
        loss = 0.0 if sent == 0 else (sent - acked) / sent

        if acked > 0:
            status, inf = ("SUCCESS", f"Received UDP ACKs from server (mode={u.udp_mode}).")
        else:
            if had_icmp_error:
                status, inf = ("BLOCKED_OR_UNREACHABLE", "ICMP error observed — host/port unreachable or filtered")
            elif hello_acked:
                status, inf = ("PARTIAL", "HELLO acknowledged but no DATA ACKs — possible server-side drop/state issue")
            else:
                status, inf = ("BLOCKED_OR_DROPPED", "No UDP responses — could be server not listening, host firewall, or network ACL drop")

        result.update({
            "status": status,
            "inference": inf,
            "hello_acked": hello_acked,
            "icmp_error_observed": had_icmp_error,
            "packets_sent": sent,
            "packets_acked": acked,
            "loss_rate": loss,
            "client_elapsed_s": elapsed,
            "approx_mbps": mbps,
        })
        return result

    except KeyboardInterrupt as e:
        elapsed = max(1e-6, time.time() - t0)
        result.update({
            "status": "ABORTED",
            "inference": "User requested quit (Q) during UDP test",
            "client_elapsed_s": elapsed,
            "error_type": "KeyboardInterrupt",
            "error": str(e),
        })
        return result

    except Exception as e:
        elapsed = max(1e-6, time.time() - t0)
        result.update({
            "status": "ERROR",
            "inference": "UDP test errored (client-side exception)",
            "client_elapsed_s": elapsed,
            "error_type": type(e).__name__,
            "error": str(e),
        })
        return result

    finally:
        try:
            sock.close()
        except Exception:
            pass
        if show_progress:
            end_progress_line()


# -------------------------
# HTTP test
# -------------------------

def http_test(h: HttpTest, test_id: str, timeout_s: float, psk: str,
              stop_event: threading.Event, show_progress: bool) -> Dict[str, Any]:
    started = _now_iso()
    t0 = time.time()

    result: Dict[str, Any] = {
        "type": "http",
        "url": h.url,
        "bytes_planned": h.bytes,
        "started": started,
    }

    payload = rand_bytes(h.bytes)
    req = urllib.request.Request(
        h.url,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/octet-stream",
            "X-Test-Id": test_id,
            "X-PSK": psk,
        },
    )

    try:
        if stop_event.is_set():
            raise KeyboardInterrupt("Aborted by user")

        if show_progress:
            print_progress_line(f"HTTP {h.url} uploading {_fmt_bytes(h.bytes)}...")

        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            body = resp.read()
            status = int(resp.status)

        elapsed = max(1e-6, time.time() - t0)
        mbps = (h.bytes * 8) / elapsed / 1_000_000

        try:
            server = json.loads(body.decode("utf-8"))
        except Exception:
            server = {"raw_response": body.decode("utf-8", errors="replace")}

        st, inf = classify_http(status)
        result.update({
            "status": st,
            "inference": inf,
            "http_status": status,
            "client_elapsed_s": elapsed,
            "client_mbps": mbps,
            "server_response": server,
        })
        return result

    except KeyboardInterrupt as e:
        elapsed = max(1e-6, time.time() - t0)
        result.update({
            "status": "ABORTED",
            "inference": "User requested quit (Q) during HTTP test",
            "client_elapsed_s": elapsed,
            "error_type": "KeyboardInterrupt",
            "error": str(e),
        })
        return result

    except urllib.error.HTTPError as e:
        elapsed = max(1e-6, time.time() - t0)
        st, inf = classify_http(int(e.code))
        result.update({
            "status": st,
            "inference": inf,
            "http_status": int(e.code),
            "client_elapsed_s": elapsed,
            "error_type": type(e).__name__,
            "error": str(e),
        })
        return result

    except urllib.error.URLError as e:
        elapsed = max(1e-6, time.time() - t0)
        reason = getattr(e, "reason", None)
        if isinstance(reason, socket.gaierror):
            st, inf = ("NAME_RESOLUTION_FAILED", "Client DNS/name resolution failure")
        elif isinstance(reason, (socket.timeout, TimeoutError)):
            st, inf = ("BLOCKED_OR_DROPPED", "Timeout/no response — likely network ACL/firewall drop")
        elif isinstance(reason, ConnectionRefusedError):
            st, inf = ("NO_LISTENER", "Connection refused — server not listening or host firewall reject")
        else:
            st, inf = ("ERROR", "HTTP connection failed — could be client/network/server")
        result.update({
            "status": st,
            "inference": inf,
            "client_elapsed_s": elapsed,
            "error_type": type(e).__name__,
            "error": str(e),
        })
        return result

    except Exception as e:
        elapsed = max(1e-6, time.time() - t0)
        result.update({
            "status": "ERROR",
            "inference": "HTTP test errored (client-side exception)",
            "client_elapsed_s": elapsed,
            "error_type": type(e).__name__,
            "error": str(e),
        })
        return result

    finally:
        if show_progress:
            end_progress_line()


# -------------------------
# HTML report + inline SVG chart
# -------------------------

def _result_label(r: Dict[str, Any]) -> str:
    t = (r.get("type") or "").lower()
    if t == "tcp":
        return f"TCP {r.get('host')}:{r.get('port')}"
    if t == "udp":
        return f"UDP {r.get('host')}:{r.get('port')} ({r.get('udp_mode')})"
    if t == "http":
        return f"HTTP {r.get('url')}"
    return str(t).upper()


def _result_mbps(r: Dict[str, Any]) -> float:
    t = (r.get("type") or "").lower()
    if t == "tcp":
        return float(r.get("client_mbps") or 0.0)
    if t == "udp":
        return float(r.get("approx_mbps") or 0.0)
    if t == "http":
        return float(r.get("client_mbps") or 0.0)
    return 0.0


def _svg_throughput_chart(results: List[Dict[str, Any]]) -> str:
    items = []
    for r in results:
        items.append((html.escape(_result_label(r)), _result_mbps(r), str(r.get("status", ""))))

    if not items:
        return "<div class='small'>No results to chart.</div>"

    max_mbps = max((mbps for _lbl, mbps, _st in items), default=0.0)
    max_mbps = max(1e-6, max_mbps)

    row_h = 22
    left_pad = 280
    right_pad = 60
    top_pad = 18
    chart_w = 780
    bar_max_w = chart_w - left_pad - right_pad
    chart_h = top_pad + len(items) * row_h + 18

    def opacity_for(status: str) -> str:
        s = status.upper()
        if s in ("SUCCESS",):
            return "0.95"
        if s in ("SKIPPED",):
            return "0.25"
        if s in ("ABORTED",):
            return "0.45"
        if s in ("ERROR", "NO_LISTENER", "BLOCKED_OR_DROPPED", "BLOCKED_OR_UNREACHABLE", "AUTH_FAILED", "RESET", "PARTIAL"):
            return "0.55"
        return "0.55"

    svg = [f"<svg width='{chart_w}' height='{chart_h}' viewBox='0 0 {chart_w} {chart_h}' xmlns='http://www.w3.org/2000/svg'>"]
    svg.append(f"<text x='0' y='14' font-size='13' fill='#222'>Throughput (Mbps) by test</text>")

    # grid
    for tick in range(0, 6):
        x = left_pad + int(bar_max_w * (tick / 5))
        val = max_mbps * (tick / 5)
        svg.append(f"<line x1='{x}' y1='{top_pad-6}' x2='{x}' y2='{chart_h-12}' stroke='#eee'/>")
        svg.append(f"<text x='{x-8}' y='{chart_h-2}' font-size='10' fill='#666'>{val:.1f}</text>")

    y = top_pad
    for lbl, mbps, st in items:
        bar_w = int(bar_max_w * (mbps / max_mbps)) if max_mbps > 0 else 0
        op = opacity_for(st)
        svg.append(f"<text x='0' y='{y+14}' font-size='11' fill='#222'>{lbl}</text>")
        svg.append(f"<rect x='{left_pad}' y='{y+5}' width='{bar_w}' height='12' rx='3' ry='3' fill='#222' opacity='{op}'/>")
        svg.append(f"<text x='{left_pad+bar_max_w+6}' y='{y+14}' font-size='11' fill='#222'>{mbps:.2f}</text>")
        y += row_h

    svg.append("</svg>")
    return "".join(svg)


def _truncate(s: str, max_len: int = 12000) -> str:
    if len(s) <= max_len:
        return s
    return s[:max_len] + "\n...[truncated]..."


def _unique_targets(results: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    tcp_udp_hosts = set()
    http_hosts = set()
    http_urls = set()

    for r in results:
        t = (r.get("type") or "").lower()
        if t in ("tcp", "udp"):
            h = r.get("host")
            p = r.get("port")
            if h is not None and p is not None:
                tcp_udp_hosts.add(f"{h}:{p}")
        elif t == "http":
            url = str(r.get("url") or "")
            http_urls.add(url)
            try:
                u = urlparse(url)
                if u.hostname:
                    http_hosts.add(u.hostname)
            except Exception:
                pass

    return {
        "tcp_udp_targets": sorted(tcp_udp_hosts),
        "http_hosts": sorted(http_hosts),
        "http_urls": sorted(http_urls),
    }


def write_html_report(path: str, summary: Dict[str, Any]) -> None:
    test_id = summary.get("test_id", "")
    started = summary.get("started", "")
    ended = summary.get("ended", "")
    run_status = summary.get("run_status", "")
    cfg = summary.get("config_path", "")
    allow_modes = summary.get("allow_udp_modes", "")
    udp_override = summary.get("udp_mode_override", "")
    server_arg = summary.get("server_arg", "")
    force_server = summary.get("force_server", False)

    client_env: Dict[str, Any] = summary.get("client_env", {})
    results: List[Dict[str, Any]] = summary.get("results", [])

    total = len(results)
    by_status: Dict[str, int] = {}
    for r in results:
        by_status[r.get("status", "UNKNOWN")] = by_status.get(r.get("status", "UNKNOWN"), 0) + 1

    status_items = "".join(
        f"<li><b>{html.escape(k)}</b>: {v}</li>"
        for k, v in sorted(by_status.items(), key=lambda kv: (-kv[1], kv[0]))
    )

    chart_svg = _svg_throughput_chart(results)
    targets = _unique_targets(results)

    # network command outputs (optional)
    net_cmds = client_env.get("net_commands") or {}
    net_cmd_blocks = []
    if isinstance(net_cmds, dict) and net_cmds:
        for k, v in net_cmds.items():
            net_cmd_blocks.append(
                f"<h4>{html.escape(str(k))}</h4>"
                f"<pre>{html.escape(_truncate(str(v)))}</pre>"
            )
    net_cmd_html = "".join(net_cmd_blocks) if net_cmd_blocks else "<div class='small'>Command output capture disabled.</div>"

    rows = []
    for r in results:
        t = r.get("type", "")
        status = r.get("status", "")
        inference = r.get("inference", "")
        elapsed = r.get("client_elapsed_s", "")

        if t == "tcp":
            target = f"{r.get('host')}:{r.get('port')}"
            detail = f"bytes={r.get('bytes_planned')}"
        elif t == "udp":
            target = f"{r.get('host')}:{r.get('port')}"
            detail = (
                f"mode={r.get('udp_mode')} packets={r.get('packets_planned')} payload={r.get('payload_size')} "
                f"ack_every={r.get('ack_every')} batch={r.get('batch_size')}"
            )
        else:
            target = r.get("url", "")
            detail = f"bytes={r.get('bytes_planned')}"

        err = r.get("error", "")
        err_type = r.get("error_type", "")
        detail2 = f"{err_type}: {err}" if err else ""

        rows.append(
            "<tr>"
            f"<td>{html.escape(str(t).upper())}</td>"
            f"<td>{html.escape(str(target))}</td>"
            f"<td class='{html.escape(str(status))}'>{html.escape(str(status))}</td>"
            f"<td>{html.escape(str(inference))}</td>"
            f"<td>{html.escape(str(elapsed))}</td>"
            f"<td>{html.escape(str(detail))}</td>"
            f"<td>{html.escape(detail2)}</td>"
            "</tr>"
        )

    # Client env block
    def env_line(k: str, v: Any) -> str:
        return f"<tr><td><b>{html.escape(k)}</b></td><td>{html.escape(str(v))}</td></tr>"

    env_table = []
    env_table.append(env_line("Hostname", client_env.get("hostname", "")))
    env_table.append(env_line("FQDN", client_env.get("fqdn", "")))
    env_table.append(env_line("Local IPs (best-effort)", ", ".join(client_env.get("local_ips", []) or [])))
    env_table.append(env_line("Platform", client_env.get("platform", "")))
    env_table.append(env_line("Python", client_env.get("python", "")))
    env_table.append(env_line("User", client_env.get("user", "")))
    env_table.append(env_line("Client timestamp (local)", client_env.get("timestamp_local", "")))
    env_table.append(env_line("Client timestamp (iso)", client_env.get("timestamp_iso", "")))

    doc = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Exfiliator Report - {html.escape(str(test_id))}</title>
  <style>
    body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 24px; }}
    h1 {{ margin: 0 0 8px 0; }}
    .meta {{ margin: 0 0 18px 0; color: #333; }}
    .card {{ border: 1px solid #ddd; border-radius: 12px; padding: 16px; margin: 14px 0; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border-bottom: 1px solid #eee; padding: 10px; text-align: left; vertical-align: top; }}
    thead th {{ background: #fafafa; }}
    .small {{ color: #555; font-size: 0.95rem; }}
    .pill {{ display: inline-block; padding: 2px 10px; border-radius: 999px; border: 1px solid #ddd; }}
    code {{ background: #f6f6f6; padding: 2px 6px; border-radius: 6px; }}
    pre {{ background: #f6f6f6; padding: 12px; border-radius: 10px; overflow-x: auto; }}
    .SUCCESS {{ background: #eaffea; }}
    .NO_LISTENER, .BLOCKED_OR_DROPPED, .BLOCKED_OR_UNREACHABLE, .RESET, .AUTH_FAILED {{ background: #fff2f2; }}
    .PARTIAL {{ background: #fff7e6; }}
    .ABORTED {{ background: #fff7e6; }}
    .ERROR {{ background: #fff7e6; }}
    .SKIPPED {{ background: #f3f3f3; }}
    .table-wrap {{ overflow-x: auto; }}
    .svg-wrap {{ overflow-x: auto; padding-top: 8px; }}
    .two-col {{ display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }}
    @media (max-width: 900px) {{ .two-col {{ grid-template-columns: 1fr; }} }}
  </style>
</head>
<body>
  <h1>Exfiliator Port/Protocol Test Report</h1>
  <p class="meta small">
    <span class="pill">test_id: {html.escape(str(test_id))}</span>
    &nbsp; <span class="pill">run: {html.escape(str(run_status))}</span><br/>
    Started: <code>{html.escape(str(started))}</code>
    &nbsp; Ended: <code>{html.escape(str(ended))}</code><br/>
    Config: <code>{html.escape(str(cfg))}</code><br/>
    Server arg: <code>{html.escape(str(server_arg))}</code>
    &nbsp; Force server: <code>{html.escape(str(force_server))}</code><br/>
    UDP allowlist: <code>{html.escape(str(allow_modes))}</code>
    &nbsp; UDP override: <code>{html.escape(str(udp_override or "none"))}</code><br/>
    Total results recorded: <b>{total}</b>
  </p>

  <div class="card two-col">
    <div>
      <h2>Client Host Info</h2>
      <table>
        <tbody>
          {''.join(env_table)}
        </tbody>
      </table>
    </div>
    <div>
      <h2>Targets Summary</h2>
      <p class="small"><b>TCP/UDP targets</b></p>
      <pre>{html.escape("\\n".join(targets["tcp_udp_targets"]) or "(none)")}</pre>
      <p class="small"><b>HTTP URLs</b></p>
      <pre>{html.escape("\\n".join(targets["http_urls"]) or "(none)")}</pre>
    </div>
  </div>

  <div class="card">
    <h2>Outcome Summary</h2>
    <ul class="small">{status_items}</ul>
    <p class="small">
      <b>Interpretation guidance (best-effort):</b><br/>
      - <b>NO_LISTENER</b>: host reachable but nothing listening (or host firewall rejected).<br/>
      - <b>BLOCKED_OR_DROPPED</b>: timeout/no response (often network ACL/firewall drop).<br/>
      - <b>RESET</b>: connection reset by server or middlebox.<br/>
      - <b>AUTH_FAILED</b>: server reached but PSK rejected (app-layer).<br/>
      - <b>ABORTED</b>: user quit mid-run (partial results).<br/>
      - <b>SKIPPED</b>: test skipped by client allowlist (policy for this run).<br/>
      - <b>UDP firehose</b>: success inferred by HELLO reachability + successful send (no DATA ACKs by design).
    </p>
  </div>

  <div class="card">
    <h2>Throughput</h2>
    <div class="svg-wrap">{chart_svg}</div>
    <p class="small">
      This chart reflects <b>client-side estimated throughput</b>. For UDP, values depend heavily on mode and ACK strategy.
    </p>
  </div>

  <div class="card table-wrap">
    <h2>Detailed Results</h2>
    <table>
      <thead>
        <tr>
          <th>Protocol</th>
          <th>Target</th>
          <th>Status</th>
          <th>Inference</th>
          <th>Elapsed (s)</th>
          <th>Test Params</th>
          <th>Error</th>
        </tr>
      </thead>
      <tbody>
        {''.join(rows)}
      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>Network Diagnostics (Best Effort)</h2>
    <p class="small">
      These are captured from local OS commands (optional) to help correlate host/network conditions during testing.
      Avoid committing reports if they contain sensitive environment details.
    </p>
    {net_cmd_html}
  </div>

</body>
</html>
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)


# -------------------------
# Main
# -------------------------

def setup_logging(verbosity: int) -> None:
    level = logging.INFO if verbosity <= 0 else logging.DEBUG
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(message)s")


def resolve_html_out(arg_html_out: Optional[str], test_id: str) -> str:
    """
    If user does not specify --html-out, generate a timestamped report name.
    If user specifies a path ending with .html, use it as-is.
    If user specifies a directory, write file inside that dir.
    """
    ts = _timestamp_for_filename()
    default_name = f"exfiliator_report_{test_id}_{ts}.html"

    if not arg_html_out:
        return default_name

    out = arg_html_out.strip()
    if not out:
        return default_name

    # If it's a directory (exists), place file inside it
    if os.path.isdir(out):
        return os.path.join(out, default_name)

    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True, help="JSON config path (explicit allowlist)")
    ap.add_argument("--timeout", type=float, default=10.0, help="Socket/HTTP timeout seconds")
    ap.add_argument("--test-id", default=None, help="Optional test id (otherwise timestamp-based)")
    ap.add_argument("--psk", default=None, help="Pre-shared key (prefer --psk-file)")
    ap.add_argument("--psk-file", default=None, help="Read PSK from file")

    # NEW: server selection for TCP/UDP
    ap.add_argument("--server", default="127.0.0.1",
                    help="Default server host/IP for TCP/UDP entries missing 'host' in config (default 127.0.0.1)")
    ap.add_argument("--force-server", action="store_true",
                    help="Override all TCP/UDP 'host' values in config with --server for this run")

    ap.add_argument("--html-out", default=None,
                    help="Write HTML report to this file. If omitted, a timestamped filename is used.")
    ap.add_argument("--no-progress", action="store_true", help="Disable progress bars")
    ap.add_argument("--no-quit-monitor", action="store_true", help="Disable 'press Q to quit' monitor")
    ap.add_argument("--include-network-commands", action="store_true",
                    help="Include OS command output (ipconfig/route/ip addr) in the HTML report (may contain sensitive details).")
    ap.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity (-v, -vv)")

    # UDP mode allow/override
    ap.add_argument(
        "--allow-udp-modes",
        default="reliable,batched_ack,firehose",
        help="Comma-separated UDP modes allowed to run. Default: reliable,batched_ack,firehose",
    )
    ap.add_argument(
        "--udp-mode-override",
        default=None,
        help="If set, forces all UDP tests to use this mode (reliable|batched_ack|firehose).",
    )

    args = ap.parse_args()
    setup_logging(args.verbose)

    cfg = load_config(args.config)
    test_id = args.test_id or f"exf-{int(time.time())}"
    show_progress = not args.no_progress

    # PSK
    psk = args.psk
    if args.psk_file:
        with open(args.psk_file, "r", encoding="utf-8") as f:
            psk = f.read().strip()
    if not psk:
        raise SystemExit("PSK required. Use --psk-file or --psk.")

    # UDP mode policy (allowlist + optional override)
    valid_udp_modes = {"reliable", "batched_ack", "firehose"}
    allowed_udp_modes = {m.strip().lower() for m in (args.allow_udp_modes or "").split(",") if m.strip()}
    allowed_udp_modes = allowed_udp_modes.intersection(valid_udp_modes)
    if not allowed_udp_modes:
        raise SystemExit("No valid UDP modes allowed. Use --allow-udp-modes reliable,batched_ack,firehose")

    udp_override = args.udp_mode_override.lower().strip() if args.udp_mode_override else None
    if udp_override and udp_override not in valid_udp_modes:
        raise SystemExit("Invalid --udp-mode-override. Use reliable|batched_ack|firehose")
    if udp_override and udp_override not in allowed_udp_modes:
        raise SystemExit(f"--udp-mode-override '{udp_override}' is not in --allow-udp-modes ({sorted(allowed_udp_modes)})")

    # HTML output path resolution (timestamped by default)
    html_out_path = resolve_html_out(args.html_out, test_id)

    # Quit monitor
    qm = QuitMonitor()
    qm.start(enable=not args.no_quit_monitor)
    if not args.no_quit_monitor:
        log.info("Quit monitor enabled: press 'Q' to quit (report will still be written).")

    # Client env info (captured once per run)
    client_env = summarize_client_env(include_cmd_output=bool(args.include_network_commands))

    tcp_items = cfg.get("tcp", [])
    udp_items = cfg.get("udp", [])
    http_items = cfg.get("http", [])
    total_tests = len(tcp_items) + len(udp_items) + len(http_items)
    completed = 0

    results: List[Dict[str, Any]] = []
    started = _now_iso()

    def overall() -> None:
        if show_progress:
            print_progress_line(progress_bar("Overall tests", completed, max(1, total_tests)))

    # Apply server default/override to TCP/UDP
    server_arg = (args.server or "127.0.0.1").strip() or "127.0.0.1"

    try:
        # TCP
        for item in tcp_items:
            if qm.stop_event.is_set():
                break
            host = str(item.get("host") or "").strip()
            if args.force_server or not host:
                host = server_arg
            t = TcpTest(host=host, port=int(item["port"]), bytes=int(item["bytes"]))
            if args.verbose:
                log.info("TCP test: %s:%d bytes=%d", t.host, t.port, t.bytes)
            results.append(tcp_test(t, test_id, args.timeout, psk, qm.stop_event, show_progress))
            completed += 1
            overall()

        # UDP
        for item in udp_items:
            if qm.stop_event.is_set():
                break

            host = str(item.get("host") or "").strip()
            if args.force_server or not host:
                host = server_arg

            mode = str(item.get("udp_mode", item.get("mode", "reliable"))).lower().strip()
            if mode not in valid_udp_modes:
                mode = "reliable"
            if udp_override:
                mode = udp_override

            if mode not in allowed_udp_modes:
                results.append({
                    "type": "udp",
                    "host": host,
                    "port": int(item.get("port", 0) or 0),
                    "status": "SKIPPED",
                    "inference": f"Skipped: UDP mode '{mode}' not allowed by --allow-udp-modes",
                    "udp_mode": mode,
                    "ack_every": int(item.get("ack_every", 50)),
                    "batch_size": int(item.get("batch_size", 200)),
                    "payload_size": int(item.get("payload_size", 512)),
                    "packets_planned": int(item.get("packets", 0) or 0),
                    "started": _now_iso(),
                })
                completed += 1
                overall()
                continue

            u = UdpTest(
                host=host,
                port=int(item["port"]),
                payload_size=int(item.get("payload_size", 512)),
                packets=int(item.get("packets", 200)),
                inter_packet_ms=int(item.get("inter_packet_ms", 0)),
                ack_timeout_ms=int(item.get("ack_timeout_ms", 50)),
                udp_mode=mode,
                ack_every=int(item.get("ack_every", 50)),
                batch_size=int(item.get("batch_size", 200)),
            )
            if args.verbose:
                log.info(
                    "UDP test: %s:%d mode=%s packets=%d payload=%d ack_every=%d batch=%d",
                    u.host, u.port, u.udp_mode, u.packets, u.payload_size, u.ack_every, u.batch_size
                )
            results.append(udp_test(u, test_id, args.timeout, psk, qm.stop_event, show_progress))
            completed += 1
            overall()

        # HTTP (URLs are used as-is; mix of IPs/hostnames supported)
        for item in http_items:
            if qm.stop_event.is_set():
                break
            h = HttpTest(url=item["url"], bytes=int(item["bytes"]))
            if args.verbose:
                log.info("HTTP test: %s bytes=%d", h.url, h.bytes)
            results.append(http_test(h, test_id, args.timeout, psk, qm.stop_event, show_progress))
            completed += 1
            overall()

    finally:
        if show_progress:
            end_progress_line()

    ended = _now_iso()
    run_status = "ABORTED" if qm.stop_event.is_set() else "COMPLETED"

    summary = {
        "test_id": test_id,
        "run_status": run_status,
        "started": started,
        "ended": ended,
        "config_path": args.config,
        "server_arg": server_arg,
        "force_server": bool(args.force_server),
        "allow_udp_modes": ",".join(sorted(allowed_udp_modes)),
        "udp_mode_override": udp_override or "",
        "client_env": client_env,
        "results": results,
    }

    # Always write report
    write_html_report(html_out_path, summary)

    # JSON to stdout
    print(json.dumps(summary, indent=2))

    if run_status == "ABORTED":
        log.warning("Run aborted by user. Partial report written to: %s", html_out_path)
    else:
        log.info("Run completed. Report written to: %s", html_out_path)


if __name__ == "__main__":
    main()
