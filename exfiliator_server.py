#!/usr/bin/env python3
"""
Exfiliator Server - Purple-team network control test listener (TCP/UDP/HTTP) with PSK.

Safety/Design:
- Synthetic payloads only (server never reads local files for exfil)
- PSK required on all protocols
- Explicitly configured ports only
- No covert channels; no obfuscation/encryption for evasion

UDP modes supported (set by client in HELLO JSON):
- reliable   : ACK each DATA packet (slowest)
- batched_ack: ACK ranges periodically (faster)
- firehose   : ACK HELLO only; no ACKs for DATA

Firewall management (Windows Defender Firewall only):
- Optional temporary inbound allow rules for requested listener ports
- Enabled with --manage-firewall (requires Administrator)
- Dry run supported with --firewall-dry-run (prints planned actions; makes no changes)
- Removes ONLY rules created by this server instance on shutdown

Notes:
- Manages only local Windows firewall; cannot open upstream network ACLs/firewalls.
- If firewall is enforced by GPO, local rules may be ignored/blocked.

Standard library only.
"""

from __future__ import annotations

import argparse
import atexit
import json
import os
import secrets
import socket
import struct
import subprocess
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Tuple


# ---------------------------
# PSK utilities
# ---------------------------

def load_or_create_psk(psk_file: str) -> str:
    if os.path.exists(psk_file):
        with open(psk_file, "r", encoding="utf-8") as f:
            return f.read().strip()

    psk = secrets.token_urlsafe(32)

    # Try restrictive perms on *nix; Windows mostly ignores this.
    try:
        fd = os.open(psk_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(psk)
    except Exception:
        with open(psk_file, "w", encoding="utf-8") as f:
            f.write(psk)

    return psk


# ---------------------------
# Firewall management (Windows)
# ---------------------------

def is_windows() -> bool:
    return os.name == "nt"


def is_admin_windows() -> bool:
    try:
        import ctypes  # type: ignore
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run_powershell(ps: str) -> Tuple[int, str, str]:
    cmd = ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps]
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


class TempFirewallRules:
    """
    Creates temporary inbound allow rules for specified ports/protocols and removes them on cleanup.
    Supports:
      - apply mode: create rules and remove on exit
      - dry-run: print what would happen; do not change firewall
    """

    def __init__(self, enabled: bool, dry_run: bool, name_prefix: str, profile: str, remote_addresses: str) -> None:
        self.enabled = enabled
        self.dry_run = dry_run
        self.name_prefix = name_prefix
        self.profile = profile
        self.remote_addresses = remote_addresses
        self._created_rule_names: List[str] = []
        self._lock = threading.Lock()

    def add_rule(self, proto: str, port: int, tag: str) -> None:
        if not self.enabled:
            return

        if not is_windows():
            print("[firewall] --manage-firewall is only supported on Windows; skipping.")
            return

        proto_u = proto.upper()
        if proto_u not in ("TCP", "UDP"):
            raise ValueError(f"Unsupported protocol for firewall rule: {proto}")

        rule_name = f"{self.name_prefix} {tag} {proto_u}/{port} {uuid.uuid4()}"
        ps = (
            f"New-NetFirewallRule "
            f"-DisplayName '{rule_name}' "
            f"-Direction Inbound "
            f"-Action Allow "
            f"-Enabled True "
            f"-Protocol {proto_u} "
            f"-LocalPort {int(port)} "
            f"-Profile {self.profile} "
            f"-RemoteAddress '{self.remote_addresses}' "
            f"| Out-Null"
        )

        if self.dry_run:
            print(f"[firewall][dry-run] Would OPEN inbound {proto_u}/{port}")
            print(f"[firewall][dry-run]   DisplayName: {rule_name}")
            print(f"[firewall][dry-run]   Profile: {self.profile}  RemoteAddress: {self.remote_addresses}")
            print(f"[firewall][dry-run]   PowerShell: {ps}")
            return

        if not is_admin_windows():
            raise RuntimeError("Administrator privileges are required to manage firewall rules. Run as Admin.")

        rc, out, err = run_powershell(ps)
        if rc != 0:
            raise RuntimeError(f"Failed to create firewall rule for {proto_u}/{port}: {err or out}")

        with self._lock:
            self._created_rule_names.append(rule_name)

        print(f"[firewall] Opened inbound {proto_u}/{port} (temp rule: {rule_name})")

    def cleanup(self) -> None:
        if not self.enabled:
            return
        if not is_windows():
            return
        if self.dry_run:
            print("[firewall][dry-run] Cleanup: no rules were created; nothing to remove.")
            return

        if not is_admin_windows():
            print("[firewall] WARNING: Not running as Admin at cleanup; cannot remove temp rules automatically.")
            return

        with self._lock:
            names = list(self._created_rule_names)
            self._created_rule_names.clear()

        for name in names:
            ps = (
                f"Get-NetFirewallRule -DisplayName '{name}' -ErrorAction SilentlyContinue "
                f"| Remove-NetFirewallRule -ErrorAction SilentlyContinue | Out-Null"
            )
            run_powershell(ps)
            print(f"[firewall] Closed temp rule: {name}")


# ---------------------------
# Port availability checks
# ---------------------------

def check_tcp_bindable(bind: str, port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((bind, port))
        return True
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def check_udp_bindable(bind: str, port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind((bind, port))
        return True
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


# ---------------------------
# TCP server
# ---------------------------

def tcp_worker(bind: str, port: int, psk: str, stop_event: threading.Event) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind, port))
    srv.listen(64)

    while not stop_event.is_set():
        try:
            srv.settimeout(1.0)
            conn, addr = srv.accept()
        except socket.timeout:
            continue
        except Exception:
            continue

        threading.Thread(target=_tcp_handle_client, args=(conn, addr, psk), daemon=True).start()

    try:
        srv.close()
    except Exception:
        pass


def _tcp_handle_client(conn: socket.socket, addr: Tuple[str, int], psk: str) -> None:
    conn.settimeout(15.0)
    try:
        header = b""
        while not header.endswith(b"\n"):
            chunk = conn.recv(1)
            if not chunk:
                break
            header += chunk
            if len(header) > 8192:
                break

        try:
            meta = json.loads(header.decode("utf-8", errors="replace").strip() or "{}")
        except Exception:
            meta = {}

        if meta.get("psk") != psk:
            resp = {"ok": False, "error": "Invalid PSK"}
            conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))
            conn.close()
            return

        expected = int(meta.get("bytes") or 0)
        received = 0

        while received < expected:
            chunk = conn.recv(min(65536, expected - received))
            if not chunk:
                break
            received += len(chunk)

        resp = {"ok": True, "bytes_received": received, "test_id": meta.get("test_id")}
        conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))
        conn.close()

    except Exception:
        try:
            conn.close()
        except Exception:
            pass


# ---------------------------
# UDP server
# ---------------------------

_UDPModes = ("reliable", "batched_ack", "firehose")


class UDPClientState:
    __slots__ = ("mode", "ack_every", "last_acked_seq", "max_seen_seq", "authorized_at")
    def __init__(self, mode: str, ack_every: int) -> None:
        self.mode = mode
        self.ack_every = max(1, int(ack_every))
        self.last_acked_seq = 0
        self.max_seen_seq = 0
        self.authorized_at = time.time()


def udp_worker(bind: str, port: int, psk: str, stop_event: threading.Event) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind, port))
    sock.settimeout(1.0)

    authorized: Dict[Tuple[str, int], UDPClientState] = {}
    seq_fmt = "!Q"

    while not stop_event.is_set():
        try:
            pkt, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except Exception:
            continue

        try:
            if pkt.startswith(b"HELLO "):
                raw = pkt[6:].decode("utf-8", errors="replace")
                hello = json.loads(raw or "{}")
                if hello.get("psk") != psk:
                    sock.sendto(b"ERROR Invalid PSK", addr)
                    continue

                mode = str(hello.get("udp_mode") or "reliable").lower()
                if mode not in _UDPModes:
                    mode = "reliable"

                ack_every = int(hello.get("ack_every") or 50)
                authorized[addr] = UDPClientState(mode=mode, ack_every=ack_every)

                sock.sendto(b"HELLO_ACK", addr)
                continue

            if pkt.startswith(b"DATA ") and len(pkt) >= 5 + 8:
                st = authorized.get(addr)
                if not st:
                    continue

                seq = struct.unpack(seq_fmt, pkt[5:13])[0]
                if seq > st.max_seen_seq:
                    st.max_seen_seq = seq

                if st.mode == "firehose":
                    continue

                if st.mode == "reliable":
                    sock.sendto(b"ACK " + pkt[5:13], addr)
                    continue

                if st.mode == "batched_ack":
                    if seq % st.ack_every == 0 or seq == 1:
                        start = st.last_acked_seq + 1
                        end = max(st.last_acked_seq + 1, seq)
                        st.last_acked_seq = end
                        ackr = b"ACKR " + struct.pack("!QQ", start, end)
                        sock.sendto(ackr, addr)
                    continue

        except Exception:
            continue

    try:
        sock.close()
    except Exception:
        pass


# ---------------------------
# HTTP server
# ---------------------------

class UploadHandler(BaseHTTPRequestHandler):
    server_version = "ExfiliatorHTTP/1.0"

    def do_POST(self) -> None:
        if self.path != "/upload":
            self.send_response(404)
            self.end_headers()
            return

        psk = getattr(self.server, "psk", None)
        if not psk:
            self.send_response(500)
            self.end_headers()
            return

        req_psk = self.headers.get("X-PSK", "")
        test_id = self.headers.get("X-Test-Id", "")

        if req_psk != psk:
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": False, "error": "Invalid PSK"}).encode("utf-8"))
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except Exception:
            length = 0

        remaining = length
        received = 0
        while remaining > 0:
            chunk = self.rfile.read(min(65536, remaining))
            if not chunk:
                break
            received += len(chunk)
            remaining -= len(chunk)

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"ok": True, "bytes_received": received, "test_id": test_id}).encode("utf-8"))

    def log_message(self, fmt: str, *args) -> None:
        return


def http_worker(bind: str, port: int, psk: str, stop_event: threading.Event) -> None:
    httpd = ThreadingHTTPServer((bind, port), UploadHandler)
    setattr(httpd, "psk", psk)
    httpd.timeout = 1.0

    while not stop_event.is_set():
        httpd.handle_request()

    try:
        httpd.server_close()
    except Exception:
        pass


# ---------------------------
# Main
# ---------------------------

def parse_ports(csv: str) -> List[int]:
    out: List[int] = []
    for part in (csv or "").split(","):
        part = part.strip()
        if not part:
            continue
        out.append(int(part))
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="0.0.0.0", help="Bind interface/IP (default 0.0.0.0)")
    ap.add_argument("--tcp-ports", default="", help="Comma-separated TCP ports to listen on")
    ap.add_argument("--udp-ports", default="", help="Comma-separated UDP ports to listen on")
    ap.add_argument("--http-port", type=int, default=0, help="HTTP port for POST /upload (0 disables)")
    ap.add_argument("--psk-file", default="pt_psk.txt", help="Path to PSK file (created if missing)")
    ap.add_argument("--print-psk", action="store_true", help="Print PSK to stdout on startup")

    # Firewall management
    ap.add_argument(
        "--manage-firewall",
        action="store_true",
        help="(Windows only, requires Admin unless --firewall-dry-run) Create temporary inbound allow rules for requested ports; remove on exit."
    )
    ap.add_argument(
        "--firewall-dry-run",
        action="store_true",
        help="Print planned firewall actions, but do not create/remove any firewall rules."
    )
    ap.add_argument("--firewall-name-prefix", default="Exfiliator TEMP",
                    help="Prefix for created firewall rule display names (used for cleanup)")
    ap.add_argument("--firewall-profile", default="Any",
                    help="Firewall profile for rules: Domain|Private|Public|Any (default Any)")
    ap.add_argument("--firewall-remote-addresses", default="LocalSubnet",
                    help="RemoteAddress scope for rules (default LocalSubnet). Use 'Any' to allow all sources.")

    args = ap.parse_args()

    psk = load_or_create_psk(args.psk_file)
    if args.print_psk:
        print(psk)

    tcp_ports = parse_ports(args.tcp_ports)
    udp_ports = parse_ports(args.udp_ports)
    http_port = int(args.http_port or 0)

    # Preflight: ensure ports can be bound
    for p in tcp_ports:
        if not check_tcp_bindable(args.bind, p):
            raise SystemExit(f"TCP port {p} is not available to bind on {args.bind}. Is it already in use?")
    for p in udp_ports:
        if not check_udp_bindable(args.bind, p):
            raise SystemExit(f"UDP port {p} is not available to bind on {args.bind}. Is it already in use?")
    if http_port > 0 and not check_tcp_bindable(args.bind, http_port):
        raise SystemExit(f"HTTP port {http_port} is not available to bind on {args.bind}. Is it already in use?")

    fw = TempFirewallRules(
        enabled=bool(args.manage_firewall),
        dry_run=bool(args.firewall_dry_run),
        name_prefix=str(args.firewall_name_prefix),
        profile=str(args.firewall_profile),
        remote_addresses=str(args.firewall_remote_addresses),
    )

    # Cleanup on process exit (best effort)
    atexit.register(fw.cleanup)

    if args.manage_firewall:
        if not is_windows():
            print("[firewall] WARNING: --manage-firewall is set but OS is not Windows. Skipping firewall actions.")
        else:
            if (not args.firewall_dry_run) and (not is_admin_windows()):
                raise SystemExit("Run this server as Administrator to use --manage-firewall (or use --firewall-dry-run).")

            for p in tcp_ports:
                fw.add_rule("TCP", p, tag="listener")
            for p in udp_ports:
                fw.add_rule("UDP", p, tag="listener")
            if http_port > 0:
                fw.add_rule("TCP", http_port, tag="http")

    stop_event = threading.Event()
    threads: List[threading.Thread] = []

    for p in tcp_ports:
        t = threading.Thread(target=tcp_worker, args=(args.bind, p, psk, stop_event), daemon=True)
        t.start()
        threads.append(t)

    for p in udp_ports:
        t = threading.Thread(target=udp_worker, args=(args.bind, p, psk, stop_event), daemon=True)
        t.start()
        threads.append(t)

    if http_port > 0:
        t = threading.Thread(target=http_worker, args=(args.bind, http_port, psk, stop_event), daemon=True)
        t.start()
        threads.append(t)

    print("Exfiliator server running.")
    if tcp_ports:
        print(f"  TCP: {tcp_ports}")
    if udp_ports:
        print(f"  UDP: {udp_ports}")
    if http_port > 0:
        print(f"  HTTP: {http_port} (/upload)")

    if args.manage_firewall:
        mode = "DRY-RUN" if args.firewall_dry_run else "APPLY"
        print(f"  Firewall: {mode} (RemoteAddress={args.firewall_remote_addresses}, Profile={args.firewall_profile})")
    print("Press Ctrl+C to stop.")
    if args.manage_firewall and (not args.firewall_dry_run):
        print("Temp firewall rules created by this server instance will be removed on exit.")

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        time.sleep(0.5)
        # Cleanup explicitly too
        fw.cleanup()


if __name__ == "__main__":
    main()
