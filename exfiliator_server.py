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
import base64
import json
import logging
import os
import re
import secrets
import shutil
import socket
import struct
import subprocess
import threading
import time
import uuid
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from version import __version__

log = logging.getLogger("exfiliator_server")


def mock_sensitive_text() -> str:
    return (
        "BEGIN MOCK SENSITIVE DATA\n"
        "Full Name: Jane Doe\n"
        "SSN: 123-45-6789\n"
        "Credit Card: 4111-1111-1111-1111\n"
        "DOB: 1970-01-01\n"
        "Medical Record: Chronic asthma monitoring required.\n"
        "Address: 123 Main St, Anytown, USA\n"
        "END MOCK DATA\n"
    )


DNS_QTYPE_CODES = {"A": 1, "AAAA": 28, "TXT": 16}


def _decode_psk_label(label: str) -> str | None:
    if not label.startswith("psk-"):
        return None
    enc = label[4:].upper()
    if not enc:
        return None
    padding = "=" * ((8 - len(enc) % 8) % 8)
    try:
        return base64.b32decode(enc + padding, casefold=True).decode("utf-8")
    except Exception:
        return None


def _parse_dns_name(data: bytes, offset: int) -> tuple[list[str], int] | tuple[None, int]:
    labels: list[str] = []
    while True:
        if offset >= len(data):
            return None, offset
        length = data[offset]
        offset += 1
        if length == 0:
            break
        if offset + length > len(data):
            return None, offset
        label = data[offset:offset + length].decode("utf-8", errors="ignore").lower()
        labels.append(label)
        offset += length
    return labels, offset


def _build_dns_response(query: bytes, psk: str) -> bytes | None:
    if len(query) < 12:
        return None
    qid, flags, qdcount, _, _, _ = struct.unpack("!HHHHHH", query[:12])
    if qdcount < 1:
        return None
    labels_tuple = _parse_dns_name(query, 12)
    labels = labels_tuple[0]
    offset = labels_tuple[1]
    if not labels or len(labels) < 2:
        return _dns_error(qid, query, rcode=5)
    decoded = _decode_psk_label(labels[1])
    if decoded != psk:
        return _dns_error(qid, query, rcode=5)
    if offset + 4 > len(query):
        return _dns_error(qid, query, rcode=5)
    qtype, qclass = struct.unpack("!HH", query[offset:offset + 4])
    if qclass != 1:
        return _dns_error(qid, query, rcode=5)
    answer_rdata = _dns_answer_rdata(qtype)
    if answer_rdata is None:
        return _dns_error(qid, query, rcode=3)
    header = struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0)
    question = query[12:offset + 4]
    answer = question[:-4] + struct.pack("!HHIH", qtype, 1, 30, len(answer_rdata)) + answer_rdata
    return header + question + answer


def _dns_answer_rdata(qtype: int) -> bytes | None:
    if qtype == 1:
        return socket.inet_aton("127.0.0.1")
    if qtype == 28:
        return socket.inet_pton(socket.AF_INET6, "::1")
    if qtype == 16:
        text = "exfiliator-dns"
        data = text.encode("utf-8")
        return bytes([len(data)]) + data
    return None


def _dns_error(qid: int, query: bytes, rcode: int) -> bytes:
    header = struct.pack("!HHHHHH", qid, 0x8180 | rcode, 1, 0, 0, 0)
    question_end = query[12:]
    return header + question_end


# ---------------------------
# PSK utilities
# ---------------------------

def generate_psk() -> str:
    return secrets.token_urlsafe(32)


def load_psk_from_file(psk_file: str) -> str:
    if not os.path.exists(psk_file):
        raise SystemExit(f"PSK file '{psk_file}' not found. Provide --psk or generate a file manually.")
    with open(psk_file, encoding="utf-8") as f:
        value = f.read().strip()
    if not value:
        raise SystemExit(f"PSK file '{psk_file}' is empty.")
    return value


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


def run_powershell(ps: str) -> tuple[int, str, str]:
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
        self._created_rule_names: list[str] = []
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


class VerbosityMonitor:
    def __init__(self, logger: logging.Logger) -> None:
        self.logger = logger
        self.stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._enabled = False

    def start(self) -> None:
        if not sys.stdin or not sys.stdin.isatty():
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
                        if ch in ("v", "V"):
                            self._enable_verbose()
                            return
                    time.sleep(0.1)
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
                            if ch in ("v", "V"):
                                self._enable_verbose()
                                return
                finally:
                    termios.tcsetattr(fd, termios.TCSADRAIN, old)
        except Exception:
            return

    def stop(self) -> None:
        self.stop_event.set()

    def _enable_verbose(self) -> None:
        if self._enabled:
            return
        self._enabled = True
        self.logger.setLevel(logging.DEBUG)
        print("[server] Verbose logging enabled (triggered by keyboard).")


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

def tcp_worker(bind: str, port: int, psk: str, stop_event: threading.Event, max_bytes: int) -> None:
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

        threading.Thread(target=_tcp_handle_client, args=(conn, addr, psk, max_bytes), daemon=True).start()

    try:
        srv.close()
    except Exception:
        pass


def _tcp_handle_client(conn: socket.socket, addr: tuple[str, int], psk: str, max_bytes: int) -> None:
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
        if expected < 0:
            expected = 0
        if expected > max_bytes:
            resp = {"ok": False, "error": f"Refusing TCP payload > {max_bytes} bytes"}
            conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))
            conn.close()
            return
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
# Telnet server
# ---------------------------

def telnet_worker(bind: str, port: int, psk: str, stop_event: threading.Event) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind, port))
    srv.listen(20)
    srv.settimeout(1.0)

    while not stop_event.is_set():
        try:
            conn, addr = srv.accept()
        except socket.timeout:
            continue
        except Exception:
            continue
        threading.Thread(target=_telnet_handle_client, args=(conn, addr, psk), daemon=True).start()

    try:
        srv.close()
    except Exception:
        pass


def _telnet_readline(conn: socket.socket, limit: int = 4096) -> str:
    data = bytearray()
    while True:
        chunk = conn.recv(1)
        if not chunk:
            raise ConnectionError("Client disconnected.")
        data.extend(chunk)
        if chunk == b"\n" or len(data) >= limit:
            break
    return bytes(data).rstrip(b"\r\n").decode("utf-8", errors="ignore")


def _telnet_handle_client(conn: socket.socket, addr: tuple[str, int], psk: str) -> None:
    conn.settimeout(15.0)
    try:
        conn.sendall(b"Welcome to Exfiliator Telnet Service\r\nlogin: ")
        username = _telnet_readline(conn)
        conn.sendall(b"Password: ")
        password = _telnet_readline(conn)
        conn.sendall(b"PSK: ")
        provided_psk = _telnet_readline(conn)

        if provided_psk != psk:
            conn.sendall(b"Authentication failed.\r\n")
            conn.close()
            return

        banner = f"\r\nAuthenticated as {username or 'user'}\r\nEnter commands (type EXIT to quit).\r\n> "
        conn.sendall(banner.encode("utf-8"))

        while True:
            cmd = _telnet_readline(conn)
            if not cmd:
                conn.sendall(b"> ")
                continue
            upper = cmd.strip().upper()
            if upper in {"EXIT", "QUIT"}:
                conn.sendall(b"Session closed.\r\n")
                break
            if cmd.startswith("DATA "):
                payload = cmd[5:]
                response = f"Captured data chunk ({len(payload)} bytes).\r\n> "
                conn.sendall(response.encode("utf-8", errors="ignore"))
                continue
            if cmd.startswith("OBF "):
                payload = cmd[4:]
                response = f"Captured obfuscated data chunk ({len(payload)} bytes).\r\n> "
                conn.sendall(response.encode("utf-8", errors="ignore"))
                continue
            response = f"Executed: {cmd}\r\n> "
            conn.sendall(response.encode("utf-8", errors="ignore"))

        conn.close()
    except Exception:
        try:
            conn.close()
        except Exception:
            pass


# ---------------------------
# SMTP server
# ---------------------------

def smtp_worker(bind: str, port: int, psk: str, stop_event: threading.Event) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind, port))
    srv.listen(20)
    srv.settimeout(1.0)

    while not stop_event.is_set():
        try:
            conn, addr = srv.accept()
        except socket.timeout:
            continue
        except Exception:
            continue
        threading.Thread(target=_smtp_handle_client, args=(conn, addr, psk), daemon=True).start()

    try:
        srv.close()
    except Exception:
        pass


def _smtp_readline_bytes(fh: Any, limit: int = 65536) -> bytes:
    line = fh.readline(limit)
    if not line:
        raise ConnectionError("SMTP client disconnected.")
    return line


def _smtp_readline(fh: Any, limit: int = 4096) -> str:
    line = _smtp_readline_bytes(fh, limit)
    return line.rstrip(b"\r\n").decode("utf-8", errors="ignore")


def _smtp_handle_client(conn: socket.socket, addr: tuple[str, int], psk: str) -> None:
    conn.settimeout(15.0)
    fh = conn.makefile("rb")

    def send(line: str) -> None:
        conn.sendall((line + "\r\n").encode("utf-8"))

    try:
        send("220 exfiliator-server ESMTP ready")
        greeting = _smtp_readline(fh)
        if not greeting.upper().startswith(("EHLO", "HELO")):
            send("500 Expected EHLO/HELO")
            conn.close()
            return
        send("250-exfiliator-server")
        send("250 AUTH PSK")

        auth_line = _smtp_readline(fh)
        parts = auth_line.split()
        if len(parts) < 3 or parts[0].upper() != "AUTH" or parts[1].upper() != "PSK":
            send("535 Authentication mechanism invalid")
            conn.close()
            return
        provided_psk = " ".join(parts[2:])
        if provided_psk != psk:
            send("535 Authentication failed")
            conn.close()
            return
        send("235 Authentication successful")

        mail_from = _smtp_readline(fh)
        if not mail_from.upper().startswith("MAIL FROM"):
            send("500 MAIL FROM required")
            conn.close()
            return
        send("250 OK")

        rcpt_to = _smtp_readline(fh)
        if not rcpt_to.upper().startswith("RCPT TO"):
            send("500 RCPT TO required")
            conn.close()
            return
        send("250 OK")

        data_cmd = _smtp_readline(fh)
        if data_cmd.upper() != "DATA":
            send("500 DATA command required")
            conn.close()
            return
        send("354 End data with <CR><LF>.<CR><LF>")

        while True:
            raw = _smtp_readline_bytes(fh)
            if raw in (b".\r\n", b".\n", b"."):
                break
        message_id = uuid.uuid4().hex[:8]
        send(f"250 Message accepted for delivery ({message_id})")

        try:
            quit_cmd = _smtp_readline(fh)
        except ConnectionError:
            quit_cmd = ""
        if quit_cmd.strip().upper() == "QUIT":
            send("221 Bye")
        conn.close()
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
    finally:
        try:
            fh.close()
        except Exception:
            pass


# ---------------------------
# UDP server
# ---------------------------

_UDPModes = ("reliable", "batched_ack", "firehose")


class UDPClientState:
    __slots__ = ("mode", "ack_every", "last_acked_seq", "max_seen_seq", "last_activity")

    def __init__(self, mode: str, ack_every: int) -> None:
        self.mode = mode
        self.ack_every = max(1, int(ack_every))
        self.last_acked_seq = 0
        self.max_seen_seq = 0
        self.last_activity = time.time()

    def touch(self) -> None:
        self.last_activity = time.time()


def udp_worker(bind: str, port: int, psk: str, stop_event: threading.Event, session_ttl: float) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind, port))
    sock.settimeout(1.0)

    authorized: dict[tuple[str, int], UDPClientState] = {}
    seq_fmt = "!Q"
    cleanup_deadline = time.time() + max(1.0, session_ttl)

    while not stop_event.is_set():
        now = time.time()
        if now >= cleanup_deadline:
            for k, st in list(authorized.items()):
                if now - st.last_activity > session_ttl:
                    authorized.pop(k, None)
            cleanup_deadline = now + max(1.0, session_ttl / 4.0)
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
                state = UDPClientState(mode=mode, ack_every=ack_every)
                authorized[addr] = state
                state.touch()

                sock.sendto(b"HELLO_ACK", addr)
                continue

            if pkt.startswith(b"DATA ") and len(pkt) >= 5 + 8:
                st = authorized.get(addr)
                if not st:
                    continue
                st.touch()

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
# DNS server
# ---------------------------

def dns_worker(bind: str, port: int, psk: str, stop_event: threading.Event) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind, port))
    sock.settimeout(1.0)
    while not stop_event.is_set():
        try:
            data, addr = sock.recvfrom(1024)
        except socket.timeout:
            continue
        except Exception:
            continue
        try:
            resp = _build_dns_response(data, psk)
            if resp:
                sock.sendto(resp, addr)
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

    def setup(self) -> None:
        super().setup()
        timeout = getattr(self.server, "http_read_timeout", 15.0)
        try:
            self.connection.settimeout(timeout)
        except Exception:
            pass

    def do_GET(self) -> None:
        if self.path != "/download":
            self.send_response(404)
            self.end_headers()
            return

        if not getattr(self.server, "mock_download_enabled", False):
            self.send_response(404)
            self.end_headers()
            return

        psk = getattr(self.server, "psk", None)
        if not psk:
            self.send_response(500)
            self.end_headers()
            return

        req_psk = self.headers.get("X-PSK", "")
        if req_psk != psk:
            self.send_response(401)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Invalid PSK")
            return

        body = mock_sensitive_text().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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
        max_bytes = getattr(self.server, "max_http_bytes", None)
        if max_bytes is not None and length > max_bytes:
            self.send_response(413)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            error_obj = {"ok": False, "error": f"HTTP payload exceeds {max_bytes} bytes"}
            self.wfile.write(json.dumps(error_obj).encode("utf-8"))
            return

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


def http_worker(
    bind: str,
    port: int,
    psk: str,
    stop_event: threading.Event,
    max_http_bytes: int,
    http_read_timeout: float,
    mock_download_enabled: bool,
) -> None:
    httpd = ThreadingHTTPServer((bind, port), UploadHandler)
    httpd.psk = psk
    httpd.max_http_bytes = max_http_bytes
    httpd.http_read_timeout = http_read_timeout
    httpd.mock_download_enabled = mock_download_enabled
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

def parse_ports(csv: str) -> list[int]:
    out: list[int] = []
    seen = set()
    for part in (csv or "").split(","):
        token = part.strip()
        if not token:
            continue
        if "-" in token:
            try:
                start_str, end_str = token.split("-", 1)
                start = int(start_str)
                end = int(end_str)
            except ValueError as exc:
                raise SystemExit(f"Invalid port range '{token}'.") from exc
            if start > end:
                raise SystemExit(f"Invalid port range '{token}' (start > end).")
            if start < 1 or end > 65535:
                raise SystemExit(f"Port range '{token}' must be between 1 and 65535.")
            for port in range(start, end + 1):
                if port not in seen:
                    out.append(port)
                    seen.add(port)
        else:
            try:
                port = int(token)
            except ValueError as exc:
                raise SystemExit(f"Invalid port '{token}'.") from exc
            if not (1 <= port <= 65535):
                raise SystemExit(f"Port '{token}' must be between 1 and 65535.")
            if port not in seen:
                out.append(port)
                seen.add(port)
    return out


def setup_logging(verbosity: int) -> None:
    if verbosity <= 0:
        level = logging.INFO
    else:
        level = logging.DEBUG
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(message)s")


def _run_capture(cmd: list[str]) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except Exception:
        return ""
    return out.stdout.strip()


def describe_port_conflict(proto: str, port: int) -> str:
    proto_u = proto.upper()
    # Prefer lsof when available
    if shutil.which("lsof"):
        args = ["lsof", "-nP", f"-i{proto_u}:{port}"]
        if proto_u == "TCP":
            args.extend(["-sTCP:LISTEN"])
        out = _run_capture(args)
        lines = [line for line in out.splitlines() if line]
        if len(lines) >= 2:
            cols = re.split(r"\s+", lines[1])
            if len(cols) >= 2:
                return f"{cols[0]} (PID {cols[1]})"

    # netstat on Windows
    if os.name == "nt" and shutil.which("netstat"):
        out = _run_capture(["netstat", "-ano", "-p", proto_u])
        for line in out.splitlines():
            cols = line.split()
            if not cols:
                continue
            if cols[0].lower() != proto.lower():
                continue
            if len(cols) < 4:
                continue
            local = cols[1]
            pid = cols[-1]
            if local.endswith(f":{port}"):
                if shutil.which("tasklist"):
                    task = _run_capture(["tasklist", "/FI", f"PID eq {pid}"])
                    match = re.search(r"^(\S+\.exe)", task, re.MULTILINE)
                    if match:
                        return f"{match.group(1)} (PID {pid})"
                return f"PID {pid}"

    # netstat on Unix (requires permissions for PID info)
    if shutil.which("netstat"):
        out = _run_capture(["netstat", "-anp", proto.lower()])
        for line in out.splitlines():
            if f":{port} " not in line:
                continue
            match = re.search(r"\s+(\S+)/(\S+)$", line.strip())
            if match:
                return match.group(0).strip()

    return "Unknown process"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    ap.add_argument("--bind", default="0.0.0.0", help="Bind interface/IP (default 0.0.0.0)")
    ap.add_argument("--tcp-ports", default="", help="Comma-separated TCP ports to listen on")
    ap.add_argument("--udp-ports", default="", help="Comma-separated UDP ports to listen on")
    ap.add_argument("--dns-ports", default="", help="Comma-separated DNS ports (UDP) to listen on")
    ap.add_argument("--telnet-ports", default="", help="Comma-separated Telnet-emulation ports (TCP)")
    ap.add_argument("--smtp-ports", default="", help="Comma-separated SMTP-emulation ports (TCP)")
    ap.add_argument("--http-port", type=int, default=0, help="HTTP port for POST /upload (0 disables)")
    ap.add_argument("--psk", default=None, help="Explicit PSK value (otherwise generated per run)")
    ap.add_argument("--psk-file", default=None, help="Read PSK from this file (no file is created)")
    ap.add_argument(
        "--suppress-psk-display",
        action="store_true",
        help="Do not print the PSK to stdout on startup (default is to display it once).",
    )
    ap.add_argument("--max-tcp-bytes", type=int, default=50_000_000,
                    help="Maximum TCP payload bytes accepted per test (default 50MB)")
    ap.add_argument("--max-http-bytes", type=int, default=50_000_000,
                    help="Maximum HTTP upload bytes accepted per request (default 50MB)")
    ap.add_argument("--http-read-timeout", type=float, default=15.0,
                    help="HTTP socket read timeout in seconds (default 15s)")
    ap.add_argument("--udp-session-ttl", type=float, default=60.0,
                    help="Seconds to keep authorized UDP clients alive without activity (default 60s)")
    ap.add_argument("--enable-mock-download", action="store_true",
                    help="Enable HTTP/S GET /download endpoint that returns mock sensitive data (requires PSK).")
    ap.add_argument("-v", "--verbose", action="count", default=0,
                    help="Increase logging verbosity (-v for verbose, -vv for very verbose)")

    # Firewall management
    ap.add_argument(
        "--manage-firewall",
        action="store_true",
        help=(
            "(Windows only, requires Admin unless --firewall-dry-run) "
            "Create temporary inbound allow rules for requested ports; remove on exit."
        ),
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
    setup_logging(args.verbose)
    verbosity_monitor = VerbosityMonitor(log)

    if args.psk and args.psk_file:
        raise SystemExit("--psk and --psk-file cannot be used together.")

    if args.psk:
        psk = args.psk.strip()
    elif args.psk_file:
        psk = load_psk_from_file(args.psk_file)
    else:
        psk = generate_psk()

    if not psk:
        raise SystemExit("PSK value cannot be empty.")

    if not args.suppress_psk_display:
        print("Server PSK (share only with authorized clients):")
        print(f"  {psk}")
        if args.psk_file:
            print(f"  Source file: {args.psk_file}")
        else:
            print("  Generated for this run (not written to disk).")

    max_tcp_bytes = int(args.max_tcp_bytes)
    if max_tcp_bytes <= 0:
        raise SystemExit("--max-tcp-bytes must be greater than zero")
    max_http_bytes = int(args.max_http_bytes)
    if max_http_bytes <= 0:
        raise SystemExit("--max-http-bytes must be greater than zero")
    http_read_timeout = float(args.http_read_timeout)
    if http_read_timeout <= 0:
        raise SystemExit("--http-read-timeout must be greater than zero")
    udp_session_ttl = float(args.udp_session_ttl)
    if udp_session_ttl <= 0:
        raise SystemExit("--udp-session-ttl must be greater than zero")

    tcp_ports = parse_ports(args.tcp_ports)
    udp_ports = parse_ports(args.udp_ports)
    dns_ports = parse_ports(args.dns_ports)
    telnet_ports = parse_ports(args.telnet_ports)
    smtp_ports = parse_ports(args.smtp_ports)
    http_port = int(args.http_port or 0)

    # Preflight: ensure ports can be bound
    for p in tcp_ports:
        if not check_tcp_bindable(args.bind, p):
            owner = describe_port_conflict("tcp", p)
            raise SystemExit(
                f"TCP port {p} is not available on {args.bind}. In use by: {owner}. "
                "Stop the conflicting process or choose another port."
            )
    for p in telnet_ports:
        if not check_tcp_bindable(args.bind, p):
            owner = describe_port_conflict("tcp", p)
            raise SystemExit(
                f"TCP port {p} is not available on {args.bind}. In use by: {owner}. "
                "Stop the conflicting process or choose another port."
            )
    for p in smtp_ports:
        if not check_tcp_bindable(args.bind, p):
            owner = describe_port_conflict("tcp", p)
            raise SystemExit(
                f"TCP port {p} is not available on {args.bind}. In use by: {owner}. "
                "Stop the conflicting process or choose another port."
            )
    for p in udp_ports:
        if not check_udp_bindable(args.bind, p):
            owner = describe_port_conflict("udp", p)
            raise SystemExit(
                f"UDP port {p} is not available on {args.bind}. In use by: {owner}. "
                "Stop the conflicting process or choose another port."
            )
    for p in dns_ports:
        if not check_udp_bindable(args.bind, p):
            owner = describe_port_conflict("udp", p)
            raise SystemExit(
                f"DNS port {p} is not available on {args.bind}. In use by: {owner}. "
                "Stop the conflicting process or choose another port."
            )
    if http_port > 0 and not check_tcp_bindable(args.bind, http_port):
        raise SystemExit(f"HTTP port {http_port} is not available to bind on {args.bind}. Is it already in use?")

    verbosity_monitor.start()
    print("Press V at any time to enable verbose logging.")

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
                raise SystemExit(
                    "Run this server as Administrator to use --manage-firewall "
                    "(or rerun with --firewall-dry-run)."
                )

            for p in tcp_ports:
                fw.add_rule("TCP", p, tag="listener")
            for p in telnet_ports:
                fw.add_rule("TCP", p, tag="telnet")
            for p in smtp_ports:
                fw.add_rule("TCP", p, tag="smtp")
            for p in udp_ports:
                fw.add_rule("UDP", p, tag="listener")
            for p in dns_ports:
                fw.add_rule("UDP", p, tag="dns")
            if http_port > 0:
                fw.add_rule("TCP", http_port, tag="http")

    stop_event = threading.Event()
    threads: list[threading.Thread] = []

    for p in tcp_ports:
        t = threading.Thread(target=tcp_worker, args=(args.bind, p, psk, stop_event, max_tcp_bytes), daemon=True)
        t.start()
        threads.append(t)

    for p in telnet_ports:
        t = threading.Thread(target=telnet_worker, args=(args.bind, p, psk, stop_event), daemon=True)
        t.start()
        threads.append(t)

    for p in smtp_ports:
        t = threading.Thread(target=smtp_worker, args=(args.bind, p, psk, stop_event), daemon=True)
        t.start()
        threads.append(t)

    for p in udp_ports:
        t = threading.Thread(
            target=udp_worker,
            args=(args.bind, p, psk, stop_event, udp_session_ttl),
            daemon=True,
        )
        t.start()
        threads.append(t)

    for p in dns_ports:
        t = threading.Thread(
            target=dns_worker,
            args=(args.bind, p, psk, stop_event),
            daemon=True,
        )
        t.start()
        threads.append(t)

    if http_port > 0:
        t = threading.Thread(
            target=http_worker,
            args=(args.bind, http_port, psk, stop_event, max_http_bytes, http_read_timeout, args.enable_mock_download),
            daemon=True,
        )
        t.start()
        threads.append(t)

    log.info("Exfiliator server running on %s", args.bind)
    if tcp_ports:
        log.info("  TCP ports: %s", tcp_ports)
    if telnet_ports:
        log.info("  Telnet ports: %s", telnet_ports)
    if smtp_ports:
        log.info("  SMTP ports: %s", smtp_ports)
    if udp_ports:
        log.info("  UDP ports: %s", udp_ports)
    if dns_ports:
        log.info("  DNS ports: %s", dns_ports)
    if http_port > 0:
        log.info("  HTTP: %s (/upload)", http_port)

    if args.manage_firewall:
        mode = "DRY-RUN" if args.firewall_dry_run else "APPLY"
        log.info("  Firewall mode: %s (RemoteAddress=%s, Profile=%s)", mode, args.firewall_remote_addresses,
                 args.firewall_profile)
    print("Press Ctrl+C to stop.")
    if args.manage_firewall and (not args.firewall_dry_run):
        print("Temp firewall rules created by this server instance will be removed on exit.")

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        log.info("Shutting down server...")
    finally:
        stop_event.set()
        time.sleep(0.5)
        # Cleanup explicitly too
        fw.cleanup()
        verbosity_monitor.stop()


if __name__ == "__main__":
    main()
