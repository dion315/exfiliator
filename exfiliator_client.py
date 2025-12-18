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
import base64
import datetime as dt
import getpass
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
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse, urlunparse
import random

from version import __version__

log = logging.getLogger("exfiliator_client")
SENSITIVE_FRAMEWORKS = ["PCI DSS", "HIPAA", "GDPR"]


# -------------------------
# Cross-platform "press Q to quit"
# -------------------------

class QuitMonitor:
    def __init__(self) -> None:
        self.stop_event = threading.Event()
        self._thread: threading.Thread | None = None

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


@dataclass
class DnsTest:
    host: str
    port: int
    qname: str
    qtype: str


@dataclass
class TelnetTest:
    host: str
    port: int
    username: str
    password: str
    commands: list[str]


@dataclass
class SmtpTest:
    host: str
    port: int
    mail_from: str
    rcpt_to: str
    subject: str
    body: str


class ConfigError(Exception):
    """Raised when the JSON config fails validation."""


def _require_positive_int(value: Any, field: str, allow_zero: bool = False) -> int:
    try:
        iv = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{field} must be an integer.") from exc
    if allow_zero and iv == 0:
        return iv
    if iv <= 0:
        raise ConfigError(f"{field} must be greater than zero.")
    return iv


def _require_port(value: Any, field: str) -> int:
    port = _require_positive_int(value, field)
    if not (1 <= port <= 65535):
        raise ConfigError(f"{field} must be between 1 and 65535.")
    return port


def _require_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{field} must be a non-empty string.")
    return value.strip()


def validate_config(cfg: dict[str, Any]) -> None:
    if not isinstance(cfg, dict):
        raise ConfigError("Config root must be a JSON object.")

    sections = {}
    for key in ("tcp", "udp", "http", "dns", "telnet", "smtp"):
        value = cfg.get(key, [])
        if value is None:
            value = []
        if not isinstance(value, list):
            raise ConfigError(f"'{key}' must be a list.")
        sections[key] = value
        cfg[key] = value

    for idx, item in enumerate(sections["tcp"]):
        if not isinstance(item, dict):
            raise ConfigError(f"tcp[{idx}] must be an object.")
        _require_port(item.get("port"), f"tcp[{idx}].port")
        _require_positive_int(item.get("bytes"), f"tcp[{idx}].bytes")
        if "host" in item and not isinstance(item.get("host"), (str, type(None))):
            raise ConfigError(f"tcp[{idx}].host must be a string if provided.")

    for idx, item in enumerate(sections["udp"]):
        if not isinstance(item, dict):
            raise ConfigError(f"udp[{idx}] must be an object.")
        _require_port(item.get("port"), f"udp[{idx}].port")
        _require_positive_int(item.get("packets"), f"udp[{idx}].packets")
        _require_positive_int(item.get("ack_every", 1), f"udp[{idx}].ack_every")
        _require_positive_int(item.get("batch_size", 1), f"udp[{idx}].batch_size")
        _require_positive_int(item.get("ack_timeout_ms", 1), f"udp[{idx}].ack_timeout_ms")
        _require_positive_int(item.get("payload_size", 1), f"udp[{idx}].payload_size", allow_zero=True)
        _require_positive_int(item.get("inter_packet_ms", 0), f"udp[{idx}].inter_packet_ms", allow_zero=True)
        if "host" in item and not isinstance(item.get("host"), (str, type(None))):
            raise ConfigError(f"udp[{idx}].host must be a string if provided.")
        if "udp_mode" in item and not isinstance(item.get("udp_mode"), (str, type(None))):
            raise ConfigError(f"udp[{idx}].udp_mode must be a string if provided.")

    for idx, item in enumerate(sections["http"]):
        if not isinstance(item, dict):
            raise ConfigError(f"http[{idx}] must be an object.")
        _require_string(item.get("url"), f"http[{idx}].url")
        _require_positive_int(item.get("bytes"), f"http[{idx}].bytes")

    for idx, item in enumerate(sections["dns"]):
        if not isinstance(item, dict):
            raise ConfigError(f"dns[{idx}] must be an object.")
        _require_port(item.get("port"), f"dns[{idx}].port")
        _require_string(item.get("host"), f"dns[{idx}].host")
        _require_string(item.get("qname"), f"dns[{idx}].qname")
        qtype = str(item.get("qtype", "A")).upper()
        if qtype not in {"A", "AAAA", "TXT"}:
            raise ConfigError(f"dns[{idx}].qtype must be one of A, AAAA, TXT.")
    for idx, item in enumerate(sections["telnet"]):
        if not isinstance(item, dict):
            raise ConfigError(f"telnet[{idx}] must be an object.")
        _require_port(item.get("port"), f"telnet[{idx}].port")
        _require_string(item.get("username"), f"telnet[{idx}].username")
        _require_string(item.get("password"), f"telnet[{idx}].password")
        commands = item.get("commands", [])
        if not isinstance(commands, list) or not commands:
            raise ConfigError(f"telnet[{idx}].commands must be a non-empty list.")
        for c_idx, command in enumerate(commands):
            if not isinstance(command, str) or not command.strip():
                raise ConfigError(f"telnet[{idx}].commands[{c_idx}] must be a non-empty string.")
        host_val = item.get("host")
        if host_val is not None and not isinstance(host_val, str):
            raise ConfigError(f"telnet[{idx}].host must be a string if provided.")
    for idx, item in enumerate(sections["smtp"]):
        if not isinstance(item, dict):
            raise ConfigError(f"smtp[{idx}] must be an object.")
        _require_port(item.get("port"), f"smtp[{idx}].port")
        _require_string(item.get("mail_from"), f"smtp[{idx}].mail_from")
        _require_string(item.get("rcpt_to"), f"smtp[{idx}].rcpt_to")
        _require_string(item.get("subject"), f"smtp[{idx}].subject")
        _require_string(item.get("body"), f"smtp[{idx}].body")
        host_val = item.get("host")
        if host_val is not None and not isinstance(host_val, str):
            raise ConfigError(f"smtp[{idx}].host must be a string if provided.")


def resolve_config_path(path: str) -> Path:
    candidate = Path(path).expanduser()
    if candidate.exists():
        return candidate
    configs_dir = Path(__file__).resolve().parent / "configs"
    if not candidate.is_absolute():
        fallback = configs_dir / path
        if fallback.exists():
            return fallback
    raise ConfigError(f"Config file '{path}' not found (searched working directory and {configs_dir})")


def load_config(path: str) -> dict[str, Any]:
    cfg_path = resolve_config_path(path)
    with open(cfg_path, encoding="utf-8") as f:
        cfg = json.load(f)
    validate_config(cfg)
    return cfg


def parse_port_spec(spec: str) -> set[int]:
    ports: set[int] = set()
    for part in (spec or "").split(","):
        token = part.strip()
        if not token:
            continue
        if "-" in token:
            try:
                start_str, end_str = token.split("-", 1)
                start = int(start_str)
                end = int(end_str)
            except ValueError as exc:
                raise ValueError(f"Invalid range '{token}'") from exc
            if start > end:
                raise ValueError(f"Invalid range '{token}' (start > end)")
            if start < 1 or end > 65535:
                raise ValueError(f"Range '{token}' must be between 1 and 65535")
            ports.update(range(start, end + 1))
        else:
            try:
                port = int(token)
            except ValueError as exc:
                raise ValueError(f"Invalid port '{token}'") from exc
            if not (1 <= port <= 65535):
                raise ValueError(f"Port '{token}' must be between 1 and 65535")
            ports.add(port)
    if not ports:
        raise ValueError("No valid ports found in specification.")
    return ports


def mock_sensitive_payload() -> bytes:
    data = (
        "BEGIN MOCK SENSITIVE DATA\n"
        "Full Name: Jane Doe\n"
        "SSN: 123-45-6789\n"
        "Credit Card: 4111-1111-1111-1111\n"
        "DOB: 1970-01-01\n"
        "Medical Record: Chronic asthma monitoring required.\n"
        "Address: 123 Main St, Anytown, USA\n"
        "END MOCK DATA\n"
    )
    return data.encode("utf-8")


def sensitive_info(enabled: bool, status: str, detail: str = "") -> dict[str, Any]:
    return {
        "enabled": enabled,
        "status": status,
        "detail": detail,
        "frameworks": SENSITIVE_FRAMEWORKS,
    }


def classify_sensitive_error(err: BaseException) -> tuple[str, str]:
    if isinstance(err, (ConnectionResetError, ConnectionRefusedError)):
        return ("FAILED", "Connection closed or refused while sending mock sensitive data.")
    if isinstance(err, (socket.timeout, TimeoutError)):
        return ("UNDETERMINED", "No response while sending mock sensitive data.")
    return ("UNDETERMINED", f"Error while sending mock sensitive data: {err}")


def obfuscate_payload(payload: bytes) -> tuple[bytes, str]:
    encoded = base64.b64encode(payload)
    return encoded, "Base64-encoded mock payload"


DNS_QTYPE_CODES = {"A": 1, "AAAA": 28, "TXT": 16}


def _sanitize_label(text: str) -> str:
    cleaned = []
    for ch in text:
        if ch.isalnum() or ch == "-":
            cleaned.append(ch.lower())
        else:
            cleaned.append("-")
    label = "".join(cleaned).strip("-") or "test"
    return label[:63]


def _psk_label(psk: str) -> str:
    encoded = base64.b32encode(psk.encode("utf-8")).decode("ascii").rstrip("=")
    encoded = encoded.lower() or "0"
    return f"psk-{encoded}"


def _build_dns_qname(base_qname: str, test_id: str, psk: str) -> str:
    base_qname = ".".join(part for part in base_qname.strip(".").split(".") if part)
    parts = [_sanitize_label(test_id), _psk_label(psk)]
    if base_qname:
        parts.append(base_qname)
    return ".".join(parts)


def _encode_dns_name(name: str) -> bytes:
    out = bytearray()
    for label in name.split("."):
        lb = label.encode("utf-8")
        out.append(len(lb))
        out.extend(lb)
    out.append(0)
    return bytes(out)


def _build_dns_query(test_id: str, psk: str, qname: str, qtype: str) -> tuple[int, bytes, int]:
    dns_qname = _build_dns_qname(qname, test_id, psk)
    qtype_code = DNS_QTYPE_CODES.get(qtype.upper(), 1)
    query_id = random.randint(0, 0xFFFF)
    header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    question = _encode_dns_name(dns_qname) + struct.pack("!HH", qtype_code, 1)
    return query_id, header + question, qtype_code


def _parse_dns_response(data: bytes, expected_id: int) -> tuple[str, str]:
    if len(data) < 12:
        return ("ERROR", "DNS response too short.")
    rid, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
    if rid != expected_id:
        return ("ERROR", "DNS response ID mismatch.")
    rcode = flags & 0xF
    if rcode != 0:
        if rcode == 5:
            return ("FAILED", "DNS server refused the query.")
        if rcode == 3:
            return ("FAILED", "DNS server returned NXDOMAIN.")
        return ("FAILED", f"DNS server error (rcode={rcode}).")
    if ancount == 0:
        return ("UNDETERMINED", "DNS server returned no answers.")
    return ("SUCCESS", "Received DNS answer.")


# -------------------------
# Host / network info (best-effort)
# -------------------------

def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().isoformat(timespec="seconds")


def _timestamp_for_filename() -> str:
    # local time
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def collect_local_ips_best_effort() -> list[str]:
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


def run_command_capture(cmd: list[str], timeout: int = 5) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")
        return out.strip()
    except Exception as e:
        return f"Command failed: {cmd} ({type(e).__name__}: {e})"


def collect_network_diagnostics() -> dict[str, str]:
    """
    Capture a small set of platform-specific network command outputs.
    Keep it best-effort and bounded.
    """
    info: dict[str, str] = {}
    if os.name == "nt":
        info["ipconfig_all"] = run_command_capture(["ipconfig", "/all"], timeout=8)
        info["route_print"] = run_command_capture(["route", "print"], timeout=8)
        info["netsh_fw_profiles"] = run_command_capture(["netsh", "advfirewall", "show", "allprofiles"], timeout=8)
    else:
        # Try iproute2 first, fallback to ifconfig/route
        info["ip_addr"] = run_command_capture(["sh", "-lc", "ip addr || ifconfig -a"], timeout=8)
        info["ip_route"] = run_command_capture(["sh", "-lc", "ip route || route -n"], timeout=8)
    return info


def summarize_client_env(include_cmd_output: bool) -> dict[str, Any]:
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
        "redacted": False,
    }

    if include_cmd_output:
        env["net_commands"] = collect_network_diagnostics()
    else:
        env["net_commands"] = {}

    return env


def redact_client_env(env: dict[str, Any]) -> dict[str, Any]:
    scrubbed = dict(env)
    scrubbed["hostname"] = "(redacted)"
    scrubbed["fqdn"] = "(redacted)"
    scrubbed["local_ips"] = []
    scrubbed["user"] = "(redacted)"
    scrubbed["net_commands"] = {}
    scrubbed["redacted"] = True
    return scrubbed


# -------------------------
# Outcome / inference helpers
# -------------------------

def classify_tcp_exception(e: BaseException) -> tuple[str, str]:
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


def classify_http(status_code: int) -> tuple[str, str]:
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


def _tcp_send_sensitive_payload(t: TcpTest, timeout_s: float, psk: str, payload: bytes, suffix: str) -> dict[str, Any]:
    meta = {"test_id": f"{suffix}", "bytes": len(payload), "psk": psk, "mock_sensitive": True}
    header = (json.dumps(meta) + "\n").encode("utf-8")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout_s)
        s.connect((t.host, t.port))
        s.sendall(header)
        s.sendall(payload)
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
            if len(buf) > 65536:
                break
        s.close()
        return sensitive_info(True, "SUCCESS", "Mock sensitive payload transmitted successfully.")
    except Exception as exc:
        status, detail = classify_sensitive_error(exc)
        return sensitive_info(True, status, detail)


def run_tcp_sensitive_probe(t: TcpTest, test_id: str, timeout_s: float, psk: str) -> dict[str, Any]:
    base_payload = mock_sensitive_payload()
    result = _tcp_send_sensitive_payload(t, timeout_s, psk, base_payload, f"{test_id}-mock")
    result["obfuscated_status"] = "NOT_RUN"
    result["obfuscated_detail"] = ""
    if result["status"] != "SUCCESS":
        obf_payload, desc = obfuscate_payload(base_payload)
        obf = _tcp_send_sensitive_payload(t, timeout_s, psk, obf_payload, f"{test_id}-mock-obf")
        result["obfuscated_status"] = obf["status"]
        result["obfuscated_detail"] = f"{desc}: {obf.get('detail', '')}"
        if obf["status"] == "SUCCESS":
            result["detail"] += " Obfuscated attempt succeeded."
        else:
            result["detail"] += f" Obfuscated attempt result: {obf['status']}."
    return result


def run_udp_sensitive_probe(u: UdpTest, test_id: str, timeout_s: float, psk: str) -> dict[str, Any]:
    base_payload = mock_sensitive_payload()
    result = _udp_send_sensitive_payload(u, test_id, timeout_s, psk, base_payload, "mock")
    result["obfuscated_status"] = "NOT_RUN"
    result["obfuscated_detail"] = ""
    if result["status"] != "SUCCESS":
        obf_payload, desc = obfuscate_payload(base_payload)
        obf = _udp_send_sensitive_payload(u, test_id, timeout_s, psk, obf_payload, "mock-obf")
        result["obfuscated_status"] = obf["status"]
        result["obfuscated_detail"] = f"{desc}: {obf.get('detail', '')}"
        if obf["status"] == "SUCCESS":
            result["detail"] += " Obfuscated attempt succeeded."
        else:
            result["detail"] += f" Obfuscated attempt result: {obf['status']}."
    return result


def run_http_sensitive_probe(h: HttpTest, timeout_s: float, psk: str) -> dict[str, Any]:
    base_payload = mock_sensitive_payload()
    result = _http_send_sensitive_payload(h, timeout_s, psk, base_payload, "mock-sensitive")
    result["obfuscated_status"] = "NOT_RUN"
    result["obfuscated_detail"] = ""
    if result["status"] != "SUCCESS":
        obf_payload, desc = obfuscate_payload(base_payload)
        obf = _http_send_sensitive_payload(h, timeout_s, psk, obf_payload, "mock-sensitive-obf")
        result["obfuscated_status"] = obf["status"]
        result["obfuscated_detail"] = f"{desc}: {obf.get('detail', '')}"
        if obf["status"] == "SUCCESS":
            result["detail"] += " Obfuscated attempt succeeded."
        else:
            result["detail"] += f" Obfuscated attempt result: {obf['status']}."
    download = run_http_sensitive_download(h, timeout_s, psk)
    result["download_status"] = download["status"]
    result["download_detail"] = download["detail"]
    return result


def _udp_send_sensitive_payload(u: UdpTest, test_id: str, timeout_s: float, psk: str,
                                payload: bytes, suffix: str) -> dict[str, Any]:
    addr = (u.host, u.port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout_s)
    seq_fmt = "!Q"
    try:
        hello_obj = {"test_id": f"{test_id}-{suffix}", "psk": psk, "udp_mode": u.udp_mode, "ack_every": u.ack_every}
        sock.sendto(b"HELLO " + json.dumps(hello_obj).encode("utf-8"), addr)
        try:
            data, _ = sock.recvfrom(2048)
        except socket.timeout:
            return sensitive_info(True, "FAILED", "Server did not acknowledge HELLO for mock sensitive data.")
        if not data.startswith(b"HELLO_ACK"):
            return sensitive_info(True, "FAILED", "Server did not acknowledge HELLO for mock sensitive data.")
        packets = 3
        acked = 0
        for i in range(packets):
            seq = i + 1
            pkt = b"DATA " + struct.pack(seq_fmt, seq) + payload
            sock.sendto(pkt, addr)
            if u.udp_mode == "firehose":
                continue
            try:
                data, _ = sock.recvfrom(2048)
            except socket.timeout:
                continue
            if data.startswith(b"ACK ") or data.startswith(b"ACKR"):
                acked += 1
        if u.udp_mode == "firehose" or acked > 0:
            return sensitive_info(True, "SUCCESS", "Mock sensitive UDP payload transmitted.")
        return sensitive_info(True, "UNDETERMINED", "No UDP ACKs observed for mock sensitive payload.")
    except Exception as exc:
        status, detail = classify_sensitive_error(exc)
        return sensitive_info(True, status, detail)
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _http_send_sensitive_payload(h: HttpTest, timeout_s: float, psk: str,
                                 payload: bytes, suffix: str) -> dict[str, Any]:
    meta = {"Content-Type": "application/octet-stream", "X-Test-Id": suffix, "X-PSK": psk}
    req = urllib.request.Request(h.url, data=payload, method="POST", headers=meta)
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            if 200 <= resp.status <= 299:
                return sensitive_info(True, "SUCCESS", "Mock sensitive payload accepted by server.")
            if resp.status in (401, 403):
                return sensitive_info(True, "FAILED", f"Server rejected mock data (HTTP {resp.status}).")
            return sensitive_info(True, "UNDETERMINED", f"Unexpected HTTP status {resp.status}.")
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            return sensitive_info(True, "FAILED", f"Server rejected mock data (HTTP {exc.code}).")
        return sensitive_info(True, "UNDETERMINED", f"HTTP error while sending mock data (HTTP {exc.code}).")
    except Exception as exc:
        status, detail = classify_sensitive_error(exc)
        return sensitive_info(True, status, detail)


def _download_url(url: str) -> str:
    parsed = urlparse(url)
    path = "/download"
    new = parsed._replace(path=path, query="", fragment="")
    return urlunparse(new)


def run_http_sensitive_download(h: HttpTest, timeout_s: float, psk: str) -> dict[str, Any]:
    url = _download_url(h.url)
    req = urllib.request.Request(url, method="GET", headers={"X-PSK": psk})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            body = resp.read()
            if 200 <= resp.status <= 299:
                snippet = body.decode("utf-8", errors="ignore")[:60]
                return {"status": "SUCCESS", "detail": f"Downloaded mock data: {snippet}..."}
            return {"status": "FAILED", "detail": f"HTTP {resp.status} on download."}
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            return {"status": "FAILED", "detail": f"Server rejected download (HTTP {exc.code})."}
        return {"status": "UNDETERMINED", "detail": f"HTTP error during download (HTTP {exc.code})."}
    except Exception as exc:
        status, detail = classify_sensitive_error(exc)
        return {"status": status, "detail": detail}


# -------------------------
# TCP test
# -------------------------

def tcp_test(t: TcpTest, test_id: str, timeout_s: float, psk: str,
             stop_event: threading.Event, show_progress: bool,
             mock_sensitive: bool) -> dict[str, Any]:
    started = _now_iso()
    t0 = time.time()

    payload = rand_bytes(t.bytes)
    meta = {"test_id": test_id, "bytes": t.bytes, "psk": psk}
    header = (json.dumps(meta) + "\n").encode("utf-8")

    result: dict[str, Any] = {
        "type": "tcp",
        "host": t.host,
        "port": t.port,
        "bytes_planned": t.bytes,
        "started": started,
        "client_timeout_s": timeout_s,
    }
    sensitive_result = (
        sensitive_info(True, "NOT_RUN", "Pending base check.")
        if mock_sensitive else sensitive_info(False, "DISABLED")
    )

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

        auth_error = (
            isinstance(server_resp, dict)
            and server_resp.get("ok") is False
            and "PSK" in str(server_resp.get("error", ""))
        )
        if auth_error:
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
        if mock_sensitive and status == "SUCCESS":
            sensitive_result = run_tcp_sensitive_probe(t, test_id, timeout_s, psk)
        elif mock_sensitive:
            sensitive_result = sensitive_info(True, "NOT_ATTEMPTED", "Base TCP test unsuccessful.")
        result["mock_sensitive"] = sensitive_result
        return result

    except KeyboardInterrupt as e:
        elapsed = max(1e-6, time.time() - t0)
        if mock_sensitive:
            sensitive_result = sensitive_info(True, "NOT_ATTEMPTED", "SMTP test aborted before mock attempt.")
        result.update({
            "status": "ABORTED",
            "inference": "User requested quit (Q) during test",
            "client_elapsed_s": elapsed,
            "error_type": "KeyboardInterrupt",
            "error": str(e),
        })
        result["mock_sensitive"] = sensitive_result
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
        if isinstance(e, (socket.timeout, TimeoutError)):
            result["failure_detail"] = f"No response before client timeout ({timeout_s}s)."
        if mock_sensitive:
            sensitive_result = sensitive_info(True, "NOT_ATTEMPTED", "Base TCP test errored.")
        result["mock_sensitive"] = sensitive_result
        return result

    finally:
        if show_progress:
            end_progress_line()


# -------------------------
# UDP test (3 modes)
# -------------------------

def _udp_send_hello(sock: socket.socket, addr: tuple[str, int], test_id: str, psk: str,
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
             stop_event: threading.Event, show_progress: bool,
             mock_sensitive: bool) -> dict[str, Any]:
    started = _now_iso()
    t0 = time.time()

    result: dict[str, Any] = {
        "type": "udp",
        "host": u.host,
        "port": u.port,
        "payload_size": u.payload_size,
        "packets_planned": u.packets,
        "udp_mode": u.udp_mode,
        "ack_every": u.ack_every,
        "batch_size": u.batch_size,
        "started": started,
        "client_timeout_s": timeout_s,
    }
    sensitive_result = (
        sensitive_info(True, "NOT_RUN", "Pending base check.")
        if mock_sensitive else sensitive_info(False, "DISABLED")
    )

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
                inf = "No HELLO_ACK; UDP may be blocked/dropped or server not reachable."
                status, inf = ("BLOCKED_OR_DROPPED", inf)

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
        if status != "SUCCESS":
            hints = []
            if not hello_acked:
                hints.append("Server did not acknowledge HELLO — listener unreachable or UDP blocked.")
            if had_icmp_error:
                hints.append("ICMP unreachable received (host/port filtered).")
            if not hints:
                hints.append(f"No UDP responses observed before client timeout ({timeout_s}s).")
            result["failure_detail"] = " ".join(hints)
        if mock_sensitive and status == "SUCCESS":
            sensitive_result = run_udp_sensitive_probe(u, test_id, timeout_s, psk)
        elif mock_sensitive:
            sensitive_result = sensitive_info(True, "NOT_ATTEMPTED", "Base UDP test unsuccessful.")
        result["mock_sensitive"] = sensitive_result
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
                inf = (
                    "No UDP responses — server may not be listening, host firewall rejected, "
                    "or a network ACL dropped the traffic"
                )
                status, inf = ("BLOCKED_OR_DROPPED", inf)

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
        if status != "SUCCESS":
            hints = []
            if not hello_acked:
                hints.append("Server did not acknowledge HELLO — listener unreachable or UDP blocked.")
            if had_icmp_error:
                hints.append("ICMP unreachable received (host/port filtered).")
            if acked == 0 and hello_acked:
                hints.append("HELLO succeeded but no DATA ACKs arrived.")
            if not hints:
                hints.append(f"No UDP responses observed before client timeout ({timeout_s}s).")
            result["failure_detail"] = " ".join(hints)
        if mock_sensitive and status == "SUCCESS":
            sensitive_result = run_udp_sensitive_probe(u, test_id, timeout_s, psk)
        elif mock_sensitive:
            sensitive_result = sensitive_info(True, "NOT_ATTEMPTED", "Base UDP test unsuccessful.")
        result["mock_sensitive"] = sensitive_result
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
        result["mock_sensitive"] = sensitive_result
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
        if isinstance(e, (socket.timeout, TimeoutError)):
            result["failure_detail"] = f"No UDP activity before client timeout ({timeout_s}s)."
        if mock_sensitive:
            sensitive_result = sensitive_info(True, "NOT_ATTEMPTED", "Base UDP test errored.")
        result["mock_sensitive"] = sensitive_result
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
              stop_event: threading.Event, show_progress: bool,
              mock_sensitive: bool) -> dict[str, Any]:
    started = _now_iso()
    t0 = time.time()

    result: dict[str, Any] = {
        "type": "http",
        "url": h.url,
        "bytes_planned": h.bytes,
        "started": started,
        "client_timeout_s": timeout_s,
    }
    sensitive_result = (
        sensitive_info(True, "NOT_RUN", "Pending base check.")
        if mock_sensitive else sensitive_info(False, "DISABLED")
    )

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
        if mock_sensitive and st == "SUCCESS":
            sensitive_result = run_http_sensitive_probe(h, timeout_s, psk)
        elif mock_sensitive:
            sensitive_result = sensitive_info(True, "NOT_ATTEMPTED", "Base HTTP test unsuccessful.")
        result["mock_sensitive"] = sensitive_result
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
        result["mock_sensitive"] = sensitive_result
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
        if mock_sensitive:
            sensitive_result = sensitive_info(True, "NOT_ATTEMPTED", "HTTP error before mock test.")
        result["mock_sensitive"] = sensitive_result
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
        if isinstance(reason, (socket.timeout, TimeoutError)):
            result["failure_detail"] = f"No HTTP response before client timeout ({timeout_s}s)."
        if mock_sensitive:
            sensitive_result = sensitive_info(True, "NOT_ATTEMPTED", "HTTP connection failed before mock test.")
        result["mock_sensitive"] = sensitive_result
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
        if isinstance(e, (socket.timeout, TimeoutError)):
            result["failure_detail"] = f"No HTTP response before client timeout ({timeout_s}s)."
        if mock_sensitive:
            sensitive_result = sensitive_info(True, "NOT_ATTEMPTED", "HTTP test errored before mock test.")
        result["mock_sensitive"] = sensitive_result
        return result

    finally:
        if show_progress:
            end_progress_line()


# -------------------------
# DNS test + sensitive payload helper
# -------------------------

def _dns_payload_chunks(text: str, limit: int = 5) -> list[str]:
    chunks: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        sanitized = _sanitize_label(line)
        if not sanitized:
            continue
        for i in range(0, len(sanitized), 40):
            chunks.append(sanitized[i:i + 40])
            if len(chunks) >= limit:
                return chunks
    if not chunks:
        chunks.append("mock-data")
    return chunks


def _dns_send_chunks(d: DnsTest, test_id: str, timeout_s: float, psk: str,
                     chunks: list[str], label: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout_s)
    try:
        for idx, chunk in enumerate(chunks):
            qname = f"{chunk}.{d.qname}".strip(".")
            query_id, packet, _ = _build_dns_query(f"{test_id}-{label}-{idx}", psk, qname, d.qtype.upper())
            sock.sendto(packet, (d.host, d.port))
            data, _ = sock.recvfrom(1024)
            status, inf = _parse_dns_response(data, query_id)
            if status != "SUCCESS":
                raise RuntimeError(f"DNS response indicated {status}: {inf}")
    finally:
        try:
            sock.close()
        except Exception:
            pass


def run_dns_sensitive_probe(d: DnsTest, test_id: str, timeout_s: float, psk: str) -> dict[str, Any]:
    payload = mock_sensitive_payload().decode("utf-8", errors="ignore")
    result = sensitive_info(True, "NOT_RUN", "Pending base check.")
    result["obfuscated_status"] = "NOT_RUN"
    result["obfuscated_detail"] = ""
    chunks = _dns_payload_chunks(payload)
    try:
        _dns_send_chunks(d, test_id, timeout_s, psk, chunks, "mock")
        result.update({
            "status": "SUCCESS",
            "detail": "DNS queries embedding mock sensitive labels were answered.",
        })
    except Exception as exc:
        if isinstance(exc, (socket.timeout, TimeoutError)):
            status = "FAILED"
            detail = "DNS queries carrying mock data timed out."
        else:
            status = "UNDETERMINED"
            detail = f"DNS mock data query failed: {exc}"
        result.update({"status": status, "detail": detail})

    if result["status"] != "SUCCESS":
        obf_payload, desc = obfuscate_payload(mock_sensitive_payload())
        obf_text = obf_payload.decode("ascii", errors="ignore")
        obf_chunks = _dns_payload_chunks(obf_text)
        try:
            _dns_send_chunks(d, test_id, timeout_s, psk, obf_chunks, "mock-obf")
            result["obfuscated_status"] = "SUCCESS"
            result["obfuscated_detail"] = f"{desc} transmitted via DNS labels."
        except Exception as exc:
            if isinstance(exc, (socket.timeout, TimeoutError)):
                status = "FAILED"
                detail = "Obfuscated DNS queries timed out."
            else:
                status = "UNDETERMINED"
                detail = f"Obfuscated DNS queries failed: {exc}"
            result["obfuscated_status"] = status
            result["obfuscated_detail"] = detail
    return result


def dns_test(d: DnsTest, test_id: str, timeout_s: float, psk: str,
             stop_event: threading.Event, show_progress: bool,
             mock_sensitive: bool) -> dict[str, Any]:
    started = _now_iso()
    t0 = time.time()

    sensitive_result = (
        sensitive_info(True, "NOT_RUN", "Pending base check.")
        if mock_sensitive else sensitive_info(False, "DISABLED", "Mock sensitive testing disabled.")
    )

    result: dict[str, Any] = {
        "type": "dns",
        "host": d.host,
        "port": d.port,
        "qname": d.qname,
        "qtype": d.qtype.upper(),
        "started": started,
        "client_timeout_s": timeout_s,
    }

    try:
        if stop_event.is_set():
            raise KeyboardInterrupt("Aborted by user")

        query_id, packet, _qtype_code = _build_dns_query(test_id, psk, d.qname, d.qtype.upper())
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout_s)
        sock.sendto(packet, (d.host, d.port))

        if show_progress:
            print_progress_line(f"DNS {d.host}:{d.port} querying {d.qname} ({d.qtype.upper()})")

        data, _ = sock.recvfrom(1024)
        sock.close()

        status, inf = _parse_dns_response(data, query_id)
        elapsed = max(1e-6, time.time() - t0)
        result.update({
            "status": status if status in ("SUCCESS",) else ("FAILED" if status == "FAILED" else status),
            "inference": inf,
            "client_elapsed_s": elapsed,
        })
        if status != "SUCCESS":
            result["failure_detail"] = inf
            if mock_sensitive:
                sensitive_result = sensitive_info(True, "NOT_ATTEMPTED", "Base DNS test unsuccessful.")
        else:
            if mock_sensitive:
                sensitive_result = run_dns_sensitive_probe(d, test_id, timeout_s, psk)
        result["mock_sensitive"] = sensitive_result
        return result

    except KeyboardInterrupt as e:
        elapsed = max(1e-6, time.time() - t0)
        result.update({
            "status": "ABORTED",
            "inference": "User requested quit (Q) during DNS test",
            "client_elapsed_s": elapsed,
            "error_type": "KeyboardInterrupt",
            "error": str(e),
        })
        result["mock_sensitive"] = sensitive_result
        return result

    except Exception as e:
        elapsed = max(1e-6, time.time() - t0)
        detail = str(e)
        if isinstance(e, (socket.timeout, TimeoutError)):
            status = "BLOCKED_OR_DROPPED"
            inf = "DNS response timeout — likely network ACL/firewall drop."
        elif isinstance(e, socket.gaierror):
            status = "NAME_RESOLUTION_FAILED"
            inf = "Client DNS resolution failed."
        else:
            status = "ERROR"
            inf = "DNS query errored (client-side exception)."
        result.update({
            "status": status,
            "inference": inf,
            "client_elapsed_s": elapsed,
            "error_type": type(e).__name__,
            "error": detail,
        })
        if status == "BLOCKED_OR_DROPPED":
            result["failure_detail"] = f"No DNS response before client timeout ({timeout_s}s)."
        if mock_sensitive:
            sensitive_result = sensitive_info(True, "NOT_ATTEMPTED", "DNS query errored before mock test.")
        result["mock_sensitive"] = sensitive_result
        return result

    finally:
        if show_progress:
            end_progress_line()


# -------------------------
# Telnet test
# -------------------------

class TelnetDialogueError(Exception):
    def __init__(self, message: str, capture: str = "") -> None:
        super().__init__(message)
        self.capture = capture


class TelnetAuthError(Exception):
    pass


def _telnet_read_until_prompt(fh: Any, marker: bytes, limit: int = 16384) -> bytes:
    buf = bytearray()
    while len(buf) < limit:
        chunk = fh.read(1)
        if not chunk:
            break
        buf.extend(chunk)
        if buf.endswith(marker):
            break
    return bytes(buf)


def _telnet_send_data_lines(send_command: Callable[[str], str], prefix: str, lines: list[str]) -> None:
    for line in lines:
        text = line.strip()
        if not text:
            continue
        send_command(f"{prefix}{text}")


def run_telnet_sensitive_probe(send_command: Callable[[str], str]) -> dict[str, Any]:
    payload = mock_sensitive_payload().decode("utf-8", errors="ignore")
    lines = [ln for ln in payload.splitlines() if ln.strip()]
    if not lines:
        lines = ["mock-data"]
    result = sensitive_info(True, "NOT_RUN", "Pending base check.")
    result["obfuscated_status"] = "NOT_RUN"
    result["obfuscated_detail"] = ""
    try:
        _telnet_send_data_lines(send_command, "DATA ", lines[:8])
        result.update({
            "status": "SUCCESS",
            "detail": "Telnet session echoed mock sensitive lines.",
        })
    except Exception as exc:
        status, detail = classify_sensitive_error(exc)
        result.update({"status": status, "detail": detail})

    if result["status"] != "SUCCESS":
        obf_payload, desc = obfuscate_payload(mock_sensitive_payload())
        obf_text = obf_payload.decode("ascii", errors="ignore")
        obf_lines = [obf_text[i:i + 60] for i in range(0, len(obf_text), 60)]
        try:
            _telnet_send_data_lines(send_command, "OBF ", obf_lines[:8])
            result["obfuscated_status"] = "SUCCESS"
            result["obfuscated_detail"] = f"{desc}: echoed via Telnet."
        except Exception as exc:
            status, detail = classify_sensitive_error(exc)
            result["obfuscated_status"] = status
            result["obfuscated_detail"] = detail
    return result


def telnet_test(t: TelnetTest, test_id: str, timeout_s: float, psk: str,
                stop_event: threading.Event, show_progress: bool,
                mock_sensitive: bool) -> dict[str, Any]:
    started = _now_iso()
    t0 = time.time()
    transcript: list[str] = []
    responses: list[str] = []
    sock: socket.socket | None = None
    fh: Any | None = None

    sensitive_result = (
        sensitive_info(True, "NOT_RUN", "Pending base check.")
        if mock_sensitive else sensitive_info(False, "DISABLED", "Mock sensitive testing disabled.")
    )

    result: dict[str, Any] = {
        "type": "telnet",
        "host": t.host,
        "port": t.port,
        "username": t.username,
        "commands_planned": len(t.commands),
        "started": started,
        "client_timeout_s": timeout_s,
    }

    def expect_prompt(fh: Any, marker: bytes, label: str) -> str:
        data = _telnet_read_until_prompt(fh, marker)
        decoded = data.decode("utf-8", errors="replace")
        transcript.append(f"S> {decoded}")
        if not data.endswith(marker):
            if "Authentication failed" in decoded:
                raise TelnetAuthError(decoded.strip())
            raise TelnetDialogueError(f"Missing {label} prompt", decoded)
        return decoded

    def send_line(sock: socket.socket, text: str) -> None:
        msg = text + "\r\n"
        sock.sendall(msg.encode("utf-8", errors="ignore"))
        transcript.append(f"C> {text}")

    def send_command(command: str) -> str:
        if stop_event.is_set():
            raise KeyboardInterrupt("Aborted by user")
        send_line(sock, command)  # type: ignore[arg-type]
        resp = _telnet_read_until_prompt(fh, b"> ")  # type: ignore[arg-type]
        decoded = resp.decode("utf-8", errors="replace")
        transcript.append(f"S> {decoded}")
        if not resp.endswith(b"> "):
            raise TelnetDialogueError("Prompt missing after command", decoded)
        responses.append(decoded.strip())
        return decoded

    try:
        if stop_event.is_set():
            raise KeyboardInterrupt("Aborted by user")

        sock = socket.create_connection((t.host, t.port), timeout_s)
        sock.settimeout(timeout_s)
        fh = sock.makefile("rb")

        expect_prompt(fh, b"login: ", "login")
        send_line(sock, t.username)
        expect_prompt(fh, b"Password: ", "password")
        send_line(sock, t.password)
        expect_prompt(fh, b"PSK: ", "PSK")
        send_line(sock, psk)
        expect_prompt(fh, b"> ", "shell prompt")

        for idx, command in enumerate(t.commands):
            if show_progress:
                print_progress_line(progress_bar(f"TELNET {t.host}:{t.port}", idx + 1, len(t.commands)))
            send_command(command)

        if mock_sensitive:
            sensitive_result = run_telnet_sensitive_probe(send_command)

        send_line(sock, "EXIT")
        if fh:
            try:
                closing = fh.readline(4096)
                if closing:
                    transcript.append(f"S> {closing.decode('utf-8', errors='replace')}")
            except Exception:
                pass

        elapsed = max(1e-6, time.time() - t0)
        result.update({
            "status": "SUCCESS",
            "inference": f"Telnet emulation authenticated and ran {len(t.commands)} commands.",
            "client_elapsed_s": elapsed,
            "dialogue": transcript,
            "responses": responses,
            "mock_sensitive": sensitive_result,
        })
        return result

    except KeyboardInterrupt as e:
        elapsed = max(1e-6, time.time() - t0)
        if mock_sensitive:
            sensitive_result = sensitive_info(True, "NOT_ATTEMPTED", "Telnet test aborted before mock attempt.")
        result.update({
            "status": "ABORTED",
            "inference": "User requested quit (Q) during Telnet test",
            "client_elapsed_s": elapsed,
            "error_type": type(e).__name__,
            "error": str(e),
            "dialogue": transcript,
            "responses": responses,
            "mock_sensitive": sensitive_result,
        })
        return result

    except TelnetAuthError as e:
        elapsed = max(1e-6, time.time() - t0)
        if mock_sensitive:
            sensitive_result = sensitive_info(True, "NOT_ATTEMPTED", "Telnet authentication failed before mock test.")
        result.update({
            "status": "AUTH_FAILED",
            "inference": "Telnet PSK authentication failed.",
            "client_elapsed_s": elapsed,
            "error_type": type(e).__name__,
            "error": str(e),
            "failure_detail": e.args[0] if e.args else "",
            "dialogue": transcript,
            "responses": responses,
            "mock_sensitive": sensitive_result,
        })
        return result

    except TelnetDialogueError as e:
        elapsed = max(1e-6, time.time() - t0)
        detail = e.capture or ""
        if mock_sensitive:
            sensitive_result = sensitive_info(True, "NOT_ATTEMPTED", "Telnet dialogue failed before mock test.")
        result.update({
            "status": "ERROR",
            "inference": "Telnet dialogue failed (unexpected prompt sequence).",
            "client_elapsed_s": elapsed,
            "error_type": type(e).__name__,
            "error": str(e),
            "failure_detail": detail or str(e),
            "dialogue": transcript,
            "responses": responses,
            "mock_sensitive": sensitive_result,
        })
        return result

    except (socket.timeout, OSError, ConnectionRefusedError, ConnectionResetError) as e:
        elapsed = max(1e-6, time.time() - t0)
        status, inf = classify_tcp_exception(e)
        if isinstance(e, socket.timeout):
            detail_hint = f"No Telnet response before timeout ({timeout_s}s)."
        else:
            detail_hint = ""
        if mock_sensitive:
            sensitive_result = sensitive_info(True, "NOT_ATTEMPTED", "Telnet connection failed before mock test.")
        result.update({
            "status": status,
            "inference": inf,
            "client_elapsed_s": elapsed,
            "error_type": type(e).__name__,
            "error": str(e),
            "failure_detail": detail_hint,
            "dialogue": transcript,
            "responses": responses,
            "mock_sensitive": sensitive_result,
        })
        return result

    except Exception as e:
        elapsed = max(1e-6, time.time() - t0)
        if mock_sensitive:
            sensitive_result = sensitive_info(True, "NOT_ATTEMPTED", "Telnet error before mock test.")
        result.update({
            "status": "ERROR",
            "inference": "Telnet test errored (client-side exception).",
            "client_elapsed_s": elapsed,
            "error_type": type(e).__name__,
            "error": str(e),
            "dialogue": transcript,
            "responses": responses,
            "mock_sensitive": sensitive_result,
        })
        return result

    finally:
        if show_progress:
            end_progress_line()
        if fh:
            try:
                fh.close()
            except Exception:
                pass
        if sock:
            try:
                sock.close()
            except Exception:
                pass


# -------------------------
# SMTP test
# -------------------------

class SMTPDialogueError(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(f"SMTP {code}: {message}")
        self.code = code
        self.message = message


def _smtp_send_message(send: Callable[[str], None], read_response: Callable[[Any, set[int]], list[str]],
                       sock: socket.socket, fh: Any, transcript: list[str], s: SmtpTest,
                       subject_suffix: str, body: str, label: str) -> None:
    send(f"MAIL FROM:<{s.mail_from}>")
    read_response(fh, {250})
    send(f"RCPT TO:<{s.rcpt_to}>")
    read_response(fh, {250})
    send("DATA")
    read_response(fh, {354})
    message_lines = [
        f"Subject: {s.subject}{subject_suffix}",
        f"X-Exfiliator-Label: {label}",
        "",
        body,
        "",
        f"--exfiliator {label}",
    ]
    payload = "\r\n".join(message_lines) + "\r\n.\r\n"
    sock.sendall(payload.encode("utf-8", errors="ignore"))
    transcript.append("C> [DATA payload]")
    read_response(fh, {250})


def run_smtp_sensitive_probe(send: Callable[[str], None], read_response: Callable[[Any, set[int]], list[str]],
                             sock: socket.socket, fh: Any, transcript: list[str],
                             s: SmtpTest, test_id: str) -> dict[str, Any]:
    payload = mock_sensitive_payload().decode("utf-8", errors="ignore")
    result = sensitive_info(True, "NOT_RUN", "Pending base check.")
    result["obfuscated_status"] = "NOT_RUN"
    result["obfuscated_detail"] = ""
    try:
        _smtp_send_message(send, read_response, sock, fh, transcript, s, " [Mock Sensitive]",
                           payload, f"{test_id}-mock")
        result.update({
            "status": "SUCCESS",
            "detail": "SMTP server accepted mock sensitive message.",
        })
    except SMTPDialogueError as exc:
        status, detail = ("FAILED", f"SMTP dialogue failed: {exc.message}")
        result.update({"status": status, "detail": detail})
    except Exception as exc:
        status, detail = classify_sensitive_error(exc)
        result.update({"status": status, "detail": detail})

    if result["status"] != "SUCCESS":
        obf_payload, desc = obfuscate_payload(mock_sensitive_payload())
        obf_text = obf_payload.decode("ascii", errors="ignore")
        try:
            _smtp_send_message(send, read_response, sock, fh, transcript, s, " [Mock Sensitive OBF]",
                               obf_text, f"{test_id}-mock-obf")
            result["obfuscated_status"] = "SUCCESS"
            result["obfuscated_detail"] = f"{desc}: SMTP server accepted obfuscated data."
        except SMTPDialogueError as exc:
            result["obfuscated_status"] = "FAILED"
            result["obfuscated_detail"] = f"SMTP dialogue failed: {exc.message}"
        except Exception as exc:
            status, detail = classify_sensitive_error(exc)
            result["obfuscated_status"] = status
            result["obfuscated_detail"] = detail
    return result


def smtp_test(s: SmtpTest, test_id: str, timeout_s: float, psk: str,
              stop_event: threading.Event, show_progress: bool,
              mock_sensitive: bool) -> dict[str, Any]:
    started = _now_iso()
    t0 = time.time()
    transcript: list[str] = []
    sock: socket.socket | None = None
    fh: Any | None = None

    result: dict[str, Any] = {
        "type": "smtp",
        "host": s.host,
        "port": s.port,
        "mail_from": s.mail_from,
        "rcpt_to": s.rcpt_to,
        "subject": s.subject,
        "started": started,
        "client_timeout_s": timeout_s,
    }

    sensitive_result = (
        sensitive_info(True, "NOT_RUN", "Pending base check.")
        if mock_sensitive else sensitive_info(False, "DISABLED", "Mock sensitive testing disabled.")
    )

    def send(sock: socket.socket, line: str) -> None:
        sock.sendall((line + "\r\n").encode("utf-8", errors="ignore"))
        transcript.append(f"C> {line}")

    def read_response(fh: Any, expected: set[int]) -> list[str]:
        lines: list[str] = []
        while True:
            raw = fh.readline(4096)
            if not raw:
                raise SMTPDialogueError(-1, "Server closed connection")
            decoded = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            lines.append(decoded)
            if len(decoded) >= 4 and decoded[3] == "-":
                continue
            try:
                code = int(decoded[:3])
            except Exception as exc:
                raise SMTPDialogueError(-1, decoded) from exc
            if code not in expected:
                raise SMTPDialogueError(code, decoded)
            break
        for line in lines:
            transcript.append(f"S> {line}")
        return lines

    def classify_smtp(code: int, message: str) -> tuple[str, str]:
        if code == 535:
            return ("AUTH_FAILED", "SMTP PSK authentication failed.")
        if 500 <= code <= 599:
            return ("SERVER_ERROR", f"SMTP server rejected the request ({code}).")
        if 400 <= code <= 499:
            return ("SERVER_TEMPFAIL", f"SMTP temporary failure ({code}).")
        return ("ERROR", message or "SMTP dialogue failed.")

    try:
        if stop_event.is_set():
            raise KeyboardInterrupt("Aborted by user")

        sock = socket.create_connection((s.host, s.port), timeout_s)
        sock.settimeout(timeout_s)
        fh = sock.makefile("rb")

        read_response(fh, {220})
        if show_progress:
            print_progress_line(f"SMTP {s.host}:{s.port} delivering payload...")
        hostname = socket.gethostname() or "exfiliator-client"
        send(sock, f"EHLO {hostname}")
        read_response(fh, {250})
        send(sock, f"AUTH PSK {psk}")
        read_response(fh, {235})

        _smtp_send_message(send, read_response, sock, fh, transcript, s, "", s.body, f"{test_id}-base")

        if mock_sensitive:
            sensitive_result = run_smtp_sensitive_probe(send, read_response, sock, fh, transcript, s, test_id)

        send(sock, "QUIT")
        read_response(fh, {221})

        elapsed = max(1e-6, time.time() - t0)
        result.update({
            "status": "SUCCESS",
            "inference": "SMTP emulation delivered the test payload successfully.",
            "client_elapsed_s": elapsed,
            "dialogue": transcript,
            "mock_sensitive": sensitive_result,
        })
        return result

    except KeyboardInterrupt as e:
        elapsed = max(1e-6, time.time() - t0)
        result.update({
            "status": "ABORTED",
            "inference": "User requested quit (Q) during SMTP test",
            "client_elapsed_s": elapsed,
            "error_type": type(e).__name__,
            "error": str(e),
            "dialogue": transcript,
            "mock_sensitive": sensitive_result,
        })
        return result

    except SMTPDialogueError as e:
        elapsed = max(1e-6, time.time() - t0)
        status, inf = classify_smtp(e.code, e.message)
        if mock_sensitive:
            sensitive_result = sensitive_info(True, "NOT_ATTEMPTED", "SMTP dialogue failed before mock test.")
        result.update({
            "status": status,
            "inference": inf,
            "client_elapsed_s": elapsed,
            "error_type": type(e).__name__,
            "error": str(e),
            "failure_detail": e.message,
            "dialogue": transcript,
            "mock_sensitive": sensitive_result,
        })
        return result

    except (socket.timeout, OSError, ConnectionRefusedError, ConnectionResetError) as e:
        elapsed = max(1e-6, time.time() - t0)
        status, inf = classify_tcp_exception(e)
        detail = f"No SMTP response before timeout ({timeout_s}s)." if isinstance(e, socket.timeout) else ""
        if mock_sensitive:
            sensitive_result = sensitive_info(True, "NOT_ATTEMPTED", "SMTP connection error before mock test.")
        result.update({
            "status": status,
            "inference": inf,
            "client_elapsed_s": elapsed,
            "error_type": type(e).__name__,
            "error": str(e),
            "failure_detail": detail,
            "dialogue": transcript,
            "mock_sensitive": sensitive_result,
        })
        return result

    except Exception as e:
        elapsed = max(1e-6, time.time() - t0)
        if mock_sensitive:
            sensitive_result = sensitive_info(True, "NOT_ATTEMPTED", "SMTP error before mock test.")
        result.update({
            "status": "ERROR",
            "inference": "SMTP test errored (client-side exception).",
            "client_elapsed_s": elapsed,
            "error_type": type(e).__name__,
            "error": str(e),
            "dialogue": transcript,
        })
        return result

    finally:
        if show_progress:
            end_progress_line()
        if fh:
            try:
                fh.close()
            except Exception:
                pass
        if sock:
            try:
                sock.close()
            except Exception:
                pass


# -------------------------
# HTML report + inline SVG chart
# -------------------------

def _result_label(r: dict[str, Any]) -> str:
    t = (r.get("type") or "").lower()
    if t == "tcp":
        return f"TCP {r.get('host')}:{r.get('port')}"
    if t == "udp":
        return f"UDP {r.get('host')}:{r.get('port')} ({r.get('udp_mode')})"
    if t == "http":
        return f"HTTP {r.get('url')}"
    if t == "dns":
        return f"DNS {r.get('host')}:{r.get('port')} {r.get('qname')} ({r.get('qtype')})"
    if t == "telnet":
        return f"TELNET {r.get('host')}:{r.get('port')}"
    if t == "smtp":
        return f"SMTP {r.get('host')}:{r.get('port')}"
    return str(t).upper()


def _result_mbps(r: dict[str, Any]) -> float:
    t = (r.get("type") or "").lower()
    if t == "tcp":
        return float(r.get("client_mbps") or 0.0)
    if t == "udp":
        return float(r.get("approx_mbps") or 0.0)
    if t == "http":
        return float(r.get("client_mbps") or 0.0)
    if t == "dns":
        return 0.0
    if t in ("telnet", "smtp"):
        return 0.0
    return 0.0


def _svg_throughput_chart(results: list[dict[str, Any]]) -> str:
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
        noisy = {
            "ERROR",
            "NO_LISTENER",
            "BLOCKED_OR_DROPPED",
            "BLOCKED_OR_UNREACHABLE",
            "AUTH_FAILED",
            "RESET",
            "PARTIAL",
        }
        if s in noisy:
            return "0.55"
        return "0.55"

    svg = [f"<svg width='{chart_w}' height='{chart_h}' viewBox='0 0 {chart_w} {chart_h}' xmlns='http://www.w3.org/2000/svg'>"]
    svg.append("<text x='0' y='14' font-size='13' fill='#222'>Throughput (Mbps) by test</text>")

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
        svg.append(
            f"<rect x='{left_pad}' y='{y+5}' width='{bar_w}' height='12' "
            f"rx='3' ry='3' fill='#222' opacity='{op}'/>"
        )
        svg.append(f"<text x='{left_pad+bar_max_w+6}' y='{y+14}' font-size='11' fill='#222'>{mbps:.2f}</text>")
        y += row_h

    svg.append("</svg>")
    return "".join(svg)


def _truncate(s: str, max_len: int = 12000) -> str:
    if len(s) <= max_len:
        return s
    return s[:max_len] + "\n...[truncated]..."


def _unique_targets(results: list[dict[str, Any]]) -> dict[str, list[str]]:
    tcp_udp_hosts = set()
    http_hosts = set()
    http_urls = set()
    dns_targets = set()

    for r in results:
        t = (r.get("type") or "").lower()
        if t in ("tcp", "udp", "telnet", "smtp"):
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
        elif t == "dns":
            h = r.get("host")
            p = r.get("port")
            q = r.get("qname")
            if h and p:
                dns_targets.add(f"{h}:{p} {q}")

    return {
        "tcp_udp_targets": sorted(tcp_udp_hosts),
        "http_hosts": sorted(http_hosts),
        "http_urls": sorted(http_urls),
        "dns_targets": sorted(dns_targets),
    }


def generate_sensitive_section(results: list[dict[str, Any]], enabled: bool) -> str:
    if not enabled:
        return "<p class='small'>Mock sensitive data testing disabled for this run.</p>"

    rows = []
    for r in results:
        info = r.get("mock_sensitive") or {}
        if not info.get("enabled"):
            continue
        status = str(info.get("status", "UNDETERMINED")).upper()
        if status == "SUCCESS":
            css = "sensitive-success"
        elif status == "FAILED":
            css = "sensitive-failed"
        else:
            css = "sensitive-undetermined"
        target = _result_label(r)
        detail = str(info.get("detail", ""))
        obf_status = info.get("obfuscated_status")
        obf_detail = info.get("obfuscated_detail")
        if obf_status and obf_status != "NOT_RUN":
            detail = f"{detail} Obfuscated attempt {obf_status}: {obf_detail}"
        download_status = info.get("download_status")
        download_detail = info.get("download_detail")
        if download_status:
            detail = f"{detail} Download attempt {download_status}: {download_detail}"
        frameworks = ", ".join(info.get("frameworks", []))
        rows.append(
            f"<tr class='{css}'>"
            f"<td>{html.escape(str(r.get('type', '')).upper())}</td>"
            f"<td>{html.escape(target)}</td>"
            f"<td>{html.escape(status)}</td>"
            f"<td>{html.escape(detail)}</td>"
            f"<td>{html.escape(frameworks)}</td>"
            "</tr>"
        )

    if not rows:
        return "<p class='small'>Mock sensitive testing enabled, but no base tests succeeded.</p>"

    frameworks_note = ", ".join(SENSITIVE_FRAMEWORKS)
    table = (
        "<table>"
        "<thead><tr><th>Protocol</th><th>Target</th><th>Status</th><th>Detail</th><th>Frameworks</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        "</table>"
        f"<p class='small'>Framework references: {html.escape(frameworks_note)}</p>"
    )
    return table


def write_html_report(path: str, summary: dict[str, Any]) -> None:
    test_id = summary.get("test_id", "")
    started = summary.get("started", "")
    ended = summary.get("ended", "")
    run_status = summary.get("run_status", "")
    cfg = summary.get("config_path", "")
    allow_modes = summary.get("allow_udp_modes", "")
    udp_override = summary.get("udp_mode_override", "")
    server_arg = summary.get("server_arg", "")
    force_server = summary.get("force_server", False)
    report_redacted = bool(summary.get("report_redacted", False))
    tcp_timeout = summary.get("tcp_timeout_s")
    udp_timeout = summary.get("udp_timeout_s")
    http_timeout = summary.get("http_timeout_s")

    client_env: dict[str, Any] = summary.get("client_env", {})
    results: list[dict[str, Any]] = summary.get("results", [])

    total = len(results)
    by_status: dict[str, int] = {}
    for r in results:
        by_status[r.get("status", "UNKNOWN")] = by_status.get(r.get("status", "UNKNOWN"), 0) + 1

    status_items = "".join(
        f"<li><b>{html.escape(k)}</b>: {v}</li>"
        for k, v in sorted(by_status.items(), key=lambda kv: (-kv[1], kv[0]))
    )

    chart_svg = _svg_throughput_chart(results)
    targets = _unique_targets(results)
    tcp_targets_text = "\n".join(targets["tcp_udp_targets"]) or "(none)"
    http_urls_text = "\n".join(targets["http_urls"]) or "(none)"
    dns_targets_text = "\n".join(targets["dns_targets"]) or "(none)"

    # network command outputs (optional)
    net_cmds = client_env.get("net_commands") or {}
    net_cmd_blocks = []
    if isinstance(net_cmds, dict) and net_cmds:
        for k, v in net_cmds.items():
            net_cmd_blocks.append(
                f"<h4>{html.escape(str(k))}</h4>"
                f"<pre>{html.escape(_truncate(str(v)))}</pre>"
            )
    if net_cmd_blocks:
        net_cmd_html = "".join(net_cmd_blocks)
    else:
        if report_redacted:
            net_cmd_html = "<div class='small'>Report redaction enabled; diagnostics suppressed.</div>"
        else:
            net_cmd_html = "<div class='small'>Command output capture disabled.</div>"

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
        elif t == "dns":
            target = f"{r.get('host')}:{r.get('port')} {r.get('qname')}"
            detail = f"qtype={r.get('qtype')}"
        elif t == "telnet":
            target = f"{r.get('host')}:{r.get('port')}"
            detail = f"user={r.get('username')} commands={r.get('commands_planned')}"
        elif t == "smtp":
            target = f"{r.get('host')}:{r.get('port')}"
            detail = f"from={r.get('mail_from')} to={r.get('rcpt_to')}"
        else:
            target = r.get("url", "")
            detail = f"bytes={r.get('bytes_planned')}"

        timeout_hint = r.get("client_timeout_s")
        if timeout_hint:
            detail = f"{detail} timeout={timeout_hint}s"

        err = r.get("error", "")
        err_type = r.get("error_type", "")
        detail2 = f"{err_type}: {err}" if err else ""
        failure_detail = r.get("failure_detail")
        if failure_detail:
            detail2 = ", ".join([part for part in [detail2, failure_detail] if part])

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
    env_table.append(env_line("Report redaction", "True" if report_redacted else "False"))

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
    .sensitive-success {{ background: #ffe5e5; }}
    .sensitive-failed {{ background: #e6f7e6; }}
    .sensitive-undetermined {{ background: #fff8d6; }}
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
        TCP timeout: <code>{html.escape(str(tcp_timeout))} s</code>
        &nbsp; UDP timeout: <code>{html.escape(str(udp_timeout))} s</code>
        &nbsp; HTTP timeout: <code>{html.escape(str(http_timeout))} s</code><br/>
        Report redaction: <code>{html.escape(str(report_redacted))}</code><br/>
        Mock sensitive data testing: <code>{html.escape(str(summary.get('mock_sensitive_testing', False)))}</code><br/>
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
      <pre>{html.escape(tcp_targets_text)}</pre>
      <p class="small"><b>HTTP URLs</b></p>
      <pre>{html.escape(http_urls_text)}</pre>
      <p class="small"><b>DNS targets</b></p>
      <pre>{html.escape(dns_targets_text)}</pre>
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
      This chart reflects <b>client-side estimated throughput</b>. UDP values depend heavily on the selected mode
      and ACK strategy.
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
    <h2>Mock Sensitive Data Exfiltration</h2>
    {generate_sensitive_section(results, summary.get("mock_sensitive_testing", False))}
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


def resolve_html_out(arg_html_out: str | None, test_id: str) -> str:
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
    ap.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    ap.add_argument("--config", required=True, help="JSON config path (explicit allowlist)")
    ap.add_argument("--timeout", type=float, default=10.0, help="Default socket/HTTP timeout seconds")
    ap.add_argument("--tcp-timeout", type=float, default=None,
                    help="Override TCP client timeout seconds (defaults to --timeout).")
    ap.add_argument("--udp-timeout", type=float, default=None,
                    help="Override UDP client timeout seconds (defaults to --timeout).")
    ap.add_argument("--test-id", default=None, help="Optional test id (otherwise timestamp-based)")
    ap.add_argument("--psk", default=None, help="Pre-shared key (prefer --psk-file)")
    ap.add_argument("--psk-file", default=None, help="Read PSK from file")
    ap.add_argument("--prompt-psk", action="store_true", help="Prompt for PSK interactively (overrides --psk).")

    # NEW: server selection for TCP/UDP
    ap.add_argument("--server", default="127.0.0.1",
                    help="Default server host/IP for TCP/UDP entries missing 'host' in config (default 127.0.0.1)")
    ap.add_argument("--force-server", action="store_true",
                    help="Override all TCP/UDP 'host' values in config with --server for this run")

    ap.add_argument("--html-out", default=None,
                    help="Write HTML report to this file. If omitted, a timestamped filename is used.")
    ap.add_argument("--no-progress", action="store_true", help="Disable progress bars")
    ap.add_argument("--no-quit-monitor", action="store_true", help="Disable 'press Q to quit' monitor")
    ap.add_argument(
        "--include-network-commands",
        action="store_true",
        help=(
            "Include OS command output (ipconfig/route/ip addr) in the HTML report "
            "(may contain sensitive details)."
        ),
    )
    ap.add_argument(
        "--redact-report",
        action="store_true",
        help="Redact host-identifying fields in the HTML/JSON output (overrides --include-network-commands).",
    )
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
    ap.add_argument(
        "--port-filter",
        default=None,
        help="Only run tests whose ports are in this comma-separated list or ranges (e.g. 80,443,5000-5005).",
    )
    ap.add_argument(
        "--test-mock-sensitive-data",
        action="store_true",
        help="Attempt mock sensitive data exfil on protocols that succeed (for compliance validation).",
    )

    args = ap.parse_args()
    setup_logging(args.verbose)

    try:
        cfg = load_config(args.config)
    except ConfigError as e:
        raise SystemExit(f"Invalid config: {e}") from e
    test_id = args.test_id or f"exf-{int(time.time())}"
    show_progress = not args.no_progress

    # PSK
    psk = args.psk
    if args.prompt_psk:
        if args.psk:
            raise SystemExit("--psk and --prompt-psk cannot be used together.")
        psk = getpass.getpass("Enter PSK: ").strip()
    if args.psk_file and not args.prompt_psk:
        with open(args.psk_file, encoding="utf-8") as f:
            psk = f.read().strip()
    if not psk:
        raise SystemExit("PSK required. Use --psk-file, --psk, or --prompt-psk.")

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
        allowed_str = ", ".join(sorted(allowed_udp_modes))
        raise SystemExit(f"--udp-mode-override '{udp_override}' is not in --allow-udp-modes ({allowed_str})")

    port_filter: set[int] | None = None
    if args.port_filter:
        try:
            port_filter = parse_port_spec(args.port_filter)
        except ValueError as exc:
            raise SystemExit(f"Invalid --port-filter: {exc}") from exc

    mock_sensitive = bool(args.test_mock_sensitive_data)

    # Per-protocol timeouts
    tcp_timeout = float(args.tcp_timeout) if args.tcp_timeout is not None else float(args.timeout)
    udp_timeout = float(args.udp_timeout) if args.udp_timeout is not None else float(args.timeout)

    # HTML output path resolution (timestamped by default)
    html_out_path = resolve_html_out(args.html_out, test_id)

    # Quit monitor
    qm = QuitMonitor()
    qm.start(enable=not args.no_quit_monitor)
    if not args.no_quit_monitor:
        log.info("Quit monitor enabled: press 'Q' to quit (report will still be written).")

    # Client env info (captured once per run)
    include_cmds = bool(args.include_network_commands) and (not args.redact_report)
    if args.include_network_commands and args.redact_report:
        log.warning("Report redaction enabled; suppressing network command capture.")
    client_env = summarize_client_env(include_cmd_output=include_cmds)
    if args.redact_report:
        client_env = redact_client_env(client_env)

    tcp_items = cfg.get("tcp", [])
    udp_items = cfg.get("udp", [])
    http_items = cfg.get("http", [])
    dns_items = cfg.get("dns", [])
    telnet_items = cfg.get("telnet", [])
    smtp_items = cfg.get("smtp", [])
    total_tests = (
        len(tcp_items)
        + len(udp_items)
        + len(http_items)
        + len(dns_items)
        + len(telnet_items)
        + len(smtp_items)
    )
    completed = 0

    results: list[dict[str, Any]] = []
    started = _now_iso()

    def overall() -> None:
        if show_progress:
            print_progress_line(progress_bar("Overall tests", completed, max(1, total_tests)))
        else:
            log.info("Progress: %d/%d tests completed", completed, max(1, total_tests))

    # Apply server default/override to TCP/UDP
    server_arg = (args.server or "127.0.0.1").strip() or "127.0.0.1"

    def port_allowed(port: int | None) -> bool:
        if port_filter is None:
            return True
        if port is None:
            return False
        return port in port_filter

    def record_skip(kind: str, detail: dict[str, Any]) -> None:
        record = {
            "type": kind,
            "status": "SKIPPED",
            "inference": "Skipped by --port-filter",
            "started": _now_iso(),
        }
        record.update(detail)
        results.append(record)

    try:
        # TCP
        for item in tcp_items:
            if qm.stop_event.is_set():
                break
            host = str(item.get("host") or "").strip()
            if args.force_server or not host:
                host = server_arg
            port = int(item["port"])
            if not port_allowed(port):
                record_skip("tcp", {"host": host, "port": port, "bytes_planned": int(item["bytes"])})
                completed += 1
                overall()
                continue
            t = TcpTest(host=host, port=port, bytes=int(item["bytes"]))
            if args.verbose:
                log.info("TCP test: %s:%d bytes=%d", t.host, t.port, t.bytes)
            results.append(tcp_test(t, test_id, tcp_timeout, psk, qm.stop_event, show_progress, mock_sensitive))
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

            port = int(item["port"])
            if not port_allowed(port):
                record_skip("udp", {
                    "host": host,
                    "port": port,
                    "udp_mode": mode,
                    "packets_planned": int(item.get("packets", 0) or 0),
                    "payload_size": int(item.get("payload_size", 512)),
                })
                completed += 1
                overall()
                continue

            u = UdpTest(
                host=host,
                port=port,
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
            results.append(udp_test(u, test_id, udp_timeout, psk, qm.stop_event, show_progress, mock_sensitive))
            completed += 1
            overall()

        # DNS
        for item in dns_items:
            if qm.stop_event.is_set():
                break
            host = str(item.get("host") or server_arg)
            port = int(item.get("port"))
            if not port_allowed(port):
                record_skip("dns", {"host": host, "port": port, "qname": str(item.get("qname"))})
                completed += 1
                overall()
                continue
            dtst = DnsTest(
                host=host,
                port=port,
                qname=str(item.get("qname")),
                qtype=str(item.get("qtype", "A")),
            )
            if args.verbose:
                log.info("DNS test: %s:%d %s %s", dtst.host, dtst.port, dtst.qtype, dtst.qname)
            results.append(dns_test(dtst, test_id, udp_timeout, psk, qm.stop_event, show_progress, mock_sensitive))
            completed += 1
            overall()

        # Telnet
        for item in telnet_items:
            if qm.stop_event.is_set():
                break
            host = str(item.get("host") or "").strip()
            if args.force_server or not host:
                host = server_arg
            port = int(item["port"])
            if not port_allowed(port):
                record_skip("telnet", {"host": host, "port": port, "commands_planned": len(item.get("commands", []))})
                completed += 1
                overall()
                continue
            commands = [str(cmd) for cmd in item.get("commands", [])]
            tt = TelnetTest(
                host=host,
                port=port,
                username=str(item.get("username")),
                password=str(item.get("password")),
                commands=commands,
            )
            if args.verbose:
                log.info("Telnet test: %s:%d user=%s", tt.host, tt.port, tt.username)
            results.append(telnet_test(tt, test_id, tcp_timeout, psk, qm.stop_event, show_progress, mock_sensitive))
            completed += 1
            overall()

        # SMTP
        for item in smtp_items:
            if qm.stop_event.is_set():
                break
            host = str(item.get("host") or "").strip()
            if args.force_server or not host:
                host = server_arg
            port = int(item["port"])
            if not port_allowed(port):
                record_skip("smtp", {"host": host, "port": port, "rcpt_to": item.get("rcpt_to")})
                completed += 1
                overall()
                continue
            sm = SmtpTest(
                host=host,
                port=port,
                mail_from=str(item.get("mail_from")),
                rcpt_to=str(item.get("rcpt_to")),
                subject=str(item.get("subject")),
                body=str(item.get("body")),
            )
            if args.verbose:
                log.info("SMTP test: %s:%d rcpt=%s", sm.host, sm.port, sm.rcpt_to)
            results.append(smtp_test(sm, test_id, tcp_timeout, psk, qm.stop_event, show_progress, mock_sensitive))
            completed += 1
            overall()

        # HTTP (URLs are used as-is; mix of IPs/hostnames supported)
        for item in http_items:
            if qm.stop_event.is_set():
                break
            h = HttpTest(url=item["url"], bytes=int(item["bytes"]))
            try:
                parsed = urlparse(h.url)
            except Exception:
                parsed = None
            http_port = None
            if parsed:
                if parsed.port:
                    http_port = int(parsed.port)
                elif parsed.scheme == "https":
                    http_port = 443
                elif parsed.scheme == "http":
                    http_port = 80
            if not port_allowed(http_port):
                record_skip("http", {"url": h.url, "bytes_planned": h.bytes, "port": http_port})
                completed += 1
                overall()
                continue
            if args.verbose:
                log.info("HTTP test: %s bytes=%d", h.url, h.bytes)
            results.append(http_test(h, test_id, args.timeout, psk, qm.stop_event, show_progress, mock_sensitive))
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
        "tcp_timeout_s": tcp_timeout,
        "udp_timeout_s": udp_timeout,
        "http_timeout_s": float(args.timeout),
        "client_env": client_env,
        "report_redacted": bool(args.redact_report),
        "mock_sensitive_testing": mock_sensitive,
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
