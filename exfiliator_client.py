#!/usr/bin/env python3
"""
Purple-team port/protocol test client with PSK auth.

- Tests TCP: connect, send N bytes, read JSON summary (PSK in JSON header)
- Tests UDP: handshake + send datagrams with seq, wait for ACKs (PSK in HELLO JSON)
- Tests HTTP: POST synthetic bytes to /upload (PSK in X-PSK header)

Requires an explicit allowlist of targets/ports in a JSON config file.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import time
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


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


@dataclass
class HttpTest:
    url: str
    bytes: int


def load_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def tcp_test(t: TcpTest, test_id: str, timeout_s: float, psk: str) -> Dict[str, Any]:
    payload = rand_bytes(t.bytes)
    meta = {"test_id": test_id, "bytes": t.bytes, "psk": psk}
    header = (json.dumps(meta) + "\n").encode("utf-8")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout_s)

    t0 = time.time()
    s.connect((t.host, t.port))
    s.sendall(header)
    s.sendall(payload)

    # Read a line of JSON response
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > 65536:
            break
    s.close()

    elapsed = max(1e-6, time.time() - t0)
    sent_mbps = (t.bytes * 8) / elapsed / 1_000_000

    resp: Dict[str, Any]
    try:
        resp = json.loads(buf.decode("utf-8").strip())
    except Exception:
        resp = {"raw_response": buf.decode("utf-8", errors="replace")}

    return {
        "type": "tcp",
        "host": t.host,
        "port": t.port,
        "bytes_sent": t.bytes,
        "client_elapsed_s": elapsed,
        "client_mbps": sent_mbps,
        "server_response": resp,
    }


def udp_test(u: UdpTest, test_id: str, timeout_s: float, psk: str) -> Dict[str, Any]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout_s)

    addr = (u.host, u.port)

    # HELLO handshake (with PSK)
    hello = b"HELLO " + json.dumps({"test_id": test_id, "psk": psk}).encode("utf-8")
    sock.sendto(hello, addr)
    try:
        _ = sock.recvfrom(2048)
    except Exception:
        # Some networks drop replies; continue with test anyway
        pass

    seq_fmt = "!Q"  # uint64
    payload = rand_bytes(max(0, u.payload_size))
    sent = 0
    acked = 0
    pending = set()

    t_start = time.time()

    for i in range(u.packets):
        seq = i + 1
        pending.add(seq)
        pkt = b"DATA " + struct.pack(seq_fmt, seq) + payload
        sock.sendto(pkt, addr)
        sent += 1
        time.sleep(max(0.0, u.inter_packet_ms / 1000.0))

        # Drain ACKs opportunistically
        drain_until = time.time() + (u.ack_timeout_ms / 1000.0)
        while time.time() < drain_until:
            try:
                data, _a = sock.recvfrom(2048)
                if data.startswith(b"ACK ") and len(data) >= 4 + 8:
                    ack_seq = struct.unpack(seq_fmt, data[4:12])[0]
                    if ack_seq in pending:
                        pending.remove(ack_seq)
                        acked += 1
            except socket.timeout:
                break
            except Exception:
                break

    # Final drain
    final_drain_end = time.time() + (u.ack_timeout_ms / 1000.0)
    while time.time() < final_drain_end and pending:
        try:
            data, _a = sock.recvfrom(2048)
            if data.startswith(b"ACK ") and len(data) >= 4 + 8:
                ack_seq = struct.unpack(seq_fmt, data[4:12])[0]
                if ack_seq in pending:
                    pending.remove(ack_seq)
                    acked += 1
        except Exception:
            break

    elapsed = max(1e-6, time.time() - t_start)
    bytes_sent = u.packets * (5 + 8 + len(payload))
    mbps = (bytes_sent * 8) / elapsed / 1_000_000

    sock.close()

    loss = 0.0 if sent == 0 else (sent - acked) / sent
    return {
        "type": "udp",
        "host": u.host,
        "port": u.port,
        "packets_sent": sent,
        "packets_acked": acked,
        "loss_rate": loss,
        "payload_size": len(payload),
        "client_elapsed_s": elapsed,
        "approx_mbps": mbps,
    }


def http_test(h: HttpTest, test_id: str, timeout_s: float, psk: str) -> Dict[str, Any]:
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
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        body = resp.read()
        status = resp.status

    elapsed = max(1e-6, time.time() - t0)
    mbps = (h.bytes * 8) / elapsed / 1_000_000

    server: Dict[str, Any]
    try:
        server = json.loads(body.decode("utf-8"))
    except Exception:
        server = {"raw_response": body.decode("utf-8", errors="replace")}

    return {
        "type": "http",
        "url": h.url,
        "bytes_sent": h.bytes,
        "status": status,
        "client_elapsed_s": elapsed,
        "client_mbps": mbps,
        "server_response": server,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True, help="JSON config path (explicit allowlist)")
    ap.add_argument("--timeout", type=float, default=10.0, help="Socket/HTTP timeout seconds")
    ap.add_argument("--test-id", default=None, help="Optional test id (otherwise timestamp-based)")

    ap.add_argument("--psk", default=None, help="Pre-shared key (prefer --psk-file)")
    ap.add_argument("--psk-file", default=None, help="Read PSK from file")

    args = ap.parse_args()

    cfg = load_config(args.config)
    test_id = args.test_id or f"pt-{int(time.time())}"

    psk = args.psk
    if args.psk_file:
        with open(args.psk_file, "r", encoding="utf-8") as f:
            psk = f.read().strip()
    if not psk:
        raise SystemExit("PSK required. Use --psk-file or --psk.")

    results: List[Dict[str, Any]] = []

    for item in cfg.get("tcp", []):
        t = TcpTest(host=item["host"], port=int(item["port"]), bytes=int(item["bytes"]))
        results.append(tcp_test(t, test_id, args.timeout, psk))

    for item in cfg.get("udp", []):
        u = UdpTest(
            host=item["host"],
            port=int(item["port"]),
            payload_size=int(item.get("payload_size", 512)),
            packets=int(item.get("packets", 200)),
            inter_packet_ms=int(item.get("inter_packet_ms", 5)),
            ack_timeout_ms=int(item.get("ack_timeout_ms", 50)),
        )
        results.append(udp_test(u, test_id, args.timeout, psk))

    for item in cfg.get("http", []):
        h = HttpTest(url=item["url"], bytes=int(item["bytes"]))
        results.append(http_test(h, test_id, args.timeout, psk))

    out = {"test_id": test_id, "results": results}
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
