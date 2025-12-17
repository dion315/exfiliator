#!/usr/bin/env python3
"""
Purple-team port/protocol test server (TCP/UDP + optional HTTP).

- Listens on multiple TCP and UDP ports
- Accepts synthetic test payloads, responds with acknowledgements
- Optional HTTP endpoint for POST /upload
- No file IO, no covert channels, no obfuscation

Run on the target host where you want to verify inbound reachability.
"""

from __future__ import annotations

import argparse
import json
import logging
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Iterable


log = logging.getLogger("pt_server")


def setup_logging(verbosity: int) -> None:
    level = logging.INFO if verbosity == 0 else logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(message)s",
    )


def tcp_worker(bind_ip: str, port: int, recv_timeout_s: float) -> None:
    """Simple TCP sink with small ACKs back to client."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind_ip, port))
    srv.listen(200)
    log.info("TCP listening on %s:%d", bind_ip, port)

    while True:
        conn, addr = srv.accept()
        conn.settimeout(recv_timeout_s)
        t0 = time.time()
        total = 0
        try:
            # Expect a JSON line header first
            header = b""
            while not header.endswith(b"\n"):
                chunk = conn.recv(1)
                if not chunk:
                    raise ConnectionError("Client disconnected before header")
                header += chunk
                if len(header) > 8192:
                    raise ValueError("Header too large")

            meta = json.loads(header.decode("utf-8").strip())
            test_id = meta.get("test_id", "unknown")
            expected = int(meta.get("bytes", 0))

            # Read expected bytes
            while total < expected:
                data = conn.recv(min(65536, expected - total))
                if not data:
                    break
                total += len(data)

            elapsed = max(1e-6, time.time() - t0)
            mbps = (total * 8) / elapsed / 1_000_000
            resp = {"test_id": test_id, "received_bytes": total, "elapsed_s": elapsed, "mbps": mbps}
            conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))
            log.info("TCP %s:%d from %s test_id=%s received=%d bytes (%.2f Mbps)",
                     bind_ip, port, addr[0], test_id, total, mbps)
        except Exception as e:
            try:
                conn.sendall((json.dumps({"error": str(e)}) + "\n").encode("utf-8"))
            except Exception:
                pass
            log.warning("TCP %s:%d from %s error: %s", bind_ip, port, addr[0], e)
        finally:
            try:
                conn.close()
            except Exception:
                pass


def udp_worker(bind_ip: str, port: int) -> None:
    """
    UDP receiver. Expects:
      - first packet: b'HELLO ' + JSON
      - data packets: b'DATA ' + 8-byte seq + payload
    Responds with ACK packets: b'ACK ' + 8-byte seq
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind_ip, port))
    log.info("UDP listening on %s:%d", bind_ip, port)

    sessions = {}  # (ip,port) -> test_id

    while True:
        pkt, addr = sock.recvfrom(65535)
        if pkt.startswith(b"HELLO "):
            try:
                meta = json.loads(pkt[6:].decode("utf-8"))
                sessions[addr] = meta.get("test_id", "unknown")
                log.info("UDP HELLO %s:%d from %s test_id=%s",
                         bind_ip, port, addr[0], sessions[addr])
                sock.sendto(b"HELLO_ACK", addr)
            except Exception as e:
                log.warning("UDP HELLO parse error from %s: %s", addr, e)
            continue

        if pkt.startswith(b"DATA ") and len(pkt) >= 5 + 8:
            seq = pkt[5:13]  # raw 8 bytes
            sock.sendto(b"ACK " + seq, addr)
            continue

        # ignore unknown packets (auditable but not noisy)
        if log.isEnabledFor(logging.DEBUG):
            log.debug("UDP unknown packet from %s len=%d", addr, len(pkt))


class UploadHandler(BaseHTTPRequestHandler):
    server_version = "PTHTTP/1.0"

    def do_POST(self):
        if self.path != "/upload":
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", "0"))
        # Read and discard body (synthetic only)
        read = 0
        while read < length:
            chunk = self.rfile.read(min(65536, length - read))
            if not chunk:
                break
            read += len(chunk)

        resp = json.dumps({"received_bytes": read, "path": self.path}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

        log.info("HTTP POST /upload from %s received=%d bytes", self.client_address[0], read)

    def log_message(self, fmt, *args):
        # suppress default noisy http.server logging; we log ourselves
        return


def http_worker(bind_ip: str, port: int) -> None:
    httpd = HTTPServer((bind_ip, port), UploadHandler)
    log.info("HTTP listening on %s:%d (POST /upload)", bind_ip, port)
    httpd.serve_forever()


def parse_ports(csv: str) -> list[int]:
    out: list[int] = []
    for part in csv.split(","):
        part = part.strip()
        if not part:
            continue
        out.append(int(part))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="0.0.0.0", help="Bind IP (default all)")
    ap.add_argument("--tcp-ports", default="5001,5002", help="CSV list of TCP ports")
    ap.add_argument("--udp-ports", default="5001,5002", help="CSV list of UDP ports")
    ap.add_argument("--http-port", type=int, default=0, help="Enable HTTP server on this port (0 disables)")
    ap.add_argument("--tcp-timeout", type=float, default=15.0, help="TCP recv timeout seconds")
    ap.add_argument("-v", "--verbose", action="count", default=0)
    args = ap.parse_args()

    setup_logging(args.verbose)

    tcp_ports = parse_ports(args.tcp_ports)
    udp_ports = parse_ports(args.udp_ports)

    for p in tcp_ports:
        t = threading.Thread(target=tcp_worker, args=(args.bind, p, args.tcp_timeout), daemon=True)
        t.start()

    for p in udp_ports:
        t = threading.Thread(target=udp_worker, args=(args.bind, p), daemon=True)
        t.start()

    if args.http_port:
        t = threading.Thread(target=http_worker, args=(args.bind, args.http_port), daemon=True)
        t.start()

    log.info("Server running. Ctrl+C to exit.")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        log.info("Shutting down.")


if __name__ == "__main__":
    main()
