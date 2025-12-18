"""End-to-end smoke tests for Exfiliator."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from exfiliator_client import parse_port_spec
from exfiliator_server import (
    dns_worker,
    generate_psk,
    http_worker,
    parse_ports,
    smtp_worker,
    tcp_worker,
    telnet_worker,
    udp_worker,
)


def _get_free_port() -> int:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except PermissionError as exc:
        pytest.skip(f"Socket creation blocked in test environment: {exc}")
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _start_server_threads(
    bind: str,
    tcp_port: int,
    udp_port: int,
    http_port: int,
    dns_port: int,
    telnet_port: int,
    smtp_port: int,
    psk: str,
) -> tuple[threading.Event, list[threading.Thread]]:
    stop_event = threading.Event()
    threads: list[threading.Thread] = []
    if tcp_port:
        threads.append(
            threading.Thread(
                target=tcp_worker,
                args=(bind, tcp_port, psk, stop_event, 1024 * 1024),
                daemon=True,
            )
        )
    if udp_port:
        threads.append(
            threading.Thread(
                target=udp_worker,
                args=(bind, udp_port, psk, stop_event, 30.0),
                daemon=True,
            )
        )
    if http_port:
        threads.append(
            threading.Thread(
                target=http_worker,
                args=(bind, http_port, psk, stop_event, 1024 * 1024, 5.0, True),
                daemon=True,
            )
        )
    if dns_port:
        threads.append(
            threading.Thread(
                target=dns_worker,
                args=(bind, dns_port, psk, stop_event),
                daemon=True,
            )
        )
    if telnet_port:
        threads.append(
            threading.Thread(
                target=telnet_worker,
                args=(bind, telnet_port, psk, stop_event),
                daemon=True,
            )
        )
    if smtp_port:
        threads.append(
            threading.Thread(
                target=smtp_worker,
                args=(bind, smtp_port, psk, stop_event),
                daemon=True,
            )
        )
    for thread in threads:
        thread.start()
    return stop_event, threads


def test_client_generates_report(tmp_path: Path) -> None:
    bind = "127.0.0.1"
    tcp_port = _get_free_port()
    udp_port = _get_free_port()
    http_port = _get_free_port()
    dns_port = _get_free_port()
    telnet_port = _get_free_port()
    smtp_port = _get_free_port()

    psk = generate_psk()
    psk_file = tmp_path / "pt_psk.txt"
    psk_file.write_text(psk, encoding="utf-8")

    stop_event, threads = _start_server_threads(
        bind, tcp_port, udp_port, http_port, dns_port, telnet_port, smtp_port, psk
    )

    try:
        time.sleep(0.2)
        cfg = {
            "tcp": [
                {"port": tcp_port, "bytes": 4096},
            ],
            "udp": [
                {
                    "port": udp_port,
                    "udp_mode": "reliable",
                    "payload_size": 64,
                    "packets": 10,
                    "inter_packet_ms": 0,
                    "ack_every": 1,
                    "batch_size": 1,
                    "ack_timeout_ms": 500,
                }
            ],
            "http": [
                {
                    "url": f"http://{bind}:{http_port}/upload",
                    "bytes": 2048,
                }
            ],
            "dns": [
                {
                    "host": bind,
                    "port": dns_port,
                    "qname": "example.com",
                    "qtype": "A",
                }
            ],
            "telnet": [
                {
                    "host": bind,
                    "port": telnet_port,
                    "username": "tester",
                    "password": "labpass",
                    "commands": ["whoami", "uname -a"],
                }
            ],
            "smtp": [
                {
                    "host": bind,
                    "port": smtp_port,
                    "mail_from": "alerts@example.com",
                    "rcpt_to": "ops@example.com",
                    "subject": "Smoke Test",
                    "body": "Exfiliator smoke test payload.",
                }
            ],
        }
        config_path = tmp_path / "pt_config.json"
        config_path.write_text(json.dumps(cfg), encoding="utf-8")
        html_path = tmp_path / "report.html"

        proc = subprocess.run(
            [
                sys.executable,
                "exfiliator_client.py",
                "--config",
                str(config_path),
                "--psk-file",
                str(psk_file),
                "--server",
                bind,
                "--html-out",
                str(html_path),
                "--test-id",
                "pytest-smoke",
                "--test-mock-sensitive-data",
                "--no-progress",
                "--no-quit-monitor",
            ],
            capture_output=True,
            text=True,
            check=True,
        )

        summary = json.loads(proc.stdout)
        assert summary["run_status"] == "COMPLETED"
        assert len(summary["results"]) == 6
        statuses = {item["type"]: item["status"] for item in summary["results"]}
        assert statuses["tcp"] == "SUCCESS"
        assert statuses["udp"] in {"SUCCESS", "PARTIAL"}
        assert statuses["http"] == "SUCCESS"
        assert statuses["dns"] == "SUCCESS"
        assert statuses["telnet"] == "SUCCESS"
        assert statuses["smtp"] == "SUCCESS"
        sensitive = {
            item["type"]: (item.get("mock_sensitive") or {}).get("status")
            for item in summary["results"]
            if (item.get("mock_sensitive") or {}).get("enabled")
        }
        allowed = {"SUCCESS", "FAILED", "UNDETERMINED", "NOT_ATTEMPTED"}
        assert sensitive["tcp"] in allowed
        assert sensitive["udp"] in allowed
        assert sensitive["http"] in allowed
        assert sensitive["dns"] == "SUCCESS"
        assert sensitive["telnet"] == "SUCCESS"
        assert sensitive["smtp"] == "SUCCESS"
        assert html_path.exists()
        html = html_path.read_text(encoding="utf-8")
        assert "Port/Protocol Test Report" in html
    finally:
        stop_event.set()
        for thread in threads:
            thread.join(timeout=1)


def test_redact_report_masks_sensitive_fields(tmp_path: Path) -> None:
    config_path = tmp_path / "empty_config.json"
    config_path.write_text(json.dumps({"tcp": [], "udp": [], "http": []}), encoding="utf-8")
    html_path = tmp_path / "redacted.html"

    proc = subprocess.run(
        [
            sys.executable,
            "exfiliator_client.py",
            "--config",
            str(config_path),
            "--psk",
            "test-psk",
            "--html-out",
            str(html_path),
            "--redact-report",
            "--include-network-commands",
            "--no-progress",
            "--no-quit-monitor",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    summary = json.loads(proc.stdout)
    env = summary["client_env"]
    assert summary["report_redacted"] is True
    assert env["hostname"] == "(redacted)"
    assert env["net_commands"] == {}
    assert html_path.exists()


def test_parse_port_helpers() -> None:
    assert parse_port_spec("80,443,5000-5002") == {80, 443, 5000, 5001, 5002}
    assert parse_ports("8080,9000-9002") == [8080, 9000, 9001, 9002]


def test_port_filter_skips_tests(tmp_path: Path) -> None:
    config_path = tmp_path / "filter.json"
    config_path.write_text(
        json.dumps(
            {
                "tcp": [{"port": 5001, "bytes": 1024}],
                "udp": [{"port": 6001, "packets": 5, "payload_size": 32}],
                "http": [{"url": "http://example.com/upload", "bytes": 128}],
                "dns": [{"host": "127.0.0.1", "port": 5553, "qname": "example.com", "qtype": "A"}],
                "telnet": [
                    {"host": "127.0.0.1", "port": 5554, "username": "user", "password": "pass", "commands": ["id"]}
                ],
                "smtp": [
                    {
                        "host": "127.0.0.1",
                        "port": 5555,
                        "mail_from": "a@example.com",
                        "rcpt_to": "b@example.com",
                        "subject": "skip",
                        "body": "test",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    proc = subprocess.run(
        [
            sys.executable,
            "exfiliator_client.py",
            "--config",
            str(config_path),
            "--psk",
            "test-psk",
            "--port-filter",
            "7000-7001",
            "--no-progress",
            "--no-quit-monitor",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    summary = json.loads(proc.stdout)
    statuses = [r["status"] for r in summary["results"]]
    assert statuses == ["SKIPPED"] * len(summary["results"])
