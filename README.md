# Exfiliator (Purple-Team Network Control Tester)

A small, **PSK-gated** client/server tool for validating network egress/ingress controls and telemetry across **TCP**, **UDP**, **HTTP**, **DNS**, **Telnet**, and **SMTP look-alike** flows using **synthetic payloads**.

Intended for **authorized purple-team testing** in controlled environments.

---

## Badges

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## What it does

### Server (`exfiliator_server.py`)
- Listens on configured **TCP**, **UDP**, **DNS (UDP)**, **Telnet (TCP)**, **SMTP (TCP)** ports and optional **HTTP** endpoint (`POST /upload`)
- Requires a **pre-shared key (PSK)** for all protocols
- Generates a new PSK each run by default (or honor `--psk` / `--psk-file`)
- Supports multiple UDP modes:
  - `reliable` (ACK every packet; slow but measurable)
  - `batched_ack` (range/batch ACKs; faster + measurable)
  - `firehose` (no DATA ACKs; fastest; reachability via HELLO ACK)
- Built-in guardrails:
  - `--max-tcp-bytes` and `--max-http-bytes` reject oversized uploads (default 50 MB cap)
  - `--http-read-timeout` enforces per-request socket deadlines
  - `--udp-session-ttl` expires idle UDP authorizations
- Prints the generated/loaded PSK on startup (use `--suppress-psk-display` to disable)
- Accepts individual ports or ranges (e.g., `--tcp-ports 5000,6000-6002`)
- Independent listeners for DNS/Telnet/SMTP via `--dns-ports`, `--telnet-ports`, and `--smtp-ports`
- Optional Windows-only helper:
  - Can create **temporary inbound allow rules** in Windows Defender Firewall for the specified ports
  - Can run in **dry-run** mode to print planned firewall changes without modifying the firewall
  - Removes **only** rules created by that server instance on shutdown
- Optional mock download endpoint (`--enable-mock-download`) serving synthetic sensitive data to validate inbound controls

### Client (`exfiliator_client.py`)
- Runs tests from a JSON allowlist config file (sections for `tcp`, `udp`, `http`, `dns`, `telnet`, and `smtp`)
- Outputs:
  - JSON summary to stdout
  - **HTML report** that is **timestamped by default**
- Report includes:
  - Tested ports/targets, outcomes, inference hints
  - An inline **throughput chart**
  - **Client host/device information**
  - **Best-effort network information**
  - The **server value used for testing** and a **targets summary** (supports mixed IPs/hostnames/URLs)
- Includes:
  - Progress bars
  - Verbose logging (`-v`, `-vv`)
  - “Press **Q** to quit” (still writes HTML report)
  - Config validation + optional `--redact-report` to strip hostname/IP/user fields (also suppresses network diagnostics capture)
  - Interactive `--prompt-psk` to enter the PSK without storing it locally
  - `--config` automatically searches the top-level `configs/` folder when given a bare filename
  - `--port-filter` lets you target a specific set or range of ports across TCP/UDP/HTTP entries
  - `--tcp-timeout` / `--udp-timeout` override protocol-specific timeouts and report them in HTML failure details
  - `--test-mock-sensitive-data` replays successful channels with mock PII/PCI/PHI payloads, tries obfuscation, and (for HTTP/S) attempts a `/download` pull to validate inbound controls—all mapped to PCI DSS / HIPAA / GDPR cues in the report; coverage spans TCP, UDP, HTTP, DNS, Telnet, and SMTP flows so you can validate DLP controls end-to-end
  - UDP policy controls:
    - `--allow-udp-modes` (allowlist)
    - `--udp-mode-override` (force)
  - Server selection controls:
    - `--server` (default **127.0.0.1**) used for TCP/UDP/Telnet/SMTP entries missing `host`
    - `--force-server` overrides **all** TCP/UDP/Telnet/SMTP hosts in config for a run
  - DNS probe builder injects the PSK into the query name, while Telnet/SMTP helpers drive banner/login flows so traffic looks like those protocols on any requested port

---

## Folder / file layout

```text
.
├─ exfiliator_client.py
├─ exfiliator_server.py
├─ README.md
├─ pt_config.test.json          # legacy example config 
├─ configs/                     # sample configs (basic_local.json, hybrid_lab.json)
└─ queries/                     # SIEM/SOAR hunting queries for Defender, Sentinel, ADX, Splunk, QRadar, etc.
```

## Sample config (excerpt)

```json
{
  "tcp": [
    {"port": 5001, "bytes": 1048576}
  ],
  "udp": [
    {"port": 5002, "udp_mode": "reliable", "packets": 200, "payload_size": 512}
  ],
  "http": [
    {"url": "http://127.0.0.1:8080/upload", "bytes": 131072}
  ],
  "dns": [
    {"host": "127.0.0.1", "port": 5353, "qname": "internal.lab", "qtype": "A"}
  ],
  "telnet": [
    {
      "host": "127.0.0.1",
      "port": 2323,
      "username": "labuser",
      "password": "labpass",
      "commands": ["whoami", "uname -a"]
    }
  ],
  "smtp": [
    {
      "host": "127.0.0.1",
      "port": 2525,
      "mail_from": "alerts@example.com",
      "rcpt_to": "ops@example.com",
      "subject": "Local smoke test",
      "body": "Synthetic SMTP payload from Exfiliator."
    }
  ]
}
```

## Detection content

Need to prove you ran Exfiliator responsibly? The `queries/` folder ships with ready-to-run hunting snippets for Microsoft Defender, Sentinel, Azure Data Explorer, Exabeam, LogRhythm, Splunk, IBM QRadar, Wazuh, Security Onion, and other widely deployed SIEM stacks. Each bundle explains which parameters to tweak (test ports, host names, PSKs) so you can rapidly search for the Exfiliator traffic patterns across your telemetry lake.

## Versioning & change control

- Exfiliator follows [Semantic Versioning](https://semver.org/) and exposes its current build via `exfiliator_client.py --version` and `exfiliator_server.py --version`.
- See `docs/change_control.md` for the lightweight change control workflow (issue → branch → tests → PR → tag) and guidance on when to bump MAJOR, MINOR, or PATCH. **Every PR merging to `main` must append its summary to the Change Log section in that document before it can be approved.**

## Automated QA & security

Two GitHub Actions workflows keep regressions in check:

- `.github/workflows/qa.yml` runs `ruff`, `pytest`, and bytecode compilation on Ubuntu and Windows for every push/PR.
- `.github/workflows/security.yml` runs `bandit` and `pip-audit --strict` on each push/PR and every Monday via cron. Keep `requirements-dev.txt` patched so the audit coverage stays accurate.

## Development quick-start

```bash
pip install -U pip
pip install -r requirements-dev.txt
ruff check .
pytest
bandit -r exfiliator_client.py exfiliator_server.py -ll
pip-audit --strict -r requirements-dev.txt
```
