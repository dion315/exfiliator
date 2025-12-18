# Threat Model

Exfiliator is a **purple-team network control testing tool** that generates **synthetic traffic** (TCP/UDP/HTTP/DNS/Telnet/SMTP) and produces a timestamped HTML report.

**Design intent:** validate network controls and telemetry safely using explicit allowlists and a PSK.
**Non-goals:** covert channels, evasion, persistence, privilege escalation, or data theft.

---

## Scope

### In scope
- Client/server traffic generation for TCP/UDP/HTTP/DNS/Telnet/SMTP
- Authentication/authorization via **pre-shared key (PSK)**
- Run controls:
  - `--server` default host for TCP/UDP entries missing `host` (default `127.0.0.1`)
  - `--force-server` override all TCP/UDP hosts for a run
  - UDP policy allowlist/override
  - Quit monitor (`Q`) and partial reporting
- HTML report generation:
  - Timestamped filename by default
  - Includes client host/device info + best-effort network info
  - Includes server arg used and targets summary
- Optional server-side Windows Firewall automation:
  - `--manage-firewall` (apply) and `--firewall-dry-run`

### Out of scope
- Bypassing security controls
- Covert channels (DNS/ICMP tunneling, stego, etc.)
- Credential theft, privilege escalation, lateral movement
- Target discovery/scanning beyond the explicit allowlist config

---

## Assets

- **PSK**: shared secret gating use of server endpoints (generated each run unless explicitly provided)
- **HTML reports / JSON output**: may contain environment identifiers (hostnames, IPs, command outputs if enabled)
- **Server firewall state** (Windows helper): temporary inbound rules may expand exposure if misconfigured

---

## Trust boundaries

1. **Client host** (endpoint under test)
2. **Network path** (routing, proxies, IDS/IPS, ACLs, NAT)
3. **Server host** (listeners and optional HTTP endpoint)
4. **Server local firewall config** (optional change via `--manage-firewall`)

---

## Key risks and mitigations

### 1) Unauthorized use of server listeners
**Threat:** A third party uses the server as a transfer endpoint.

**Mitigations:**
- PSK required for every protocol (TCP/UDP/HTTP/DNS/Telnet/SMTP)
- UDP ignores unauthenticated DATA (must pass HELLO with PSK)
- DNS rejects queries whose labels do not contain the current PSK
- Telnet/SMTP handlers refuse to proceed until PSK step succeeds
- Operational guardrails:
  - bind to limited interfaces where possible
  - restrict firewall scope (default `LocalSubnet`)
  - rotate PSK, store securely, do not commit

**Residual risk:** PSK compromise enables misuse.

---

### 2) Firewall automation expands attack surface
**Threat:** `--manage-firewall` opens ports wider than intended (e.g., RemoteAddress=Any), exposing listeners.

**Mitigations:**
- Firewall automation is opt-in
- Default firewall scope is `LocalSubnet`
- Dry-run mode prints planned rules and PowerShell commands without changes (`--firewall-dry-run`)
- Rules are unique per instance and removed on exit (best effort)

**Residual risk:** If terminated abruptly or if cleanup cannot run with admin, rules may persist. Validate post-run.

---

### 3) Report leakage / environment disclosure
**Threat:** HTML report reveals sensitive environment details (hostname, IPs, routes, firewall profiles).

**Mitigations:**
- Command output capture is **opt-in** (`--include-network-commands`)
- Reports are timestamped (reduces accidental overwrite and helps audit)
- Operational: store reports in controlled locations; avoid attaching externally

**Residual risk:** human handling errors.

---

### 4) Misinterpretation of “blocked vs refused”
**Threat:** Users misread outcomes (e.g., `NO_LISTENER` vs `BLOCKED_OR_DROPPED`).

**Mitigations:**
- Best-effort inference strings included in report
- Encourage paired validation:
  - confirm server is listening
  - compare with/without server firewall helper
  - test from multiple vantage points

**Residual risk:** middleboxes can mimic/reset/drop in ways that are hard to attribute definitively.

---

### 5) Performance / DoS / noise generation
**Threat:** Large payloads/high UDP packet rates impact networks or endpoints; `firehose` can be particularly noisy.

**Mitigations:**
- Explicit allowlist config for bytes/packets/rates
- Quit monitor supports abort while still producing report
- UDP modes let you trade speed vs confirmation signal:
  - `reliable` (slow, confirmation-heavy)
  - `batched_ack` (balanced)
  - `firehose` (fast, minimal feedback)

**Residual risk:** misconfiguration can still cause congestion. Use sensible sizing and schedule appropriately.

---

## ATT&CK mapping (defensive/purple-team context)

These mappings are for **coverage/telemetry validation**. Exfiliator is not intended to provide stealth or evasion.

| Test/Behavior | Validates | ATT&CK technique (example) |
|---|---|---|
| TCP synthetic upload to arbitrary port | Egress filtering, IDS/IPS/flow logs, proxy/firewall behavior | Application Layer Protocol, Exfiltration Over Alternative Protocol (TCP) |
| UDP synthetic packets (`reliable/batched/firehose`) | UDP egress controls, drops vs rejects, flow logs, IDS alerts | Exfiltration Over Alternative Protocol (UDP) |
| HTTP POST `/upload` + optional `/download` | Web proxy controls, URL filtering, HTTP telemetry, inbound restrictions | Exfiltration Over Web Service / Application Layer Protocol (HTTP) |
| DNS queries embedding PSK/mock labels | DNS egress controls, RPZ/filtering, DLP tuned to DNS labels | Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol, DNS |
| Telnet “looks like” traffic with mock payload | Legacy/OT protocol monitoring, NAC policy coverage, proxy alerts | Application Layer Protocol (Telnet), Exfiltration Over Unencrypted/Obfuscated Channel |
| SMTP AUTH + DATA uploads | Email egress monitoring, DLP policy, MTA controls | Exfiltration Over Unencrypted/Obfuscated Channel / Application Layer Protocol (SMTP) |

> Choose the specific ATT&CK technique labels used by your org’s mapping standard; many teams map these at a higher level (“Exfiltration Over Alternative Protocol” / “Application Layer Protocol”) depending on fidelity.

---

## Operational guardrails

- Use only **synthetic data** (no file reads)
- Keep PSK secure; rotate frequently and avoid persisting it unless necessary
- Prefer constrained listener binding and firewall remote scope
- Store/share reports appropriately; avoid committing reports
- Use firewall dry-run for review/change control when needed
- Validate post-run:
  - server listeners stopped
  - temporary firewall rules removed (if applied)
