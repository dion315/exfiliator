# Architecture

Exfiliator is a PSK-gated, synthetic-data client/server pair used to test network egress/ingress controls and generate a human-readable HTML report.

The system is intentionally simple:
- No file-reading “exfil” behavior (synthetic random bytes only)
- No covert channels, obfuscation, or evasion logic
- Explicit allowlist config and explicit runtime options

---

## Components

### 1) Client (`exfiliator_client.py`)
Primary responsibilities:
- Load allowlisted tests from JSON config
- Apply run-time targeting policy:
  - `--server` sets default host for TCP/UDP/Telnet/SMTP entries missing `host` (default `127.0.0.1`)
  - `--force-server` overrides all TCP/UDP/Telnet/SMTP `host` values for the run
- Apply UDP mode policy:
  - `--allow-udp-modes` (allowlist)
  - `--udp-mode-override` (force)
- Execute tests:
  - TCP: connect → send JSON header (PSK + bytes) → send payload → read JSON response
  - UDP: HELLO (PSK + mode) → send DATA packets → optional ACK handling depending on mode
  - HTTP: POST /upload with `X-PSK` + synthetic payload → parse response (plus optional `/download` validation when mock-sensitive mode is enabled)
  - DNS: craft PSK-tagged queries (`psk-...`) to prove reachability and, optionally, replay mock-sensitive labels
  - Telnet: emulate username/password prompts and PSK challenge before running scripted commands
  - SMTP: speak a minimal AUTH PSK + DATA workflow to look like legitimate SMTP traffic
- Mock sensitive workflow (`--test-mock-sensitive-data`):
  - Replays successful channels for TCP/UDP/HTTP/DNS/Telnet/SMTP
  - Attempts base payload and base64-obfuscated fallback
  - For HTTP, also attempts `/download` pull to validate inbound controls
- User experience:
  - Progress bars (no third-party deps)
  - Verbose logging (-v/-vv)
  - Press `Q` to quit gracefully and still write report
- Output:
  - JSON summary to stdout
  - HTML report:
    - Timestamped file name by default
    - Includes client host/device info and best-effort network info
    - Includes server arg used and target summary (supports a mix of IPs, hostnames, URLs)

### 2) Server (`exfiliator_server.py`)
Primary responsibilities:
- Generate a PSK each run (or load via `--psk` / `--psk-file`)
- Listen on configured ports:
  - TCP: per-port listener threads
  - UDP: per-port listener threads with HELLO auth
  - HTTP: optional `POST /upload` (+ `/download` when mock download is enabled)
  - DNS: optional UDP responders that validate PSK embedded in the query labels
  - Telnet: optional TCP workers that emulate login/command shells with PSK prompt
  - SMTP: optional TCP workers that perform AUTH PSK and accept DATA payloads
- Authenticate:
  - TCP: expects JSON header with PSK
  - UDP: expects HELLO JSON with PSK; ignores unauthenticated DATA
  - HTTP: expects header `X-PSK`
  - DNS: second label must be `psk-...` matching the active PSK
  - Telnet: interactive prompts require PSK before accepting commands
  - SMTP: custom `AUTH PSK <value>` handshake
- Compute minimal metrics:
  - Counts bytes received (does not persist payload)
  - Responds with JSON status objects or emulated command output summaries

### 3) Optional: Windows Firewall Helper (server-side)
If enabled, the server can temporarily open inbound firewall ports on Windows:
- `--manage-firewall`: creates inbound allow rules for configured TCP/UDP/HTTP/DNS/Telnet/SMTP ports
- `--firewall-dry-run`: prints the exact PowerShell commands and planned rules without changing firewall
- Cleanup:
  - Removes only the rules created by that server instance (unique display names)
  - Cleanup runs on normal exit and Ctrl+C (best effort)

Limitations:
- Only affects local Windows Defender Firewall on the server host
- Does not modify upstream network ACLs/firewalls/NAT
- May be blocked/overridden by Group Policy

---

## Data flows

### TCP flow (high level)
1. Client connects to `host:port`
2. Client sends one JSON line: `{test_id, bytes, psk}`
3. Client sends `bytes` synthetic payload
4. Server responds with JSON `{ok, bytes_received, test_id}`

### UDP flow (high level)
1. Client sends `HELLO {test_id, psk, udp_mode, ack_every}`
2. Server replies `HELLO_ACK` if PSK matches
3. Client sends `DATA <seq> <payload>` packets
4. ACK strategy depends on `udp_mode`:
   - `reliable`: server ACKs each seq
   - `batched_ack`: server sends ACK ranges periodically
   - `firehose`: server sends no DATA ACKs (fastest)

### HTTP flow (high level)
1. Client POSTs synthetic payload to `/upload`
2. Client includes headers `X-PSK` and `X-Test-Id`
3. Server responds JSON with `{ok, bytes_received, test_id}`
4. If `--enable-mock-download` is set and mock testing is enabled, client issues `GET /download` with `X-PSK` to confirm inbound controls

### DNS flow (high level)
1. Client builds qname `<test>-<psk>.base_qname` (plus optional mock-sensitive labels)
2. DNS listener parses labels, validates PSK, and returns synthetic record matching requested type (A/AAAA/TXT)
3. Client parses response and records success/failure

### Telnet flow (high level)
1. Client connects to Telnet port, receives banner, and sends username/password
2. Server prompts for PSK; commands only execute after a match
3. Client runs scripted commands and (when mock-sensitive enabled) sends `DATA`/`OBF` lines
4. Server echoes responses and closes session on `EXIT`

### SMTP flow (high level)
1. Client connects, receives `220`, issues `EHLO`, then `AUTH PSK <value>`
2. Server responds `235` on success; client sends `MAIL FROM` / `RCPT TO`
3. Client sends `DATA` payload (base message, then mock-sensitive/obfuscated messages when enabled)
4. Server acknowledges each message (`250`), client issues `QUIT`

---

## Architecture diagram (Mermaid)

```mermaid
flowchart LR
  C[Client<br/>exfiliator_client.py] -->|TCP connect + JSON header + payload| STCP[(TCP listener(s))]
  C -->|UDP HELLO + DATA packets| SUDP[(UDP listener(s))]
  C -->|HTTP POST /upload + X-PSK| SHTTP[(HTTP server)]
  C -->|DNS query with PSK label| SDNS[(DNS responder)]
  C -->|Telnet banner + commands| STEL[(Telnet emulator)]
  C -->|SMTP AUTH PSK + DATA| SSMTP[(SMTP emulator)]

  subgraph ServerHost[Server Host<br/>exfiliator_server.py]
    STCP
    SUDP
    SHTTP
    SDNS
    STEL
    SSMTP
    FW[Optional: Windows Firewall Helper<br/>--manage-firewall / --firewall-dry-run]
  end

  FW -.->|Create temp inbound rules (Windows only)| ServerHost
  FW -.->|Cleanup rules on exit| ServerHost

  C --> R[HTML Report + JSON Summary]
