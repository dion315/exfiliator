
---

# `CONTRIBUTING.md`

```markdown
# Contributing Guidelines (Internal)

This repository is intended for **authorized internal purple-team / security engineering use**.

## Who Can Contribute
- Security Engineering
- Purple Team
- Network Security
- Approved AppSec engineers

## Contribution Rules

### ✅ Allowed
- Detection improvements (queries, reports, telemetry guidance)
- Reporting enhancements (HTML/JSON outputs, summaries)
- Safety guardrails (allowlist enforcement, rate limits, PSK improvements)
- Documentation updates
- Test coverage expansion (more ports/protocols in configs; still synthetic payloads)

### ❌ Not Allowed
- Real data access (reading files, credentials, secrets beyond PSK bootstrap)
- Covert exfiltration techniques (ICMP/DNS tunneling, steganography, etc.)
- Obfuscation or encryption intended to bypass inspection
- Persistence, lateral movement, or malware-like behaviors

## Coding Standards
- Python standard library only (unless explicitly approved)
- Clear logs and deterministic behavior
- Defensive defaults (safe caps; explicit allowlists)
- “Audit-friendly” changes: explain what it tests and why

## Review Requirements
All changes must be reviewed by:
- Security Engineering + Purple Team lead

## Authorization Reminder
Do not run this tool outside environments where you own the system or have explicit authorization.

## Questions
Contact: Security Engineering / Purple Team
