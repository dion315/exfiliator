# Threat Model & MITRE ATT&CK Mapping

This tool **does not implement real attacks**. It models **behaviors** associated with outbound data transfer to validate controls and telemetry.

## Scope

**Primary tactic:** Exfiltration (TA0010)  
**Secondary (behavioral):** Command and Control (TA0011) for application-layer protocol visibility

## ATT&CK Coverage Table

| ATT&CK Tactic | Technique | Sub-Technique | What we simulate | Protocols | Primary controls validated | Notes / limits |
|---|---|---|---|---|---|---|
| Exfiltration (TA0010) | Exfiltration Over C2 Channel (T1041) | N/A | Generic outbound data transfer to a listener | TCP, HTTP | Egress rules, proxy enforcement, endpoint network protection, visibility | Behavioral only; no C2 framework or evasion |
| Exfiltration (TA0010) | Exfiltration Over Alternative Protocol (T1048) | T1048.003 | Alternative transport over non-standard ports / datagrams | UDP, TCP | ACL/firewall enforcement, IDS/IPS anomaly detection, endpoint telemetry | UDP attribution is ambiguous by nature |
| Command and Control (TA0011) | Application Layer Protocol (T1071) | N/A | Application-layer POST to a controlled endpoint | HTTP | Proxy/DLP/CASB visibility, app-layer auth, policy enforcement | No TLS emulation unless you explicitly add it |

## What This Tool Explicitly Does NOT Do

- No real file access or data harvesting
- No covert channels (ICMP/DNS tunneling)
- No obfuscation/encryption intended to evade inspection
- No persistence or lateral movement

## Purple Team Questions This Answers

- Can traffic leave on these ports/protocols?
- Are blocks enforced at endpoint, server, or network?
- Do we see consistent telemetry in Defender/Sentinel/Data Lake?
- Do our alerts fire and do they contain actionable context?
