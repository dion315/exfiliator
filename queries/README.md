# Detection Query Bundles

This directory contains copy/paste-ready hunting queries that highlight the typical indicators left behind by Exfiliator test runs (e.g., Python client processes talking to unusual ports, HTTP uploads to `/upload`, DNS lookups carrying PSK labels, etc.). Update the placeholder parameters (devices, time ranges, test ports) so they match your lab.

| File | Platform / SIEM | Notes |
| --- | --- | --- |
| `bundle-defender.kql` | Microsoft Defender Advanced Hunting | Uses `DeviceNetworkEvents` / `DeviceProcessEvents`. |
| `bundle-sentinel.kql` | Microsoft Sentinel (Log Analytics) | Works with MDE tables, Windows Security Events, CommonSecurityLog, AzureDiagnostics. |
| `bundle-adx-datalake.kql` | Azure Data Explorer / Data Lake | Focuses on raw network/process tables stored in ADX. |
| `bundle-exabeam.dsl` | Exabeam Data Lake / Fusion SIEM | Filters `dataset=network` and `dataset=process`. |
| `bundle-logrhythm.sql` | LogRhythm LogMart / NDR | Highlights normalized events via `CommonEvent` fields. |
| `bundle-splunk.spl` | Splunk Enterprise / ES | SPL searches against `tstats` + raw indexes. |
| `bundle-qradar.aql` | IBM QRadar | Native AQL query referencing `events` table. |
| `bundle-wazuh-elastic.esql` | Wazuh (Elastic stack) | ES|QL query that pivots `wazuh-alerts-*` ECS fields. |
| `bundle-security-onion.esql` | Security Onion / Elastic SIEM | ES|QL search against `so-*` indices. |

Each query bundle follows the same structure:

1. **Parameter block** — edit `TestPorts`, hostnames, or process names once at the top.
2. **Core detection logic** — trace outbound TCP/UDP/DNS/HTTP interactions tied to your Exfiliator run.
3. **Contextual pivots** — (where supported) join process creation, firewall, or IDS tables so you can quickly triage.

Feel free to copy any of these into your SOC playbooks or extend them with additional filters that map to your environment’s field names. If your SIEM is not listed, `bundle-splunk.spl` and `bundle-wazuh-elastic.esql` are good generic references for building detections on top of Elastic/Common Event Format data.
