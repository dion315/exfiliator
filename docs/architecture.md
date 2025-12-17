# Architecture Overview

This tool uses a **client/server model** to exercise network paths and controls using **synthetic data only**.

## Diagram (Mermaid)

```mermaid
flowchart LR
  subgraph Client["exfiliator_client.py (Endpoint Under Test)"]
    C1["Reads JSON allowlist config"]
    C2["Loads PSK (file or arg)"]
    C3["Generates synthetic payloads (in-memory)"]
    C4["Runs tests: TCP / UDP / HTTP"]
    C5["Classifies outcomes + writes HTML report"]
  end

  subgraph Server["exfiliator_server.py (Target Listener)"]
    S1["Generates/loads PSK (pt_psk.txt)"]
    S2["TCP listeners (configured ports)"]
    S3["UDP listeners (configured ports)"]
    S4["HTTP /upload (optional)"]
    S5["Auth checks (PSK) + minimal responses"]
  end

  C1 --> C4
  C2 --> C4
  C3 --> C4
  C4 -->|TCP connect + payload| S2
  C4 -->|UDP HELLO+DATA + ACKs| S3
  C4 -->|HTTP POST /upload| S4
  S1 --> S2
  S1 --> S3
  S1 --> S4
  S2 -->|JSON line response| C4
  S3 -->|ACK packets| C4
  S4 -->|HTTP 200/401| C4
  C4 --> C5
