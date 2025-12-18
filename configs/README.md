# Example Configurations

These JSON files illustrate common Exfiliator test layouts. Copy them and adjust hosts, ports, and payload sizes for your own environments.

> **Safety reminder:** Only run Exfiliator in environments you own or have authorization to test. Never commit PSKs or real report artifacts.

## Files

- `basic_local.json` – Minimal single-host test that relies on `--server` to fill in missing TCP/UDP hosts. Good for loopback/lab smoke runs.
- `hybrid_lab.json` – Demonstrates mixing specific hosts, different UDP modes, and HTTP uploads targeting a separate listener.

## Usage

1. Start the server with the ports referenced in the config. Example:
   ```bash
   python3 exfiliator_server.py --tcp-ports 5001,8443 --udp-ports 5002,6001 --http-port 8080
   ```
2. Run the client with the desired config (supply PSK as appropriate). You can reference files in this folder by filename only; the client resolves them automatically:
  ```bash
  python3 exfiliator_client.py \
    --config configs/basic_local.json \
    --psk my-shared-secret \
     --server 127.0.0.1 \
     --allow-udp-modes reliable,batched_ack
   ```

Feel free to create additional variants (different payload sizes, rate limits, UDP policies) inside this folder for your team. Combine these configs with the client's `--port-filter` flag if you want to target only certain ports or ranges without editing the files.
