# ======================================================
# Exfiliator - Exabeam Data Lake / Fusion SIEM
# Paste into Event Search (Data Lake) or Timeline Search.
# ======================================================

# ---------- PARAMETERS ----------
LET start_time = NOW() - INTERVAL 24 HOUR;
LET end_time = NOW();
LET asset_name = "REPLACE-HOSTNAME";
LET test_ports = (5001, 5002, 8080, 8443);
LET proc_names = ("python.exe", "python3.exe", "python");

# ---------- 1) Network telemetry tied to python ----------
dataset = network
| filter timestamp BETWEEN start_time AND end_time
| filter asset IN (asset_name)
| filter destination_port IN test_ports OR url CONTAINS "/upload"
| filter LOWER(parent_process_name) IN proc_names OR LOWER(process_name) IN proc_names
| stats event_count = COUNT(),
        first_seen = MIN(timestamp),
        last_seen = MAX(timestamp),
        sample_cmd = ANY(command_line),
        dest_ips = VALUES(destination_ip)
        BY protocol, destination_port, destination_ip;

# ---------- 2) DNS lookups with embedded PSK ----------
dataset = dns
| filter timestamp BETWEEN start_time AND end_time
| filter asset IN (asset_name)
| filter LOWER(query) CONTAINS "psk-"
| stats dns_hits = COUNT(), first_seen = MIN(timestamp), last_seen = MAX(timestamp)
        BY query, query_type, answer;

# ---------- 3) Process creation context ----------
dataset = process
| filter timestamp BETWEEN start_time AND end_time
| filter asset IN (asset_name)
| filter LOWER(process_name) IN proc_names
| fields timestamp, asset, username, process_name, process_id, parent_process_name, parent_process_id, command_line
| sort timestamp DESC;

# ---------- 4) HTTP POST visibility (if proxy/firewall logs ingested) ----------
dataset = proxy
| filter timestamp BETWEEN start_time AND end_time
| filter action = "allowed"
| filter destination_port IN (80, 8080, 443, 8443)
| filter url CONTAINS "/upload"
| fields timestamp, source_ip, destination_ip, destination_port, http_method, url, bytes_out;
