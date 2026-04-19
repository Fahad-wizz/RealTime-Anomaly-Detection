import requests
import time

from sniffer import packet_queue, start_sniffing
import flow_features

SERVER_URL = "https://realtime-anomaly-detection.onrender.com/api/ingest"

print("Starting local sniffer agent...")
start_sniffing()

while True:
    if packet_queue.empty():
        time.sleep(0.2)
        continue

    data = packet_queue.get()

    key, flow = flow_features.update_flow(data)

    if not flow_features.is_flow_ready(flow):
        continue

    feature_row = flow_features.extract_features(flow)

    # 🔥 Add metadata (IMPORTANT for your dashboard)
    feature_row["src"] = data.get("src")
    feature_row["dst"] = data.get("dst")
    feature_row["proto"] = data.get("proto")

    try:
        res = requests.post(SERVER_URL, json=feature_row, timeout=5)
        print("Sent:", feature_row)
        print("Response:", res.json())
    except Exception as e:
        print("Error sending:", e)

    # cleanup
    flow_features.flows.pop(key, None)