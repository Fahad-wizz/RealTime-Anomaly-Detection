import requests
import time

from sniffer import packet_queue, start_sniffing
import flow_features

SERVER_URL = "https://realtime-anomaly-detection.onrender.com/api/ingest"

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

    # 🔥 Attach metadata
    feature_row["src"] = data.get("src")
    feature_row["dst"] = data.get("dst")
    feature_row["proto"] = data.get("proto")

    try:
        requests.post(SERVER_URL, json=feature_row, timeout=3)
    except:
        pass

    flow_features.flows.pop(key, None)