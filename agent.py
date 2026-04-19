import requests
import time
import threading

from sniffer import packet_queue, start_sniffing
import flow_features

SERVER_URL = "https://realtime-anomaly-detection.onrender.com/api/ingest"

BATCH_SIZE = 5
batch = []

print("Starting agent...")

# ✅ Run sniffer in background thread
threading.Thread(target=start_sniffing, daemon=True).start()

def send_batch(batch_data):
    for attempt in range(3):  # retry logic
        try:
            res = requests.post(SERVER_URL, json=batch_data, timeout=5)
            print(f"Sent batch ({len(batch_data)}) →", res.json())
            return True
        except Exception as e:
            print("Retrying...", e)
            time.sleep(1)
    return False


while True:
    # ✅ BLOCKING queue (no CPU waste)
    data = packet_queue.get()

    key, flow = flow_features.update_flow(data)

    if not flow_features.is_flow_ready(flow):
        continue

    feature_row = flow_features.extract_features(flow)

    # ✅ attach metadata (IMPORTANT)
    feature_row["src"] = data.get("src")
    feature_row["dst"] = data.get("dst")
    feature_row["proto"] = data.get("proto")

    batch.append(feature_row)

    # ✅ batch send
    if len(batch) >= BATCH_SIZE:
        send_batch(batch)
        batch.clear()

    # cleanup
    flow_features.flows.pop(key, None)

    time.sleep(0.01)  # small throttle