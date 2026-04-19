import requests
import time
import threading

from sniffer import packet_queue, start_sniffing
import flow_features

SERVER_URL = "https://realtime-anomaly-detection.onrender.com/api/ingest"

BATCH_SIZE = 5
BATCH_TIMEOUT = 1  # seconds

batch = []
last_send_time = time.time()

print("🚀 Starting agent...")

# ================= START SNIFFER =================
threading.Thread(target=start_sniffing, daemon=True).start()

def heartbeat():
    while True:
        try:
            requests.post(SERVER_URL, json={"heartbeat": True}, timeout=2)
        except:
            pass
        time.sleep(2)

# start it
threading.Thread(target=heartbeat, daemon=True).start()
# ================= SEND FUNCTION =================
def send_batch(batch_data):
    for attempt in range(3):
        try:
            res = requests.post(SERVER_URL, json=batch_data, timeout=3)
            print(f"✅ Sent batch ({len(batch_data)}) →", res.json())
            return True
        except Exception as e:
            print(f"⚠️ Retry {attempt+1}/3:", e)
            time.sleep(1)
    return False


# ================= MAIN LOOP =================
while True:
    data = packet_queue.get()

    key, flow = flow_features.update_flow(data)

    packet_count = flow.get("packet_count", 0)
    duration = max(flow["last"] - flow["start"], 0.001)
    # 🔥 DEBUG: Flow growth
    print(f"📈 Flow [{key}] packets = {packet_count}")

    # ================= FLOW TRIGGER =================
    # Only process when flow is meaningful
    if packet_count < 30:
        continue
    if duration < 0.5: 
        continue

    # ================= FEATURE EXTRACTION =================
    feature_row = flow_features.extract_features(flow)

    print("🧠 FEATURE:", feature_row)

    # ================= METADATA =================
    feature_row["src"] = data.get("src")
    feature_row["dst"] = data.get("dst")
    feature_row["proto"] = data.get("proto")

    batch.append(feature_row)

    now = time.time()

    # ================= BATCH SEND =================
    if len(batch) >= BATCH_SIZE or (now - last_send_time) >= BATCH_TIMEOUT:
        send_batch(batch)
        batch.clear()
        last_send_time = now

    # ================= SAFE CLEANUP =================
    # Instead of deleting immediately, only clear VERY large flows
    if packet_count > 200:
        flow_features.flows.pop(key, None)
        print(f"🧹 Flow {key} cleared after large accumulation")