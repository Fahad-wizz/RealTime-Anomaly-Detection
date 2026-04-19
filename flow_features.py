from collections import defaultdict
import time

FLOW_TIMEOUT = 5
MIN_PACKETS_FOR_CLASSIFICATION = 5


def _new_flow():
    now = time.time()
    return {
        "src": "N/A",
        "dst": "N/A",
        "proto": "Unknown",
        "start": now,
        "last": now,
        "packet_count": 0,
        "byte_count": 0,
    }


flows = defaultdict(_new_flow)


def get_flow_key(pkt):
    return (
        pkt.get("src"),
        pkt.get("dst"),
        pkt.get("proto"),
        pkt.get("dport"),   # 🔥 add this back
    )


def update_flow(pkt):
    key = get_flow_key(pkt)
    flow = flows[key]

    pkt_time = float(pkt.get("timestamp", time.time()))
    pkt_len = float(pkt.get("length", 0) or 0)

    # initialize only once
    if flow["packet_count"] == 0:
        flow["src"] = pkt.get("src", "N/A")
        flow["dst"] = pkt.get("dst", "N/A")
        flow["proto"] = pkt.get("proto", "Unknown")
        flow["start"] = pkt_time

    flow["packet_count"] += 1
    flow["byte_count"] += pkt_len
    flow["last"] = pkt_time

    return key, flow


def extract_features(flow):
    duration = max(flow["last"] - flow["start"], 0.001)

    packet_rate = flow["packet_count"] / duration
    byte_rate = flow["byte_count"] / duration

    # 🔥 CLIP EXTREME VALUES (VERY IMPORTANT)
    packet_rate = min(packet_rate, 1e6)
    byte_rate = min(byte_rate, 1e8)

    return {
        "packet_count": flow["packet_count"],
        "byte_count": flow["byte_count"],
        "duration": duration,
        "packet_rate": packet_rate,
        "byte_rate": byte_rate,
    }


def is_flow_ready(flow):
    inactive_time = time.time() - flow["last"]

    return (
        flow["packet_count"] >= MIN_PACKETS_FOR_CLASSIFICATION
        or inactive_time > FLOW_TIMEOUT
    )