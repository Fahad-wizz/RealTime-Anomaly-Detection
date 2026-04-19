from collections import defaultdict
from threading import Lock


stats = {
    "total": 0,
    "threats": 0,
    "normal": 0,
}

ip_threats = defaultdict(int)
recent_alerts = []
metrics_lock = Lock()


def update_metrics(packet, prediction, attack_type="Anomaly"):
    with metrics_lock:
        stats["total"] += 1

        if prediction == -1:
            stats["threats"] += 1
            src = packet.get("src", "Unknown")
            ip_threats[src] += 1

            recent_alerts.append(
                {
                    "src": src,
                    "dst": packet.get("dst", "Unknown"),
                    "proto": packet.get("proto", "Unknown"),
                    "type": attack_type or "Anomaly",
                }
            )

            if len(recent_alerts) > 10:
                del recent_alerts[0]
        else:
            stats["normal"] += 1


def get_metrics():
    with metrics_lock:
        top_ip = max(ip_threats, key=ip_threats.get, default="-")
        return {
            "total": stats["total"],
            "threats": stats["threats"],
            "normal": stats["normal"],
            "top_ip": top_ip,
            "alerts": list(recent_alerts),
        }
