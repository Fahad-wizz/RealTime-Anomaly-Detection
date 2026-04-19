import time
from queue import Queue
from scapy.all import sniff, TCP, UDP, ICMP, IP

packet_queue = Queue(maxsize=10000)  # prevent memory overflow


# ---------------- PROTOCOL DETECTION ---------------- #

def detect_protocol(packet):
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    elif packet.haslayer(IP):
        return str(packet[IP].proto)
    return "Unknown"


# ---------------- PACKET PROCESSING ---------------- #

def process_packet(packet):
    try:
        if not packet.haslayer(IP):
            return  # ignore non-IP traffic

        ip_layer = packet[IP]

        src = ip_layer.src
        dst = ip_layer.dst

        proto = detect_protocol(packet)

        # Extract ports safely
        sport = 0
        dport = 0

        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport

        data = {
            "src": src,
            "dst": dst,
            "sport": sport,
            "dport": dport,
            "proto": proto,
            "length": len(packet),
            "timestamp": float(getattr(packet, "time", time.time())),
        }

        # Prevent queue overflow
        if not packet_queue.full():
            packet_queue.put(data)

    except Exception:
        pass


# ---------------- START SNIFFER ---------------- #

def start_sniffing():
    sniff(
        prn=process_packet,
        store=False,
        filter="ip",   # 🔥 capture only IP traffic
    )