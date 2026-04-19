// ================= GLOBAL STATE =================

let total = 0;
let attacks = 0;
let normal = 0;

let attackId = null;
let lastTimestamp = null;
let isFetching = false;


// ================= LIVE DATA FETCH =================

async function fetchLiveData() {

    if (isFetching) return; // prevent overlap
    isFetching = true;

    try {
        const res = await fetch(`/api/live-data?since=${lastTimestamp || ""}`);
        const data = await res.json();

        if (data && data.length > 0) {

            data.forEach(entry => {

                total++;

                if (entry.prediction === "ATTACK") {
                    attacks++;
                } else {
                    normal++;
                }

                updateStats();
                addRow(entry);

                lastTimestamp = entry.timestamp;
            });
        }

    } catch (err) {
        console.error("Live data fetch error:", err);
    }

    isFetching = false;
}


// ================= UPDATE STATS =================

function updateStats() {
    document.getElementById("totalPackets").innerText = total;
    document.getElementById("attackCount").innerText = attacks;
    document.getElementById("normalCount").innerText = normal;
}


// ================= ADD TABLE ROW =================

function addRow(data) {

    const table = document.getElementById("liveTable");

    const row = document.createElement("tr");

    row.innerHTML = `
        <td>${new Date(data.timestamp * 1000).toLocaleTimeString()}</td>
        <td>${data.src}</td>
        <td>
            <span class="badge ${data.prediction === "ATTACK" ? "bg-danger" : "bg-success"}">
                ${data.prediction}
            </span>
        </td>
        <td>${data.attack_type || "-"}</td>
        <td>${data.confidence || 0}%</td>
    `;

    table.prepend(row);

    // Limit rows for performance
    if (table.children.length > 100) {
        table.removeChild(table.lastChild);
    }
}


// ================= START ATTACK =================

async function startAttack() {

    const ip = document.getElementById("targetIp").value.trim();
    const port = document.getElementById("targetPort").value;
    const duration = document.getElementById("duration").value;
    const rate = document.getElementById("rate").value;

    if (!ip) {
        alert("Enter target IP / domain");
        return;
    }

    try {

        setStatus("Starting...");

        const res = await fetch("/attack/start", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({
                type: "dos",
                ip: ip,
                port: port,
                duration: duration,
                rate: rate
            })
        });

        const data = await res.json();

        if (!data.attack_id) {
            setStatus("Failed to start");
            return;
        }

        attackId = data.attack_id;

        setStatus("Running");

        trackAttackStatus();

    } catch (err) {
        console.error("Start attack error:", err);
        setStatus("Error");
    }
}


// ================= TRACK ATTACK =================

async function trackAttackStatus() {

    if (!attackId) return;

    try {

        const res = await fetch(`/attack/status/${attackId}`);
        const data = await res.json();

        document.getElementById("packetsSent").innerText =
            data.packets_sent || 0;

        if (data.running) {
            setTimeout(trackAttackStatus, 2000);
        } else {
            setStatus("Stopped");
        }

    } catch (err) {
        console.error("Status error:", err);
        setStatus("Error");
    }
}


// ================= STOP ATTACK =================

async function stopAttack() {

    if (!attackId) return;

    try {

        setStatus("Stopping...");

        await fetch("/attack/stop", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ attack_id: attackId })
        });

    } catch (err) {
        console.error("Stop attack error:", err);
        setStatus("Error");
    }
}


// ================= STATUS HELPER =================

function setStatus(text) {
    document.getElementById("attackStatus").innerText = text;
}


// ================= OPTIONAL: AUTO BOOST =================

function autoBoost() {

    const rateInput = document.getElementById("rate");

    let currentRate = parseInt(rateInput.value || 100);

    currentRate += 50;

    rateInput.value = currentRate;

    startAttack();
}


// ================= INIT =================

// Poll every 2 seconds
setInterval(fetchLiveData, 2000);