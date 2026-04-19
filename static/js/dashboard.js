(() => {
    const metricsNode = document.getElementById("dashboardMetrics");
    const trafficCanvas = document.getElementById("trafficChart");
    const attackCanvas = document.getElementById("attackChart");
    const alertsNode = document.getElementById("alerts");

    if (!metricsNode || !trafficCanvas || !attackCanvas || typeof Chart === "undefined") {
        return;
    }

    const initialMetrics = JSON.parse(metricsNode.textContent || "{}");
    const maxPoints = 10;
    const maxAlerts = 10;
    const css = getComputedStyle(document.documentElement);
    const colors = {
        text: css.getPropertyValue("--text").trim(),
        muted: css.getPropertyValue("--muted").trim(),
        accentStrong: "#0ea5e9",
        danger: "#fb7185",
        success: "#22c55e",
    };

    function updateStatus(isActive) {
    const node = document.getElementById("agentStatus");

    if (!node) return;

    if (isActive) {
        node.textContent = "Agent Active";
        node.style.color = "limegreen";
    } else {
        node.textContent = "Agent Offline";
        node.style.color = "red";
    }
}

    function chartDefaults() {
        return {
            plugins: {
                legend: {
                    labels: {
                        color: colors.text,
                    },
                },
            },
            scales: {
                x: {
                    ticks: { color: colors.muted },
                    grid: { color: "rgba(148, 163, 184, 0.08)" },
                },
                y: {
                    ticks: { color: colors.muted },
                    grid: { color: "rgba(148, 163, 184, 0.08)" },
                },
            },
        };
    }

    const trafficChart = new Chart(trafficCanvas, {
        type: "line",
        data: {
            labels: [],
            datasets: [
                {
                    label: "Traffic",
                    data: [],
                    borderColor: colors.accentStrong,
                    backgroundColor: "rgba(14, 165, 233, 0.16)",
                    fill: true,
                    tension: 0.35,
                },
                {
                    label: "Threats",
                    data: [],
                    borderColor: colors.danger,
                    backgroundColor: "rgba(251, 113, 133, 0.14)",
                    fill: true,
                    tension: 0.35,
                },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            ...chartDefaults(),
        },
    });

    const attackChart = new Chart(attackCanvas, {
        type: "doughnut",
        data: {
            labels: ["Normal", "Threats"],
            datasets: [{
                data: [initialMetrics.normal || 0, initialMetrics.threats || 0],
                backgroundColor: [colors.success, colors.danger],
                borderWidth: 2,
                borderColor: "rgba(7, 17, 31, 0.15)",
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: "bottom",
                    labels: { color: colors.text, padding: 16 },
                },
            },
        },
    });

    function setText(id, value) {
        const node = document.getElementById(id);
        if (node) node.textContent = value;
    }

    function renderAlerts(alerts) {
        if (!alertsNode) return;

        if (!alerts || !alerts.length) {
            alertsNode.innerHTML = `
                <div class="empty-state">
                    <i class="fa-solid fa-wave-square"></i>
                    <p>No alerts yet. Live detections will appear here.</p>
                </div>
            `;
            return;
        }

        alertsNode.innerHTML = alerts
            .slice()
            .reverse()
            .slice(0, maxAlerts)
            .map((alert) => `
                <div class="alert-row">
                    <div class="alert-row__icon"><i class="fa-solid fa-satellite-dish"></i></div>
                    <div>
                        <strong>${alert.src || "Unknown source"}</strong>
                        <p>${alert.proto || "Unknown protocol"} - ${alert.type || alert.attack_type || "Unknown threat"}</p>
                    </div>
                    <span>Live</span>
                </div>
            `)
            .join("");
    }

    renderAlerts(initialMetrics.alerts || []);

    if (typeof io !== "function") return;

    async function fetchLiveData() {
    try {
        const res = await fetch("/api/live");
        const payload = await res.json();

        const stats = payload.metrics || {};
        const data = payload.data || [];

        setText("total", stats.total || 0);
        setText("anomalies", stats.threats || 0);
        setText("normal", stats.normal || 0);
        setText("top_ip", stats.top_ip || "-");

        renderAlerts(stats.alerts || []);

        const timestamp = new Date().toLocaleTimeString();

        trafficChart.data.labels.push(timestamp);
        trafficChart.data.datasets[0].data.push(stats.total || 0);
        trafficChart.data.datasets[1].data.push(stats.threats || 0);

        if (trafficChart.data.labels.length > maxPoints) {
            trafficChart.data.labels.shift();
            trafficChart.data.datasets.forEach(d => d.data.shift());
        }

        trafficChart.update();

        attackChart.data.datasets[0].data = [
            stats.normal || 0,
            stats.threats || 0
        ];
        attackChart.update();
        updateStatus(payload.agent_active);

    } catch (err) {
        console.error("Polling error:", err);
    }
}

// 🔥 Run every 2 seconds
setInterval(fetchLiveData, 500);
})();
