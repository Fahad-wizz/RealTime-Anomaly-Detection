document.addEventListener("DOMContentLoaded", function () {

    (() => {

        const chartNode = document.getElementById("attackChart");
        const filterNode = document.getElementById("attackFilter");
        const searchNode = document.getElementById("searchBox");
        const tableBody = document.getElementById("tableBody");
        const countsNode = document.getElementById("attackCounts");

        // -----------------------------
        // SAFE DATA LOAD
        // -----------------------------
        const attackCounts = countsNode ? JSON.parse(countsNode.textContent || "{}") : {};

        let chart;

        // -----------------------------
        // CHART
        // -----------------------------
        function buildDataset(data) {
            const entries = Object.entries(data);
            return {
                labels: entries.map(([label]) => label),
                values: entries.map(([, value]) => value),
            };
        }

        function renderChart(source) {
            if (!chartNode || typeof Chart === "undefined") return;

            const dataset = buildDataset(source);

            const chartConfig = {
                type: "doughnut",
                data: {
                    labels: dataset.labels,
                    datasets: [{
                        data: dataset.values,
                        backgroundColor: [
                            "#34d399", "#fb7185", "#0ea5e9",
                            "#fbbf24", "#a78bfa", "#f97316"
                        ],
                        borderColor: "rgba(7, 17, 31, 0.15)",
                        borderWidth: 2,
                        hoverOffset: 6,
                    }],
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: false, // 🔥 prevents unwanted refresh feel
                    plugins: {
                        legend: {
                            position: "bottom",
                            labels: {
                                color: getComputedStyle(document.documentElement)
                                    .getPropertyValue("--text").trim(),
                                padding: 18,
                            },
                        },
                    },
                },
            };

            if (!chart) {
                chart = new Chart(chartNode, chartConfig);
            } else {
                chart.data = chartConfig.data;
                chart.options = chartConfig.options;
                chart.update();
            }
        }

        // -----------------------------
        // FILTER DROPDOWN
        // -----------------------------
        function populateFilter() {
            if (!filterNode) return;

            Object.keys(attackCounts).forEach((key) => {
                const option = document.createElement("option");
                option.value = key;
                option.textContent = key;
                filterNode.appendChild(option);
            });
        }

        // -----------------------------
        // TABLE FILTERING (ENTERPRISE FIX)
        // -----------------------------
        function applyTableFilters() {
            if (!tableBody) return;

            const rows = tableBody.querySelectorAll("tr");

            const searchValue = searchNode
                ? searchNode.value.trim().toLowerCase()
                : "";

            const filterValue = filterNode
                ? (filterNode.value || "ALL").toLowerCase()
                : "all";

            rows.forEach((row) => {

                const rowText = row.textContent.toLowerCase();

                // 🔥 SAFE NORMALIZATION
                let attack = (row.dataset.attack || "").toLowerCase().trim();

                const matchesSearch =
                    !searchValue || rowText.includes(searchValue);

                const matchesFilter =
                    filterValue === "all" ||
                    attack === filterValue;

                row.style.display = (matchesSearch && matchesFilter)
                    ? ""
                    : "none";
        });
    }
        // -----------------------------
        // EVENTS
        // -----------------------------
        if (filterNode) {
            filterNode.addEventListener("change", () => {

                const filterValue = filterNode.value;

                renderChart(
                    filterValue === "ALL"
                        ? attackCounts
                        : { [filterValue]: attackCounts[filterValue] }
                );

                applyTableFilters();
            });
        }

        // 🔥 DEBOUNCED SEARCH (NO LAG)
        if (searchNode) {
            let debounceTimer;

            searchNode.addEventListener("input", () => {
                clearTimeout(debounceTimer);
                debounceTimer = setTimeout(() => {
                    applyTableFilters();
                }, 200);
            });
        }

        // -----------------------------
        // SOCKET (OPTIONAL)
        // -----------------------------
        /*
        if (typeof io === "function") {
            const socket = io();
            socket.on("packet", (payload) => {
                const attackType = payload.attack_type || "Unknown";

                attackCounts[attackType] =
                    (attackCounts[attackType] || 0) + 1;

                if (
                    filterNode &&
                    ![...filterNode.options].some(
                        (opt) => opt.value === attackType
                    )
                ) {
                    const option = document.createElement("option");
                    option.value = attackType;
                    option.textContent = attackType;
                    filterNode.appendChild(option);
                }

                renderChart(attackCounts);
            });
        }
        */

        // -----------------------------
        // INIT (CRITICAL ORDER)
        // -----------------------------
        populateFilter();
        renderChart(attackCounts);

        // 🔥 CRITICAL FIX
        if (filterNode) {
            filterNode.value = "ALL";
        }

        // 🔥 FORCE ALL ROWS VISIBLE FIRST
        const rows = document.querySelectorAll("#tableBody tr");
        rows.forEach(row => row.style.display = "");

        // THEN apply filters
        applyTableFilters();
    })();

    // ✅ SAFE DEBUG (NO CRASH)
    const rows = document.querySelectorAll("#tableBody tr");
    console.log("Rows count:", rows.length);

});