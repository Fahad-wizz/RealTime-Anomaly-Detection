(() => {
    const html = document.documentElement;
    const themeToggle = document.getElementById("themeToggle");
    const navToggle = document.getElementById("navToggle");
    const sidebar = document.getElementById("appSidebar");
    const overlay = document.getElementById("shellOverlay");
    const savedTheme = localStorage.getItem("sentinel-theme");
    const prefersLight = window.matchMedia("(prefers-color-scheme: light)").matches;
    const theme = savedTheme || (prefersLight ? "light" : "dark");

    function applyTheme(nextTheme) {
        html.setAttribute("data-theme", nextTheme);
        localStorage.setItem("sentinel-theme", nextTheme);

        if (themeToggle) {
            themeToggle.innerHTML =
                nextTheme === "light"
                    ? '<i class="fa-solid fa-sun"></i>'
                    : '<i class="fa-solid fa-moon"></i>';
        }
    }

    function setNavState(isOpen) {
        document.body.classList.toggle("nav-open", isOpen);
        if (navToggle) {
            navToggle.setAttribute("aria-expanded", String(isOpen));
        }
    }

    applyTheme(theme);

    if (themeToggle) {
        themeToggle.addEventListener("click", () => {
            const nextTheme = html.getAttribute("data-theme") === "light" ? "dark" : "light";
            applyTheme(nextTheme);
        });
    }

    if (navToggle && sidebar && overlay) {
        navToggle.addEventListener("click", () => {
            setNavState(!document.body.classList.contains("nav-open"));
        });

        overlay.addEventListener("click", () => setNavState(false));

        sidebar.querySelectorAll("a").forEach((link) => {
            link.addEventListener("click", () => setNavState(false));
        });
    }

    const revealNodes = document.querySelectorAll("[data-reveal]");
    if (revealNodes.length) {
        const observer = new IntersectionObserver(
            (entries) => {
                entries.forEach((entry) => {
                    if (entry.isIntersecting) {
                        entry.target.classList.add("is-visible");
                        observer.unobserve(entry.target);
                    }
                });
            },
            { threshold: 0.15 }
        );

        revealNodes.forEach((node, index) => {
            node.style.transitionDelay = `${Math.min(index * 70, 280)}ms`;
            observer.observe(node);
        });
    }

    document.querySelectorAll("[data-count-up]").forEach((node) => {
        const finalValue = Number(node.getAttribute("data-count-up"));
        if (!Number.isFinite(finalValue)) return;

        const duration = 1200;
        const start = performance.now();
        const suffix = node.textContent.includes("%")
            ? "%"
            : node.textContent.includes("+")
                ? "+"
                : "";

        const render = (now) => {
            const progress = Math.min((now - start) / duration, 1);
            const value = Math.round(finalValue * (1 - Math.pow(1 - progress, 3)));
            node.textContent = `${value.toLocaleString()}${suffix}`;
            if (progress < 1) {
                requestAnimationFrame(render);
            }
        };

        requestAnimationFrame(render);
    });
})();
