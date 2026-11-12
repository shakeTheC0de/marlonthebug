// MarlonTheBug panel — small, dependency-free interactions.
(function () {
  "use strict";

  // Sidebar (mobile)
  const toggle = document.querySelector("[data-sidebar-toggle]");
  if (toggle) {
    toggle.addEventListener("click", () => document.body.classList.toggle("sidebar-open"));
    document.addEventListener("click", (event) => {
      if (window.innerWidth > 980) return;
      const sidebar = document.getElementById("sidebar");
      if (!sidebar) return;
      if (!sidebar.contains(event.target) && !toggle.contains(event.target)) {
        document.body.classList.remove("sidebar-open");
      }
    });
  }

  // Confirm destructive actions
  document.querySelectorAll("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      const message = form.getAttribute("data-confirm") || "¿Continuar?";
      if (!window.confirm(message)) event.preventDefault();
    });
  });

  // Auto-dismiss flash messages
  document.querySelectorAll("[data-flash]").forEach((flash) => {
    window.setTimeout(() => {
      flash.style.transition = "opacity .35s ease, transform .35s ease";
      flash.style.opacity = "0";
      flash.style.transform = "translateY(-4px)";
      window.setTimeout(() => flash.remove(), 400);
    }, 6500);
  });

  // Evidence tabs
  document.querySelectorAll("[data-tabs]").forEach((tabs) => {
    const buttons = tabs.querySelectorAll("[data-tab]");
    buttons.forEach((button) => {
      button.addEventListener("click", () => {
        buttons.forEach((item) => item.classList.remove("active"));
        button.classList.add("active");
        const container = tabs.parentElement;
        container.querySelectorAll(".code-block").forEach((panel) => panel.classList.add("hidden"));
        const target = document.getElementById(button.getAttribute("data-tab"));
        if (target) target.classList.remove("hidden");
      });
    });
  });

  // Copy to clipboard
  document.querySelectorAll("[data-copy-target]").forEach((button) => {
    button.addEventListener("click", async () => {
      const target = document.getElementById(button.getAttribute("data-copy-target"));
      if (!target) return;
      const text = target.innerText || target.textContent || "";
      try {
        await navigator.clipboard.writeText(text);
        const original = button.innerHTML;
        button.innerHTML = "Copiado";
        window.setTimeout(() => (button.innerHTML = original), 1400);
      } catch (error) {
        window.prompt("Copia el contenido:", text);
      }
    });
  });

  // Live scan console (SSE)
  const consoleEl = document.getElementById("scan-console");
  if (consoleEl && window.EventSource) {
    const streamUrl = consoleEl.getAttribute("data-stream-url");
    const progress = document.getElementById("scan-progress");
    const liveState = document.getElementById("scan-live-state");
    let source = null;
    let logCount = consoleEl.querySelectorAll(".log-line").length;

    const appendLog = (entry) => {
      const line = document.createElement("div");
      line.className = `log-line log-${(entry.level || "INFO").toLowerCase()}`;
      const time = document.createElement("span");
      time.className = "log-time";
      time.textContent = entry.time || "";
      const level = document.createElement("span");
      level.className = "log-level";
      level.textContent = entry.level || "INFO";
      const message = document.createElement("span");
      message.className = "log-msg";
      message.textContent = entry.message || "";
      line.appendChild(time);
      line.appendChild(level);
      line.appendChild(message);
      consoleEl.appendChild(line);
      logCount += 1;
      while (logCount > 600) {
        const first = consoleEl.querySelector(".log-line");
        if (!first) break;
        first.remove();
        logCount -= 1;
      }
      consoleEl.scrollTop = consoleEl.scrollHeight;
    };

    const connect = () => {
      if (source) source.close();
      source = new EventSource(streamUrl);
      source.onmessage = (event) => {
        let data;
        try {
          data = JSON.parse(event.data);
        } catch (error) {
          return;
        }
        if (data.type === "log") {
          appendLog(data);
        } else if (data.type === "progress") {
          const total = Number(data.total) || 1;
          const done = Number(data.done) || 0;
          const pct = Math.max(4, Math.min(100, Math.round((done / total) * 100)));
          if (progress) progress.style.width = `${pct}%`;
          if (liveState) liveState.textContent = `${pct}% · ${data.message || ""}`;
        } else if (data.type === "finding") {
          const finding = data.finding || {};
          appendLog({
            time: new Date().toLocaleTimeString("es-ES", { hour12: false }),
            level: finding.severity ? finding.severity.toUpperCase() : "FINDING",
            message: `${finding.title || "Hallazgo"} · ${finding.endpoint || finding.target || ""}`,
          });
        } else if (data.type === "done") {
          if (liveState) liveState.textContent = data.status === "completed" ? "completado" : (data.status || "finalizado");
          if (progress) progress.style.width = "100%";
          source.close();
          window.setTimeout(() => window.location.reload(), 1400);
        }
      };
      source.onerror = () => {
        if (liveState) liveState.textContent = "reconectando…";
      };
    };
    connect();
    window.addEventListener("beforeunload", () => source && source.close());
  }

  // Keyboard: "/" focuses the search box
  document.addEventListener("keydown", (event) => {
    if (event.key !== "/" || event.metaKey || event.ctrlKey || event.altKey) return;
    const tag = (event.target && event.target.tagName) || "";
    if (["INPUT", "TEXTAREA", "SELECT"].includes(tag)) return;
    const search = document.querySelector('input[type="search"]');
    if (search) {
      event.preventDefault();
      search.focus();
    }
  });
})();
