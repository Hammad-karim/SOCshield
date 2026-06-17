/* ===================================================================
   SOCshield — Frontend JS
   -------------------------------------------------------------------
   - Builds the dashboard Chart.js charts from data injected by the
     server (window.SOC_DATA).
   - Polls the /api/summary endpoint every 30s and refreshes the KPI
     block + the "recent alerts" table.
   - Renders the MITRE frequency charts on /mitre.
   =================================================================== */

(function (global) {
  "use strict";

  // ---- Slate/steel palette (matches socshield.css) -------------
  const PALETTE = {
    text:        "#d6dce5",
    textMuted:   "#7c8696",
    textDim:     "#4f5868",
    grid:        "rgba(124, 134, 150, 0.12)",
    border:      "#2a3543",
    surface:     "#10151d",
    raised:      "#161c27",

    accent:      "#d4a85a",
    accentFill:  "rgba(212, 168, 90, 0.10)",

    CRITICAL: "#d05858",
    HIGH:     "#d68a3a",
    MEDIUM:   "#c7b266",
    LOW:      "#5fa882",

    RECON:    "#6b8db3",
    CREDA:    "#8a7340",
    PRIVES:   "#a87555",
  };

  const SEV_COLORS = {
    CRITICAL: PALETTE.CRITICAL,
    HIGH:     PALETTE.HIGH,
    MEDIUM:   PALETTE.MEDIUM,
    LOW:      PALETTE.LOW,
  };

  function tacticColor(t) {
    if (t === "Reconnaissance")        return PALETTE.RECON;
    if (t === "Credential Access")     return PALETTE.CREDA;
    if (t === "Privilege Escalation")  return PALETTE.PRIVES;
    return PALETTE.textDim;
  }

  // ---- Chart.js theme ------------------------------------------
  function applyChartDefaults() {
    if (typeof Chart === "undefined") return;
    Chart.defaults.color = PALETTE.textMuted;
    Chart.defaults.borderColor = PALETTE.grid;
    Chart.defaults.font.family = "Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif";
    Chart.defaults.font.size = 11;
    Chart.defaults.plugins.legend.labels.color = PALETTE.textMuted;
    Chart.defaults.plugins.legend.labels.boxWidth = 10;
    Chart.defaults.plugins.legend.labels.boxHeight = 10;
    Chart.defaults.plugins.tooltip.backgroundColor = PALETTE.surface;
    Chart.defaults.plugins.tooltip.borderColor = PALETTE.border;
    Chart.defaults.plugins.tooltip.borderWidth = 1;
    Chart.defaults.plugins.tooltip.padding = 8;
    Chart.defaults.plugins.tooltip.titleColor = PALETTE.text;
    Chart.defaults.plugins.tooltip.bodyColor = PALETTE.text;
    Chart.defaults.plugins.tooltip.titleFont = { size: 11, weight: "600" };
    Chart.defaults.plugins.tooltip.bodyFont = { size: 11 };
    Chart.defaults.scale = Chart.defaults.scale || {};
  }

  function axisOptions() {
    return {
      ticks: { color: PALETTE.textDim, font: { size: 10, family: "JetBrains Mono, monospace" } },
      grid:  { color: PALETTE.grid, drawBorder: false },
      border: { display: false },
    };
  }

  // ---- Dashboard charts ---------------------------------------
  function initDashboardCharts() {
    applyChartDefaults();
    if (typeof Chart === "undefined") return;
    const D = global.SOC_DATA || {};
    buildTimelineChart(D.timeline || []);
    buildSeverityChart(D.severity || []);
    buildTopIpsChart(D.topIps || []);
    buildTacticsChart(D.tactics || []);
    buildTechniquesChart(D.techniques || []);
    buildCountriesChart(D.countries || []);
  }

  function buildTimelineChart(data) {
    const el = document.getElementById("chartTimeline");
    if (!el) return;
    new Chart(el, {
      type: "line",
      data: {
        labels: data.map(d => d.bucket),
        datasets: [{
          label: "Alerts",
          data: data.map(d => d.count),
          borderColor: PALETTE.accent,
          backgroundColor: PALETTE.accentFill,
          fill: true,
          tension: 0,
          pointRadius: 0,
          pointHoverRadius: 3,
          borderWidth: 1.5,
        }],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { x: axisOptions(), y: { ...axisOptions(), beginAtZero: true, ticks: { ...axisOptions().ticks, precision: 0 } } },
      },
    });
  }

  function buildSeverityChart(data) {
    const el = document.getElementById("chartSeverity");
    if (!el) return;
    new Chart(el, {
      type: "doughnut",
      data: {
        labels: data.map(d => d.severity),
        datasets: [{
          data: data.map(d => d.count),
          backgroundColor: data.map(d => SEV_COLORS[d.severity] || PALETTE.textDim),
          borderColor: PALETTE.surface,
          borderWidth: 2,
        }],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        cutout: "70%",
        plugins: { legend: { position: "bottom", labels: { boxWidth: 10, boxHeight: 10, padding: 10 } } },
      },
    });
  }

  function buildTopIpsChart(data) {
    const el = document.getElementById("chartTopIps");
    if (!el) return;
    new Chart(el, {
      type: "bar",
      data: {
        labels: data.map(d => d.ip),
        datasets: [{
          label: "Alerts",
          data: data.map(d => d.count),
          backgroundColor: PALETTE.accent,
          borderRadius: 0,
          barThickness: 12,
        }],
      },
      options: {
        indexAxis: "y", responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ...axisOptions(), beginAtZero: true, ticks: { ...axisOptions().ticks, precision: 0 } },
          y: { ...axisOptions(), ticks: { ...axisOptions().ticks, font: { size: 10, family: "JetBrains Mono, monospace" } } },
        },
      },
    });
  }

  function buildTacticsChart(data) {
    const el = document.getElementById("chartTactics");
    if (!el) return;
    new Chart(el, {
      type: "bar",
      data: {
        labels: data.map(d => d.tactic),
        datasets: [{
          label: "Detections",
          data: data.map(d => d.count),
          backgroundColor: data.map(d => tacticColor(d.tactic)),
          borderRadius: 0,
          barThickness: 18,
        }],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { x: axisOptions(), y: { ...axisOptions(), beginAtZero: true, ticks: { ...axisOptions().ticks, precision: 0 } } },
      },
    });
  }

  function buildTechniquesChart(data) {
    const el = document.getElementById("chartTechniques");
    if (!el) return;
    new Chart(el, {
      type: "bar",
      data: {
        labels: data.map(d => d.technique_id + " — " + d.technique_name),
        datasets: [{
          label: "Detections",
          data: data.map(d => d.count),
          backgroundColor: PALETTE.RECON,
          borderRadius: 0,
          barThickness: 14,
        }],
      },
      options: {
        indexAxis: "y", responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ...axisOptions(), beginAtZero: true, ticks: { ...axisOptions().ticks, precision: 0 } },
          y: { ...axisOptions(), ticks: { ...axisOptions().ticks, font: { size: 10, family: "JetBrains Mono, monospace" } } },
        },
      },
    });
  }

  function buildCountriesChart(data) {
    const el = document.getElementById("chartCountries");
    if (!el) return;
    new Chart(el, {
      type: "bar",
      data: {
        labels: data.map(d => d.country || "UNKNOWN"),
        datasets: [{
          label: "Alerts",
          data: data.map(d => d.count),
          backgroundColor: PALETTE.HIGH,
          borderRadius: 0,
          barThickness: 14,
        }],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { x: axisOptions(), y: { ...axisOptions(), beginAtZero: true, ticks: { ...axisOptions().ticks, precision: 0 } } },
      },
    });
  }

  // ---- MITRE page charts --------------------------------------
  function initMitreCharts(tacticFreq, techniqueFreq) {
    applyChartDefaults();
    if (typeof Chart === "undefined") return;

    const tacEl = document.getElementById("chartTacticFreq");
    if (tacEl) {
      const labels = Object.keys(tacticFreq);
      const values = labels.map(l => tacticFreq[l]);
      new Chart(tacEl, {
        type: "bar",
        data: {
          labels: labels,
          datasets: [{
            label: "Detections",
            data: values,
            backgroundColor: labels.map(tacticColor),
            borderRadius: 0,
            barThickness: 18,
          }],
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: { x: axisOptions(), y: { ...axisOptions(), beginAtZero: true, ticks: { ...axisOptions().ticks, precision: 0 } } },
        },
      });
    }

    const techEl = document.getElementById("chartTechFreq");
    if (techEl) {
      const labels = Object.keys(techniqueFreq);
      const values = labels.map(l => techniqueFreq[l]);
      new Chart(techEl, {
        type: "bar",
        data: {
          labels: labels,
          datasets: [{
            label: "Detections",
            data: values,
            backgroundColor: PALETTE.accent,
            borderRadius: 0,
            barThickness: 14,
          }],
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: { x: axisOptions(), y: { ...axisOptions(), beginAtZero: true, ticks: { ...axisOptions().ticks, precision: 0 } } },
        },
      });
    }
  }

  // ---- Auto-refresh (KPI + recent alerts) ----------------------
  let _refreshTimer = null;

  function setStatus(state) {
    const wrap = document.getElementById("socStatus");
    const txt = document.getElementById("statusText");
    if (!wrap) return;
    wrap.classList.remove("is-stale", "is-offline");
    if (state === "live") {
      if (txt) txt.textContent = "Live";
    } else if (state === "stale") {
      wrap.classList.add("is-stale");
      if (txt) txt.textContent = "Stale";
    } else {
      wrap.classList.add("is-offline");
      if (txt) txt.textContent = "Offline";
    }
  }

  function updateStatusTime() {
    const el = document.getElementById("statusTime");
    if (!el) return;
    const d = new Date();
    const hh = String(d.getHours()).padStart(2, "0");
    const mm = String(d.getMinutes()).padStart(2, "0");
    const ss = String(d.getSeconds()).padStart(2, "0");
    el.textContent = `${hh}:${mm}:${ss}`;
  }

  async function refreshDashboard() {
    try {
      const [summary, recent] = await Promise.all([
        fetch("/api/summary").then(r => r.ok ? r.json() : null),
        fetch("/api/alerts/recent").then(r => r.ok ? r.json() : null),
      ]);
      if (summary) applySummary(summary);
      if (recent) applyRecentAlerts(recent);
      setStatus("live");
    } catch (e) {
      setStatus("offline");
      console.warn("auto-refresh failed", e);
    } finally {
      updateStatusTime();
    }
  }

  function applySummary(s) {
    const set = (id, v) => {
      const el = document.getElementById(id);
      if (el && v !== undefined && v !== null) el.textContent = v;
    };
    set("kpi-total", s.total_alerts);
    set("kpi-critical", s.critical_alerts);
    set("kpi-active-ips", s.active_attacker_count);
    set("kpi-incidents", s.incidents_generated);
    const mitre = document.getElementById("kpi-mitre");
    if (mitre) {
      const sub = s.mitre_total_techniques;
      mitre.innerHTML = `${escapeHtml(String(s.mitre_techniques_covered))}<span class="kpi-value-sub">/ ${escapeHtml(String(sub))}</span>`;
    }
    const abuse = document.getElementById("kpi-abuse");
    if (abuse) {
      abuse.textContent = s.average_abuse_score === null || s.average_abuse_score === undefined
        ? "—"
        : Number(s.average_abuse_score).toFixed(1);
    }
  }

  function applyRecentAlerts(payload) {
    const tbody = document.querySelector("#recentAlertsTable tbody");
    if (!tbody) return;
    const rows = payload.rows || [];
    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="6"><div class="empty-state"><div class="empty-icon"><i class="bi bi-inbox"></i></div><p>No alerts in the database yet.</p></div></td></tr>';
      return;
    }
    tbody.innerHTML = rows.map(a => {
      const sev = (a.severity || "").toLowerCase();
      const sevLabel = sev ? `<span class="sev-label sev-${sev}">${escapeHtml(a.severity)}</span>` : "—";
      const sevCell = sev ? `class="sev-cell sev-${sev}"` : "";
      const mitre = a.mitre_technique
        ? `<span class="chip chip-mitre">${escapeHtml(a.mitre_technique)}</span><div class="text-dim" style="font-size: 11px; margin-top: 2px;">${escapeHtml(a.mitre_tactic || "")}</div>`
        : '<span class="text-dim">—</span>';
      return `
        <tr>
          <td class="text-dim mono">${escapeHtml(a.timestamp || "")}</td>
          <td><code>${escapeHtml(a.source_ip || "")}</code></td>
          <td>${escapeHtml(a.detector || "")}</td>
          <td ${sevCell}>${sevLabel}</td>
          <td>${mitre}</td>
          <td class="truncate">${escapeHtml(a.title || "")}</td>
        </tr>`;
    }).join("");
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;",
      '"': "&quot;", "'": "&#39;",
    }[c]));
  }

  function startAutoRefresh(intervalMs) {
    if (_refreshTimer) clearInterval(_refreshTimer);
    _refreshTimer = setInterval(refreshDashboard, intervalMs);

    const btn = document.getElementById("refreshNowBtn");
    if (btn) {
      btn.addEventListener("click", function (ev) {
        ev.preventDefault();
        refreshDashboard();
      });
    }

    updateStatusTime();
    setStatus("live");
  }

  // ---- Public API ---------------------------------------------
  global.SOCDashboard = {
    initCharts:        initDashboardCharts,
    initMitreCharts:   initMitreCharts,
    startAutoRefresh:  startAutoRefresh,
  };
})(window);
