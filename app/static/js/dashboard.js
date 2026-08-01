/**
 * SentinelASM — Enterprise Dashboard
 * ==================================
 * Renders every dashboard widget from a single overview payload shaped by
 * app/dashboard/analytics.py (server-rendered on load via
 * window.SENTINEL_OVERVIEW, and re-fetched from GET /dashboard/overview
 * when the user clicks Refresh). No widget on this page uses fake/sample
 * numbers — if there's no data, the empty state template block handles it
 * server-side instead.
 *
 * Depends on charts.js having run first (SENTINEL_PALETTE, sentinelGradient).
 */

(function () {
  "use strict";

  const RING_CIRCUMFERENCE = 352; // matches r=56 circle used across the app

  const charts = {}; // name -> Chart.js instance, so refresh() can destroy/rebuild

  function toneForScore(score) {
    if (score === null || score === undefined) return SENTINEL_PALETTE.grid;
    if (score >= 75) return SENTINEL_PALETTE.green;
    if (score >= 50) return SENTINEL_PALETTE.amber;
    return SENTINEL_PALETTE.red;
  }

  function toneForRisk(score) {
    if (score === null || score === undefined) return SENTINEL_PALETTE.grid;
    if (score >= 70) return SENTINEL_PALETTE.red;
    if (score >= 40) return SENTINEL_PALETTE.amber;
    return SENTINEL_PALETTE.green;
  }

  function setGauge(circleEl, valueEl, value, color) {
    if (!circleEl) return;
    const pct = Math.max(0, Math.min(100, value || 0));
    const offset = RING_CIRCUMFERENCE * (1 - pct / 100);
    circleEl.style.stroke = color;
    circleEl.setAttribute("stroke-dashoffset", offset.toFixed(1));
    if (valueEl) valueEl.textContent = value === null || value === undefined ? "-" : Math.round(value);
  }

  function destroyChart(name) {
    if (charts[name]) {
      charts[name].destroy();
      delete charts[name];
    }
  }

  function fmt(n) {
    return n === null || n === undefined ? "-" : n;
  }

  /**
   * Animates a KPI element's text from 0 (or its current text) up to the
   * target value in `data-count`. Respects prefers-reduced-motion by
   * jumping straight to the final value.
   */
  function animateCounter(id, target, opts) {
    const el = document.getElementById(id);
    if (!el) return;
    const decimals = (opts && opts.decimals) || 0;
    const suffix = (opts && opts.suffix) || "";
    const end = Number(target);

    if (target === null || target === undefined || Number.isNaN(end)) {
      el.textContent = "-";
      return;
    }

    const prefersReduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (prefersReduced) {
      el.textContent = end.toFixed(decimals) + suffix;
      return;
    }

    const duration = 900;
    const start = 0;
    const startTime = performance.now();

    function tick(now) {
      const progress = Math.min(1, (now - startTime) / duration);
      const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
      const value = start + (end - start) * eased;
      el.textContent = value.toFixed(decimals) + suffix;
      if (progress < 1) {
        requestAnimationFrame(tick);
      } else {
        el.textContent = end.toFixed(decimals) + suffix;
      }
    }
    requestAnimationFrame(tick);
  }

  function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function timeAgo(iso) {
    if (!iso) return "-";
    const then = new Date(iso).getTime();
    const now = Date.now();
    const diffMin = Math.round((now - then) / 60000);
    if (diffMin < 1) return "just now";
    if (diffMin < 60) return diffMin + "m ago";
    const diffHr = Math.round(diffMin / 60);
    if (diffHr < 24) return diffHr + "h ago";
    const diffDay = Math.round(diffHr / 24);
    return diffDay + "d ago";
  }

  /* =========================================================================
     KPI row + gauges + executive summary (plain DOM writes, no chart lib)
     ========================================================================= */
  function renderKpis(overview) {
    const k = overview.kpis || {};
    animateCounter("kpiTotalAssets", k.total_assets);
    animateCounter("kpiTotalScans", k.total_scans);
    animateCounter("kpiAvgSecurity", k.avg_security_score === null ? null : k.avg_security_score);
    animateCounter("kpiCriticalOpen", k.critical_open);
    animateCounter("kpiScansWeek", k.scans_this_week);

    const delta = (k.scans_this_week || 0) - (k.scans_prior_week || 0);
    const deltaEl = document.getElementById("kpiScansDelta");
    if (deltaEl) {
      if (delta > 0) {
        deltaEl.innerHTML = '<i class="fa-solid fa-arrow-up"></i> +' + delta + " vs last week";
        deltaEl.className = "kpi-delta up";
      } else if (delta < 0) {
        deltaEl.innerHTML = '<i class="fa-solid fa-arrow-down"></i> ' + delta + " vs last week";
        deltaEl.className = "kpi-delta down";
      } else {
        deltaEl.innerHTML = '<i class="fa-solid fa-minus"></i> flat vs last week';
        deltaEl.className = "kpi-delta text-secondary";
      }
    }
  }

  function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
  }

  function renderGauges(overview) {
    const latest = overview.latest;
    const secScore = latest ? latest.security_score : null;
    const riskScore = latest ? latest.risk_score : null;

    setGauge(
      document.getElementById("securityGaugeRing"),
      document.getElementById("securityScore"),
      secScore,
      toneForScore(secScore)
    );
    setGauge(
      document.getElementById("riskGaugeRing"),
      document.getElementById("riskScore"),
      riskScore,
      toneForRisk(riskScore)
    );

    setText("securityGrade", latest && latest.grade ? latest.grade : "-");
    setText("securityRating", latest && latest.rating ? latest.rating : "No scans yet");
    setText("riskSeverity", latest && latest.risk_severity ? latest.risk_severity : "-");
  }

  function renderExecutiveSummary(overview) {
    const latest = overview.latest;
    const targetEl = document.getElementById("execTarget");
    const summaryEl = document.getElementById("execSummary");
    const metaEl = document.getElementById("execMeta");

    if (!latest) {
      if (targetEl) targetEl.textContent = "No scans yet";
      if (summaryEl) summaryEl.textContent = "Run a scan to generate an AI executive summary.";
      if (metaEl) metaEl.textContent = "";
      return;
    }

    if (targetEl) targetEl.textContent = latest.target;
    if (summaryEl) summaryEl.textContent = latest.summary || "No summary available for this scan.";
    if (metaEl) {
      metaEl.textContent =
        "Threat level: " + (latest.threat_level || "-") +
        " · Business impact: " + (latest.business_impact || "-") +
        " · " + timeAgo(latest.created_at);
    }
  }

  /* =========================================================================
     Charts
     ========================================================================= */
  function renderTrendChart(overview) {
    const el = document.getElementById("riskTrendChart");
    if (!el) return;
    destroyChart("trend");

    const points = overview.trend || [];
    charts.trend = new Chart(el, {
      type: "line",
      data: {
        labels: points.map((p) => p.date),
        datasets: [
          {
            label: "Risk Score",
            data: points.map((p) => p.risk_score),
            borderColor: SENTINEL_PALETTE.red,
            backgroundColor: (ctx) => sentinelGradient(ctx.chart.ctx, SENTINEL_PALETTE.red, 0.25, 0),
            fill: true,
            tension: 0.4,
            pointRadius: 2,
          },
          {
            label: "Security Score",
            data: points.map((p) => p.security_score),
            borderColor: SENTINEL_PALETTE.green,
            backgroundColor: (ctx) => sentinelGradient(ctx.chart.ctx, SENTINEL_PALETTE.green, 0.2, 0),
            fill: true,
            tension: 0.4,
            pointRadius: 2,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { mode: "index", intersect: false },
        scales: {
          y: { min: 0, max: 100, grid: { color: SENTINEL_PALETTE.grid } },
          x: { grid: { display: false } },
        },
      },
    });
  }

  function renderSeverityChart(overview) {
    const el = document.getElementById("severityPieChart");
    if (!el) return;
    destroyChart("severity");

    const dist = overview.severity_distribution || {};
    charts.severity = new Chart(el, {
      type: "doughnut",
      data: {
        labels: ["Critical", "High", "Medium", "Low"],
        datasets: [
          {
            data: [dist.Critical || 0, dist.High || 0, dist.Medium || 0, dist.Low || 0],
            backgroundColor: [SENTINEL_PALETTE.red, SENTINEL_PALETTE.amber, SENTINEL_PALETTE.blue, SENTINEL_PALETTE.green],
            borderWidth: 0,
          },
        ],
      },
      options: { responsive: true, maintainAspectRatio: false, cutout: "68%" },
    });
  }

  function renderCveChart(overview) {
    const el = document.getElementById("cveDistributionChart");
    if (!el) return;
    destroyChart("cve");

    const dist = overview.cve_distribution || {};
    charts.cve = new Chart(el, {
      type: "bar",
      data: {
        labels: ["Critical", "High", "Medium"],
        datasets: [
          {
            label: "CVEs",
            data: [dist.critical || 0, dist.high || 0, dist.medium || 0],
            backgroundColor: [SENTINEL_PALETTE.red, SENTINEL_PALETTE.amber, SENTINEL_PALETTE.blue],
            borderRadius: 6,
            maxBarThickness: 42,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          y: { beginAtZero: true, ticks: { precision: 0 }, grid: { color: SENTINEL_PALETTE.grid } },
          x: { grid: { display: false } },
        },
      },
    });
  }

  function renderOpenPortsChart(overview) {
    const el = document.getElementById("openPortsChart");
    if (!el) return;
    destroyChart("ports");

    const ports = overview.open_ports || [];
    charts.ports = new Chart(el, {
      type: "bar",
      data: {
        labels: ports.map((p) => p.label),
        datasets: [
          {
            label: "Occurrences",
            data: ports.map((p) => p.count),
            backgroundColor: SENTINEL_PALETTE.blue,
            borderRadius: 6,
            maxBarThickness: 34,
          },
        ],
      },
      options: {
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { beginAtZero: true, ticks: { precision: 0 }, grid: { color: SENTINEL_PALETTE.grid } },
          y: { grid: { display: false } },
        },
      },
    });
  }

  function renderWeeklyTrendChart(overview) {
    const el = document.getElementById("weeklyScanTrendChart");
    if (!el) return;
    destroyChart("weekly");

    const buckets = overview.weekly_scan_trend || [];
    charts.weekly = new Chart(el, {
      type: "bar",
      data: {
        labels: buckets.map((b) => b.label),
        datasets: [
          {
            label: "Scans",
            data: buckets.map((b) => b.count),
            backgroundColor: SENTINEL_PALETTE.purple,
            borderRadius: 6,
            maxBarThickness: 28,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          y: { beginAtZero: true, ticks: { precision: 0 }, grid: { color: SENTINEL_PALETTE.grid } },
          x: { grid: { display: false } },
        },
      },
    });
  }

  function renderAssetGrowthChart(overview) {
    const el = document.getElementById("assetGrowthChart");
    if (!el) return;
    destroyChart("growth");

    const buckets = overview.asset_growth || [];
    charts.growth = new Chart(el, {
      type: "line",
      data: {
        labels: buckets.map((b) => b.label),
        datasets: [
          {
            label: "Distinct assets",
            data: buckets.map((b) => b.assets),
            borderColor: SENTINEL_PALETTE.blue,
            backgroundColor: (ctx) => sentinelGradient(ctx.chart.ctx, SENTINEL_PALETTE.blue, 0.25, 0),
            fill: true,
            stepped: true,
            pointRadius: 2,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          y: { beginAtZero: true, ticks: { precision: 0 }, grid: { color: SENTINEL_PALETTE.grid } },
          x: { grid: { display: false } },
        },
      },
    });
  }

  function renderComplianceChart(overview) {
    const el = document.getElementById("complianceChart");
    if (!el) return;
    destroyChart("compliance");

    const c = overview.compliance || { passing: 0, total: 0, percent: null };
    const remaining = Math.max(0, (c.total || 0) - (c.passing || 0));

    charts.compliance = new Chart(el, {
      type: "doughnut",
      data: {
        labels: ["Passing (≥75)", "Needs attention"],
        datasets: [
          {
            data: c.total ? [c.passing, remaining] : [0, 1],
            backgroundColor: [SENTINEL_PALETTE.green, "rgba(148,163,184,.18)"],
            borderWidth: 0,
          },
        ],
      },
      options: { responsive: true, maintainAspectRatio: false, cutout: "72%", plugins: { legend: { display: false } } },
    });

    setText("complianceLabel", c.percent === null ? "No data" : c.percent + "%");
  }

  /* =========================================================================
     Tables / lists (server-shaped rows re-rendered on refresh)
     ========================================================================= */
  function severityBadgeClass(sev) {
    const s = (sev || "").toLowerCase();
    if (["critical", "high", "medium", "low"].includes(s)) return "badge-soft badge-" + s;
    return "badge-soft badge-suspended";
  }

  function renderScanHistory(overview) {
    const tbody = document.getElementById("scanHistoryBody");
    if (!tbody) return;
    const rows = overview.scan_history || [];

    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted-2 py-4">No scans recorded yet.</td></tr>';
      return;
    }

    tbody.innerHTML = rows
      .map(
        (r) => `
      <tr>
        <td class="mono">${escapeHtml(r.target)}</td>
        <td>${timeAgo(r.created_at)}</td>
        <td style="color:${toneForRisk(r.risk_score)}">${fmt(r.risk_score)}</td>
        <td style="color:${toneForScore(r.security_score)}">${fmt(r.security_score)} <span class="text-muted-2">(${escapeHtml(r.grade)})</span></td>
        <td><span class="${severityBadgeClass(r.severity)}">${escapeHtml(r.severity || "-")}</span></td>
      </tr>`
      )
      .join("");
  }

  function renderActivity(overview) {
    const list = document.getElementById("activityList");
    if (!list) return;
    const rows = overview.recent_activity || [];

    if (!rows.length) {
      list.innerHTML = '<li class="text-center text-muted-2 py-3">No recent activity.</li>';
      return;
    }

    const dotClass = (level) => {
      if (level === "critical" || level === "error") return "timeline-dot-critical";
      if (level === "warning") return "timeline-dot-warning";
      return "";
    };

    list.innerHTML = rows
      .map(
        (r) => `
      <li class="timeline-item ${dotClass(r.level)}">
        <div class="fw-semibold">${escapeHtml(r.action)}</div>
        ${r.details ? `<div class="small text-secondary">${escapeHtml(r.details)}</div>` : ""}
        <span class="timeline-meta">${timeAgo(r.created_at)}</span>
      </li>`
      )
      .join("");
  }

  function renderAssetOverview(overview) {
    const tbody = document.getElementById("assetOverviewBody");
    if (!tbody) return;
    const rows = overview.assets || [];

    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted-2 py-4">No assets scanned yet.</td></tr>';
      return;
    }

    tbody.innerHTML = rows
      .map(
        (a) => `
      <tr>
        <td class="mono">${escapeHtml(a.target)}</td>
        <td style="color:${toneForScore(a.security_score)}">${fmt(a.security_score)} <span class="text-muted-2">(${escapeHtml(a.grade)})</span></td>
        <td><span class="${severityBadgeClass(a.severity)}">${escapeHtml(a.severity || "-")}</span></td>
        <td>${fmt(a.open_ports)}</td>
        <td style="color:${a.critical_cves ? "var(--red)" : "inherit"}">${fmt(a.critical_cves)}</td>
        <td class="text-secondary">${timeAgo(a.last_scanned)}</td>
      </tr>`
      )
      .join("");
  }

  function renderTopVulnerabilities(overview) {
    const list = document.getElementById("topVulnList");
    if (!list) return;
    const rows = overview.top_vulnerabilities || [];

    if (!rows.length) {
      list.innerHTML = '<div class="text-center text-muted-2 py-3">No open findings — nice work.</div>';
      return;
    }

    list.innerHTML = rows
      .map(
        (r) => `
      <div class="alert-row d-flex justify-content-between align-items-start gap-3 mb-2">
        <div>
          <div class="fw-semibold text-white">${escapeHtml(r.title)}</div>
          <div class="small text-secondary mb-1">${escapeHtml(r.description || "")}</div>
          <span class="chip-target">${escapeHtml(r.target)}</span>
        </div>
        <span class="${severityBadgeClass(r.severity)}">${escapeHtml(r.severity)}</span>
      </div>`
      )
      .join("");
  }

  /* =========================================================================
     Orchestration
     ========================================================================= */
  function renderAll(overview) {
    renderKpis(overview);
    renderGauges(overview);
    renderExecutiveSummary(overview);
    renderTrendChart(overview);
    renderSeverityChart(overview);
    renderCveChart(overview);
    renderOpenPortsChart(overview);
    renderWeeklyTrendChart(overview);
    renderAssetGrowthChart(overview);
    renderComplianceChart(overview);
    renderAssetOverview(overview);
    renderScanHistory(overview);
    renderActivity(overview);
    renderTopVulnerabilities(overview);
  }

  function refresh() {
    const btn = document.getElementById("refreshDashboardBtn");
    const icon = btn ? btn.querySelector("i") : null;
    if (icon) icon.classList.add("refresh-spin");

    fetch("/dashboard/overview", { headers: { Accept: "application/json" } })
      .then((r) => r.json())
      .then((overview) => {
        window.SENTINEL_OVERVIEW = overview;
        renderAll(overview);
      })
      .catch((err) => console.error("Dashboard refresh failed:", err))
      .finally(() => {
        if (icon) icon.classList.remove("refresh-spin");
      });
  }

  document.addEventListener("DOMContentLoaded", () => {
    if (window.SENTINEL_OVERVIEW) {
      renderAll(window.SENTINEL_OVERVIEW);
    }

    const refreshBtn = document.getElementById("refreshDashboardBtn");
    if (refreshBtn) refreshBtn.addEventListener("click", refresh);
  });
})();
