// SentinelASM — shared interactions

/**
 * Sentinel — shared UI helpers reused across Assets, Scan Results, and any
 * other page that needs to render a favicon, a technology chip, an SSL
 * grade, a radial gauge, or export table data. Kept dependency-free so it
 * can run before any page-specific script.
 */
window.Sentinel = (function () {
  const TECH_ICON_MAP = [
    [["wordpress"], "fa-brands fa-wordpress"],
    [["php"], "fa-brands fa-php"],
    [["react"], "fa-brands fa-react"],
    [["node"], "fa-brands fa-node-js"],
    [["python", "django", "flask"], "fa-brands fa-python"],
    [["aws", "amazon"], "fa-brands fa-aws"],
    [["cloudflare"], "fa-brands fa-cloudflare"],
    [["iis", "asp.net", "microsoft"], "fa-brands fa-microsoft"],
    [["docker"], "fa-brands fa-docker"],
    [["laravel"], "fa-brands fa-laravel"],
    [["angular"], "fa-brands fa-angular"],
    [["vue"], "fa-brands fa-vuejs"],
    [["bootstrap"], "fa-brands fa-bootstrap"],
    [["nginx", "apache", "openresty", "litespeed"], "fa-solid fa-server"],
  ];

  function techIcon(name) {
    const n = (name || "").toLowerCase();
    for (const [keys, icon] of TECH_ICON_MAP) {
      if (keys.some((k) => n.includes(k))) return icon;
    }
    return "fa-solid fa-cube";
  }

  function faviconUrl(target) {
    if (!target) return "";
    const domain = String(target).replace(/^https?:\/\//, "").split("/")[0];
    return `https://www.google.com/s2/favicons?sz=64&domain=${encodeURIComponent(domain)}`;
  }

  function sslGrade(ssl) {
    if (!ssl || Object.keys(ssl).length === 0) return { grade: "N/A", cls: "badge-medium" };
    if (ssl.expired) return { grade: "F", cls: "badge-critical" };
    if (ssl.self_signed) return { grade: "D", cls: "badge-high" };
    const days = ssl.days_remaining;
    const tls = (ssl.tls_version || "").toUpperCase();
    if (typeof days === "number" && days <= 14) return { grade: "C", cls: "badge-high" };
    if (tls.includes("1.3") && (typeof days !== "number" || days > 30)) return { grade: "A", cls: "badge-low" };
    return { grade: "B", cls: "badge-medium" };
  }

  function statusBadge(status) {
    const s = (status || "None").toLowerCase();
    if (s === "expired") return { text: "Expired", cls: "badge-critical" };
    if (s === "self-signed") return { text: "Self-Signed", cls: "badge-high" };
    if (s === "valid") return { text: "Valid", cls: "badge-low" };
    return { text: "None", cls: "badge-suspended" };
  }

  // Sets a radial gauge's progress ring based on a percentage (0-100),
  // computed live rather than hardcoded so the ring always matches the
  // real number rendered beside it.
  function setRing(circleEl, percent, radius) {
    if (!circleEl) return;
    const r = radius || parseFloat(circleEl.getAttribute("r")) || 56;
    const circumference = 2 * Math.PI * r;
    const pct = Math.max(0, Math.min(100, Number(percent) || 0));
    const offset = circumference - (pct / 100) * circumference;
    circleEl.style.strokeDasharray = String(circumference);
    circleEl.style.strokeDashoffset = String(offset);
  }

  function download(filename, content, mime) {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function rowsToCSV(rows, headers) {
    const esc = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const lines = [headers.map(esc).join(",")];
    rows.forEach((r) => lines.push(headers.map((h) => esc(r[h])).join(",")));
    return lines.join("\n");
  }

  return { techIcon, faviconUrl, sslGrade, statusBadge, setRing, download, rowsToCSV };
})();

document.addEventListener('DOMContentLoaded', () => {

  // Mobile sidebar toggle
  const sidebar   = document.getElementById('sentinelSidebar');
  const backdrop  = document.getElementById('sidebarBackdrop');
  const mToggle   = document.getElementById('sidebarToggle');
  const cToggle   = document.getElementById('sidebarCollapse');

  function openMobile() {
    if (!sidebar || !backdrop) return;
    sidebar.classList.add('mobile-open');
    backdrop.style.display = 'block';
  }
  function closeMobile() {
    if (!sidebar || !backdrop) return;
    sidebar.classList.remove('mobile-open');
    backdrop.style.display = 'none';
  }

  mToggle && mToggle.addEventListener('click', () => {
    sidebar.classList.contains('mobile-open') ? closeMobile() : openMobile();
  });
  backdrop && backdrop.addEventListener('click', closeMobile);

  // Desktop collapse (icon rail)
  if (cToggle && sidebar) {
    cToggle.addEventListener('click', () => {
      sidebar.classList.toggle('collapsed');
      const icon = cToggle.querySelector('i');
      icon.classList.toggle('fa-angles-left');
      icon.classList.toggle('fa-angles-right');
      localStorage_safe_set('sentinel_sidebar_collapsed', sidebar.classList.contains('collapsed'));
    });
  }

  if (sidebar && localStorage_safe_get('sentinel_sidebar_collapsed') === 'true') {
    sidebar.classList.add('collapsed');
  }

  // Theme toggle (dark <-> light)
  const themeToggle = document.getElementById('themeToggle');
  if (themeToggle) {
    const html = document.documentElement;
    const isLight = html.getAttribute('data-theme') === 'light';
    themeToggle.querySelector('i').className = isLight ? 'fa-solid fa-sun' : 'fa-solid fa-moon';

    themeToggle.addEventListener('click', () => {
      const isLightMode = html.getAttribute('data-theme') === 'light';
      html.setAttribute('data-theme', isLightMode ? 'dark' : 'light');
      document.body.classList.toggle('theme-light', !isLightMode);
      themeToggle.querySelector('i').className = isLightMode ? 'fa-solid fa-moon' : 'fa-solid fa-sun';
    });
  }

  // Bootstrap tooltips
  if (typeof bootstrap !== "undefined" && bootstrap.Tooltip) {
    document
        .querySelectorAll('[data-bs-toggle="tooltip"]')
        .forEach((element) => {
            new bootstrap.Tooltip(element);
        });
  } 

  // Generic "reveal" stagger for elements marked .reveal-stagger
  document.querySelectorAll('.reveal-stagger > *').forEach((el, i) => {
    el.style.animationDelay = (i * 60) + 'ms';
    el.classList.add('reveal');
  });

  // Safe localStorage wrappers (works even if storage disabled)
  function localStorage_safe_set(k, v){ try { window.localStorage.setItem(k, v); } catch(e) {} }
  function localStorage_safe_get(k){ try { return window.localStorage.getItem(k); } catch(e) { return null; } }
    // Scanner API Integration

  const scanButton = document.getElementById("scanButton");

  if (scanButton) {

    scanButton.addEventListener("click", async () => {

      const domain = document.getElementById("domain").value;

      if (!domain) {
        alert("Enter domain");
        return;
      }

      try {

        const response = await fetch(
          "/scanner/scan",
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json"
            },
            body: JSON.stringify({
              target: domain
            })
          }
        );


        const data = await response.json();
        // ------------------------------
// Member 3 (AI) -> Member 4 (UI)
// ------------------------------

const riskScore = document.getElementById("riskScore");
const securityScore = document.getElementById("securityScore");
const threatLevel = document.getElementById("threatLevel");
const recommendations = document.getElementById("recommendations");

if (riskScore)
    riskScore.innerText = data.ai_analysis.risk_score ?? "-";

if (securityScore)
    securityScore.innerText = data.ai_analysis.security_score ?? "-";

if (threatLevel)
    threatLevel.innerText =
        data.ai_analysis.threat?.threat_level ?? "-";

if (recommendations)
    recommendations.innerHTML =
        data.ai_analysis.recommendations
            .map(r => `<li>${r.title}</li>`)
            .join("");

        console.log("Scanner Result:", data);


        // AI Analysis
        if(data.ai_analysis){

          console.log(
            "Risk:",
            data.ai_analysis.risk_score
          );

          console.log(
            "Security:",
            data.ai_analysis.security_score
          );

          console.log(
            "Recommendations:",
            data.ai_analysis.recommendations
          );

        }


      } catch(error){

        console.error(
          "Scan Error:",
          error
        );

      }

    });

  }
  document.getElementById("scanBtn")?.addEventListener("click", async () => {

    const targetInput = document.getElementById("targetInput");
    const scanResult = document.getElementById("scanResult");

    if (!targetInput || !scanResult) {
      return;
    }

    const target = targetInput.value.trim();

  try {
    const response = await fetch("/scanner/scan", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            target: target
        })
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.message || data.error || "Scan failed");
    }

    console.log(data);

    // Member 2 ka data
    scanResult.innerText =
        JSON.stringify(data.data, null, 2);

  } catch(err){

    console.error(err);
    scanResult.innerText = err.message;

}
});
});
