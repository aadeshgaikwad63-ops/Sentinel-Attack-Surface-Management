// SentinelASM — shared interactions
document.addEventListener('DOMContentLoaded', () => {

  // Mobile sidebar toggle
  const sidebar   = document.getElementById('sentinelSidebar');
  const backdrop  = document.getElementById('sidebarBackdrop');
  const mToggle   = document.getElementById('sidebarToggle');
  const cToggle   = document.getElementById('sidebarCollapse');

  function openMobile(){ sidebar.classList.add('mobile-open'); backdrop.style.display = 'block'; }
  function closeMobile(){ sidebar.classList.remove('mobile-open'); backdrop.style.display = 'none'; }

  mToggle && mToggle.addEventListener('click', () => {
    sidebar.classList.contains('mobile-open') ? closeMobile() : openMobile();
  });
  backdrop && backdrop.addEventListener('click', closeMobile);

  // Desktop collapse (icon rail)
  if (cToggle) {
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
  document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(el => new bootstrap.Tooltip(el));

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
          "/api/scanner/scan",
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

if (data.ai_analysis) {

    document.getElementById("riskScore").innerText =
        data.ai_analysis.risk_score ?? "-";

    document.getElementById("securityScore").innerText =
        data.ai_analysis.security_score ?? "-";

    document.getElementById("threatLevel").innerText =
        data.ai_analysis.threat.threat_level ?? "-";

    document.getElementById("recommendations").innerHTML =
        data.ai_analysis.recommendations
            .map(r => `<li>${r.title}</li>`)
            .join("");

}

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

    const target = document.getElementById("targetInput").value;

    const response = await fetch("/api/scanner/scan", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            target: target
        })
    });

    const data = await response.json();

    console.log(data);

    // Member 2 ka data
    document.getElementById("scanResult").innerText =
        JSON.stringify(data.data, null, 2);
});
});
