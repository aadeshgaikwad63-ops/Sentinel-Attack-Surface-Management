/**
 * SentinelASM — Landing page interactions.
 * Pure front-end enhancement layer. No calls to authenticated routes,
 * no changes to auth/session logic — this file only touches DOM it owns
 * inside .sasm.
 */
(function () {
  "use strict";

  var reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ---------------- Mobile nav ---------------- */
  var toggle = document.querySelector(".js-nav-toggle");
  var mobileNav = document.querySelector(".js-mobile-nav");
  if (toggle && mobileNav) {
    toggle.addEventListener("click", function () {
      var open = mobileNav.classList.toggle("open");
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
      document.body.style.overflow = open ? "hidden" : "";
    });
    mobileNav.querySelectorAll("a").forEach(function (a) {
      a.addEventListener("click", function () {
        mobileNav.classList.remove("open");
        toggle.setAttribute("aria-expanded", "false");
        document.body.style.overflow = "";
      });
    });
  }

  /* ---------------- Hero floating particles + mouse interaction ----------------
   * Purely decorative CSS-driven particles seeded once on load, plus a light
   * parallax tilt on the hero visual that tracks pointer position. No network
   * calls, no state — safe progressive enhancement.
   */
  var particleField = document.querySelector(".js-hero-particles");
  if (particleField && !reducedMotion) {
    var particleColors = ["var(--accent)", "var(--info)"];
    var PARTICLE_COUNT = 26;
    for (var p = 0; p < PARTICLE_COUNT; p++) {
      var dot = document.createElement("span");
      dot.className = "hero-particle";
      dot.style.left = Math.random() * 100 + "%";
      dot.style.top = Math.random() * 100 + "%";
      dot.style.setProperty("--p-size", (2 + Math.random() * 3).toFixed(1) + "px");
      dot.style.setProperty("--p-color", particleColors[p % particleColors.length]);
      dot.style.setProperty("--p-dur", (8 + Math.random() * 10).toFixed(1) + "s");
      dot.style.setProperty("--p-delay", (Math.random() * -12).toFixed(1) + "s");
      dot.style.setProperty("--p-dx", (Math.random() * 40 - 20).toFixed(0) + "px");
      dot.style.setProperty("--p-dy", (Math.random() * 40 - 20).toFixed(0) + "px");
      particleField.appendChild(dot);
    }
  }

  var heroSection = document.querySelector(".hero");
  var heroVisual = document.querySelector(".hero-visual");
  if (heroSection && heroVisual && !reducedMotion && window.matchMedia("(min-width: 961px)").matches) {
    heroSection.addEventListener("mousemove", function (e) {
      var rect = heroSection.getBoundingClientRect();
      var px = (e.clientX - rect.left) / rect.width - 0.5;
      var py = (e.clientY - rect.top) / rect.height - 0.5;
      heroVisual.style.transform = "perspective(900px) rotateY(" + (px * 4) + "deg) rotateX(" + (py * -4) + "deg)";
    });
    heroSection.addEventListener("mouseleave", function () {
      heroVisual.style.transform = "";
    });
  }

  /* ---------------- Scroll reveal ---------------- */
  var revealEls = document.querySelectorAll(".reveal");
  if ("IntersectionObserver" in window && !reducedMotion) {
    var io = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add("is-visible");
            io.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.15 }
    );
    revealEls.forEach(function (el) { io.observe(el); });
  } else {
    revealEls.forEach(function (el) { el.classList.add("is-visible"); });
  }

  /* ---------------- FAQ accordion ---------------- */
  document.querySelectorAll(".js-faq-item").forEach(function (item) {
    var btn = item.querySelector(".faq-q");
    btn.addEventListener("click", function () {
      var wasOpen = item.classList.contains("open");
      item.parentElement.querySelectorAll(".js-faq-item").forEach(function (other) {
        other.classList.remove("open");
        other.querySelector(".faq-q").setAttribute("aria-expanded", "false");
      });
      if (!wasOpen) {
        item.classList.add("open");
        btn.setAttribute("aria-expanded", "true");
      }
    });
  });

  /* ---------------- Pricing monthly/annual toggle ---------------- */
  var pricingSwitch = document.querySelector(".js-pricing-switch");
  if (pricingSwitch) {
    pricingSwitch.addEventListener("click", function () {
      var annual = pricingSwitch.classList.toggle("on");
      pricingSwitch.setAttribute("aria-checked", annual ? "true" : "false");
      document.querySelectorAll(".js-price").forEach(function (priceEl) {
        var monthly = priceEl.getAttribute("data-monthly");
        var yearly = priceEl.getAttribute("data-annual");
        priceEl.textContent = annual ? yearly : monthly;
      });
      document.querySelectorAll(".js-price-period").forEach(function (el) {
        el.textContent = annual ? "/mo, billed annually" : "/month";
      });
    });
  }

  /* ---------------- Screenshot tabs ---------------- */
  var tabButtons = document.querySelectorAll(".js-shot-tab");
  var panels = document.querySelectorAll(".js-shot-panel");
  tabButtons.forEach(function (btn) {
    btn.addEventListener("click", function () {
      tabButtons.forEach(function (b) { b.classList.remove("active"); b.setAttribute("aria-selected", "false"); });
      panels.forEach(function (p) { p.hidden = true; });
      btn.classList.add("active");
      btn.setAttribute("aria-selected", "true");
      var target = document.getElementById(btn.getAttribute("data-target"));
      if (target) target.hidden = false;
    });
  });

  /* ---------------- Contact / newsletter forms (front-end only) ----------------
   * These forms are not wired to a backend endpoint in Phase 1 (no server
   * route exists yet, and creating one is a backend change out of scope).
   * We prevent a hard page navigation and show an inline confirmation so
   * the UI is fully demonstrable; swap this for a real fetch() to a Flask
   * endpoint when one is added.
   */
  document.querySelectorAll(".js-frontend-form").forEach(function (form) {
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var note = form.querySelector(".js-form-note");
      if (note) {
        note.textContent = "Thanks — this is a UI preview. Hook this form up to a backend endpoint to go live.";
        note.hidden = false;
      }
      form.reset();
    });
  });

  /* ---------------- Signature element: live attack-surface graph ----------------
   * Canvas-based force-ish network animation representing discovered assets
   * (nodes) and their live-scanned exposure state (colour). Purely
   * decorative/illustrative — no real scan data, no network calls.
   */
  var canvas = document.querySelector(".js-graph-canvas");
  if (canvas && canvas.getContext) {
    var ctx = canvas.getContext("2d");
    var DPR = Math.min(window.devicePixelRatio || 1, 2);
    var w, h;
    var STATES = [
      { color: "#00e676", weight: 6 },  /* secured */
      { color: "#3b82f6", weight: 3 },  /* monitoring */
      { color: "#d29922", weight: 2 },  /* exposed */
      { color: "#f85149", weight: 1 }   /* critical */
    ];
    var weightedPool = [];
    STATES.forEach(function (s) { for (var i = 0; i < s.weight; i++) weightedPool.push(s.color); });

    function resize() {
      var rect = canvas.getBoundingClientRect();
      w = rect.width; h = rect.height;
      canvas.width = w * DPR;
      canvas.height = h * DPR;
      ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
    }

    var NODE_COUNT = 22;
    var nodes = [];
    function buildNodes() {
      nodes = [];
      for (var i = 0; i < NODE_COUNT; i++) {
        nodes.push({
          x: Math.random() * w,
          y: Math.random() * h,
          vx: (Math.random() - 0.5) * 0.18,
          vy: (Math.random() - 0.5) * 0.18,
          r: 2.4 + Math.random() * 2.2,
          color: weightedPool[Math.floor(Math.random() * weightedPool.length)],
          pulse: Math.random() * Math.PI * 2
        });
      }
    }

    var LINK_DIST = 120;
    var scanAngle = 0;

    function step() {
      ctx.clearRect(0, 0, w, h);

      /* connections */
      for (var i = 0; i < nodes.length; i++) {
        for (var j = i + 1; j < nodes.length; j++) {
          var a = nodes[i], b = nodes[j];
          var dx = a.x - b.x, dy = a.y - b.y;
          var dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < LINK_DIST) {
            ctx.strokeStyle = "rgba(139, 152, 165, " + (0.14 * (1 - dist / LINK_DIST)) + ")";
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.stroke();
          }
        }
      }

      /* radar sweep, ties the animation to "active scanning" */
      var cx = w / 2, cy = h / 2, sweepR = Math.max(w, h) * 0.75;
      var grad = ctx.createConicGradient ? ctx.createConicGradient(scanAngle, cx, cy) : null;
      if (grad) {
        grad.addColorStop(0, "rgba(63,185,80,0.16)");
        grad.addColorStop(0.06, "rgba(63,185,80,0)");
        grad.addColorStop(1, "rgba(63,185,80,0)");
        ctx.fillStyle = grad;
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.arc(cx, cy, sweepR, 0, Math.PI * 2);
        ctx.fill();
      }
      scanAngle += reducedMotion ? 0 : 0.012;

      /* nodes */
      nodes.forEach(function (n) {
        if (!reducedMotion) {
          n.x += n.vx; n.y += n.vy;
          if (n.x < 0 || n.x > w) n.vx *= -1;
          if (n.y < 0 || n.y > h) n.vy *= -1;
          n.pulse += 0.03;
        }
        var glow = 0.5 + Math.sin(n.pulse) * 0.5;
        ctx.beginPath();
        ctx.fillStyle = n.color;
        ctx.globalAlpha = 0.85;
        ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
        ctx.fill();
        ctx.globalAlpha = 0.18 * glow;
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r + 5, 0, Math.PI * 2);
        ctx.fill();
        ctx.globalAlpha = 1;
      });

      if (!reducedMotion) requestAnimationFrame(step);
    }

    resize();
    buildNodes();
    step();
    window.addEventListener("resize", function () {
      resize();
      buildNodes();
      if (reducedMotion) step();
    });
  }
})();
