/**
 * SentinelASM - Theme & Accent Switcher
 * ======================================
 * Applies dark/light/system theme and accent color instantly on click,
 * then persists the choice server-side (Setting table, per-user) via
 * POST /settings/theme so it survives a refresh or a new session.
 */
(function () {
  "use strict";

  function csrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") : "";
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
  }

  function applyAccent(accent) {
    document.documentElement.setAttribute("data-accent", accent);
  }

  function persist(payload) {
    return fetch("/settings/theme", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": csrfToken(),
      },
      body: JSON.stringify(payload),
    }).then(function (res) {
      if (!res.ok) {
        throw new Error("Failed to save theme preference");
      }
      return res.json();
    });
  }

  function toast(message, isError) {
    if (window.showToast) {
      window.showToast(message, isError ? "danger" : "success");
      return;
    }
    // Minimal fallback toast if main.js's toast helper isn't present.
    var el = document.createElement("div");
    el.textContent = message;
    el.style.cssText =
      "position:fixed;bottom:20px;right:20px;z-index:9999;padding:10px 16px;" +
      "border-radius:10px;color:#fff;font-size:14px;" +
      "background:" + (isError ? "#E5484D" : "#17C990") + ";" +
      "box-shadow:0 8px 24px rgba(0,0,0,.35);";
    document.body.appendChild(el);
    setTimeout(function () { el.remove(); }, 2500);
  }

  function initThemeSwatches() {
    var swatches = document.querySelectorAll("[data-theme-choice]");
    swatches.forEach(function (el) {
      el.style.cursor = "pointer";
      el.addEventListener("click", function () {
        var theme = el.getAttribute("data-theme-choice");
        applyTheme(theme);
        swatches.forEach(function (s) { s.classList.toggle("theme-swatch-active", s === el); });
        persist({ theme: theme })
          .then(function () { toast("Theme updated to " + theme + "."); })
          .catch(function () { toast("Couldn't save theme preference.", true); });
      });
    });
  }

  function initAccentSwatches() {
    var swatches = document.querySelectorAll("[data-accent-choice]");
    swatches.forEach(function (el) {
      el.style.cursor = "pointer";
      el.addEventListener("click", function () {
        var accent = el.getAttribute("data-accent-choice");
        applyAccent(accent);
        swatches.forEach(function (s) { s.classList.toggle("accent-swatch-active", s === el); });
        persist({ accent: accent })
          .then(function () { toast("Accent color updated."); })
          .catch(function () { toast("Couldn't save accent preference.", true); });
      });
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    initThemeSwatches();
    initAccentSwatches();
  });
})();
