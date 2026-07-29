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
});
