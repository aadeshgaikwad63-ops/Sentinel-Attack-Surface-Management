# SentinelASM — Frontend UI Kit

Dark-theme, Bootstrap 5 + Chart.js frontend for the Sentinel Attack Surface
Management platform. **Templates and static assets only** — no Python,
Flask auth, or SQLAlchemy logic was touched, per project rules. `app.py` is
a thin preview scaffold (plain routes, `render_template` only) so you can
click through the UI; swap it for the real backend's routes/blueprints.

## Structure

```
templates/
  base.html              # shared shell: sidebar + topbar + content block
  components/
    sidebar.html          # left nav, active-state highlighting via `active_page`
    navbar.html           # search, notifications, theme toggle, user menu
  login.html               # standalone (no sidebar/topbar)
  register.html            # standalone (no sidebar/topbar)
  dashboard.html
  assets.html
  new_scan.html
  scan_results.html
  vulnerability_details.html
  ai_assistant.html
  reports.html
  user_management.html
  profile.html
  settings.html
static/
  css/theme.css           # design tokens + every component style
  js/main.js              # sidebar collapse/mobile toggle, theme toggle
  js/charts.js            # Chart.js dark-theme defaults + gradient helper
```

## Wiring into the real app

Every page extends `base.html` and sets `{% set active_page = '...' %}` to
drive sidebar highlighting. All internal links use `url_for('endpoint')`, so
your Flask blueprint endpoints must be named to match:
`dashboard, assets, new_scan, scan_results, vulnerability_details,
ai_assistant, reports, user_management, profile, settings, login, register, logout`.

Swap the hard-coded example rows (assets, users, scan data, chat messages)
for real data passed from your view functions — the markup already loops
over Jinja-friendly lists/dicts in `assets.html` and `user_management.html`
as a pattern to follow for the rest.

## Design system

- **Signature motif — "Sweep Ring":** a rotating radar-arc reused on the
  Security Score gauge, the scan-in-progress loader, and the sidebar mark,
  so "scanning your attack surface" is felt, not just labeled.
- **Palette:** background `#0B1220`, cards `#1F2937`, sidebar `#111827`,
  green accent `#17C990`, blue `#3E8EF7`, amber `#F5A524`, red `#F0465B`,
  purple (AI) `#8B6BF2`.
- **Type:** Space Grotesk for headings, Inter for body copy, JetBrains Mono
  for every data readout (scores, IPs, ports, CVE IDs, hashes) — a small
  but consistent tell that a number is a live reading, not prose.
- Respects `prefers-reduced-motion`; sidebar collapses to an icon rail on
  desktop and becomes an off-canvas drawer on mobile.

## Preview locally

```bash
pip install flask
python app.py
# open http://127.0.0.1:5000
```
