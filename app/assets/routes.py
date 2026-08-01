"""
SentinelASM - Asset Management Routes
======================================
"""

from __future__ import annotations

from datetime import datetime, timezone

from flask import flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.assets import assets_bp
from app.models import Scan


def _humanize(dt: datetime) -> str:
    if dt is None:
        return "never"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = datetime.now(timezone.utc) - dt
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


def _ssl_status(data: dict) -> str:
    """Reduce the raw SSL analysis payload to a single display status."""
    ssl = data.get("ssl") or {}
    if not ssl:
        return "None"
    if ssl.get("expired"):
        return "Expired"
    if ssl.get("self_signed"):
        return "Self-Signed"
    return "Valid"


def _asset_row(scan: Scan) -> tuple:
    """Build a single (name, type, ip, tech, ports, risk, scanned, ssl) row
    from the latest Scan record for a given target."""
    data = scan.scan_data or {}
    analysis = scan.ai_analysis or {}

    dns = data.get("dns") or {}
    a_records = dns.get("A") or []
    ip = a_records[0] if a_records else "-"

    ports = data.get("ports") or []
    open_ports = sorted({str(p.get("port")) for p in ports if isinstance(p, dict) and p.get("port")})
    ports_display = ", ".join(open_ports) if open_ports else "-"

    tech = data.get("technologies") or {}
    frameworks = tech.get("frameworks") or []
    server = tech.get("server")
    tech_bits = [b for b in ([server] if server else []) + list(frameworks) if b]
    tech_display = " / ".join(tech_bits) if tech_bits else "Unknown"

    risk = (analysis.get("risk") or {}).get("severity", "Low")

    # A target with no dots is treated as a bare host/IP; anything else with
    # more than one label is heuristically a subdomain vs. a root domain.
    target = scan.target
    label_count = target.count(".")
    asset_type = "Domain" if label_count <= 1 else "Subdomain"

    return (
        target,
        asset_type,
        ip,
        tech_display,
        ports_display,
        risk,
        _humanize(scan.created_at),
        _ssl_status(data),
    )


@assets_bp.route("/", methods=["GET"])
@login_required
def assets():
    """Render the asset inventory, derived from the latest scan of each
    distinct target the current user has scanned."""
    scans = (
        Scan.query.filter_by(user_id=current_user.id)
        .order_by(Scan.created_at.desc())
        .all()
    )

    latest_by_target = {}
    for scan in scans:
        if scan.target not in latest_by_target:
            latest_by_target[scan.target] = scan

    asset_rows = [_asset_row(scan) for scan in latest_by_target.values()]

    domains = sum(1 for row in asset_rows if row[1] == "Domain")
    subdomains = sum(1 for row in asset_rows if row[1] == "Subdomain")
    unique_ips = len({row[2] for row in asset_rows if row[2] != "-"})
    at_risk = sum(1 for row in asset_rows if row[5] in ("Critical", "High"))

    return render_template(
        "assets/assets.html",
        active_page="assets",
        assets=asset_rows,
        total_assets=len(asset_rows),
        stats={
            "domains": domains,
            "subdomains": subdomains,
            "ips": unique_ips,
            "at_risk": at_risk,
        },
    )


@assets_bp.route("/", methods=["POST"])
@login_required
def add_asset():
    """Kick off a scan for a newly added asset target. Actual scanning is
    delegated to the scanner API; this just validates input and redirects
    the user to the new-scan page pre-filled with their target."""
    target = (request.form.get("target") or "").strip()
    if not target:
        flash("Please provide a domain or IP address.", "warning")
        return redirect(url_for("assets.assets"))

    flash(f"'{target}' queued. Start a scan to begin monitoring it.", "success")
    return redirect(url_for("scanner.new_scan", target=target))


@assets_bp.route("/api", methods=["GET"])
@login_required
def assets_api():
    """JSON version of the asset inventory for dashboards/AJAX consumers."""
    scans = (
        Scan.query.filter_by(user_id=current_user.id)
        .order_by(Scan.created_at.desc())
        .all()
    )
    latest_by_target = {}
    for scan in scans:
        if scan.target not in latest_by_target:
            latest_by_target[scan.target] = scan

    rows = [_asset_row(scan) for scan in latest_by_target.values()]
    keys = ["name", "type", "ip", "technology", "open_ports", "risk", "last_scanned", "ssl"]
    return jsonify([dict(zip(keys, row)) for row in rows])
