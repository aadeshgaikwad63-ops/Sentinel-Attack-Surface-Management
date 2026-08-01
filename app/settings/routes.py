"""
SentinelASM - Settings Routes
===============================
"""

from __future__ import annotations

from flask import flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.extensions import db
from app.models import Log
from app.settings import settings_bp
from app.utils.decorators import admin_required
from app.utils.email import send_email
from app.utils.logging import log_action

THEME_CHOICES = {"dark", "light", "system"}
ACCENT_CHOICES = {"green", "blue", "purple", "orange"}

NOTIFICATION_DEFS = [
    ("notif_critical_cve", "Critical vulnerability alerts", "Notify immediately when a critical CVE is found", True),
    ("notif_scan_complete", "Scan completion", "Email when a scan finishes", True),
    ("notif_ssl_expiry", "SSL expiry warnings", "Notify 14 days before certificate expiry", True),
    ("notif_weekly_digest", "Weekly digest", "Summary of posture changes every Monday", False),
]


def _pref_key(user_id: int, name: str) -> str:
    return f"user:{user_id}:{name}"


def _get_notification_prefs(user_id: int):
    from app.models import Setting

    prefs = []
    for key, label, sub, default in NOTIFICATION_DEFS:
        stored = Setting.get(_pref_key(user_id, key))
        checked = (stored == "1") if stored is not None else default
        prefs.append((label, sub, checked, key))
    return prefs


def get_user_theme(user_id: int) -> str:
    from app.models import Setting

    value = Setting.get(_pref_key(user_id, "theme"))
    return value if value in THEME_CHOICES else "dark"


def get_user_accent(user_id: int) -> str:
    from app.models import Setting

    value = Setting.get(_pref_key(user_id, "accent"))
    return value if value in ACCENT_CHOICES else "green"


@settings_bp.route("/", methods=["GET"])
@login_required
def settings():
    from app.models import Setting

    prefs = _get_notification_prefs(current_user.id)
    smtp_config = {
        "host": Setting.get("smtp_host", ""),
        "port": Setting.get("smtp_port", "587"),
        "username": Setting.get("smtp_username", ""),
        "use_tls": Setting.get("smtp_use_tls", "1") == "1",
        "sender": Setting.get("smtp_sender", ""),
        "configured": bool(Setting.get("smtp_host")),
    }
    return render_template(
        "settings/settings.html",
        active_page="settings",
        notification_prefs=prefs,
        current_theme=get_user_theme(current_user.id),
        current_accent=get_user_accent(current_user.id),
        smtp_config=smtp_config,
    )


@settings_bp.route("/theme", methods=["POST"])
@login_required
def update_theme():
    """
    Persist the caller's theme + accent choice and apply it instantly.

    Called via fetch() from the theme swatches so the UI updates without a
    full page reload; the value is stored server-side (Setting table) so it
    survives a refresh or a new session.
    """
    from app.models import Setting

    data = request.get_json(silent=True) or request.form
    theme = (data.get("theme") or "").strip().lower()
    accent = (data.get("accent") or "").strip().lower()

    if theme and theme not in THEME_CHOICES:
        return jsonify({"error": f"Invalid theme '{theme}'."}), 400
    if accent and accent not in ACCENT_CHOICES:
        return jsonify({"error": f"Invalid accent '{accent}'."}), 400

    if theme:
        Setting.set(_pref_key(current_user.id, "theme"), theme)
    if accent:
        Setting.set(_pref_key(current_user.id, "accent"), accent)

    return jsonify({
        "theme": get_user_theme(current_user.id),
        "accent": get_user_accent(current_user.id),
    })


@settings_bp.route("/smtp", methods=["POST"])
@login_required
@admin_required
def update_smtp():
    from app.models import Setting

    host = (request.form.get("smtp_host") or "").strip()
    port = (request.form.get("smtp_port") or "587").strip()
    username = (request.form.get("smtp_username") or "").strip()
    password = request.form.get("smtp_password") or ""
    sender = (request.form.get("smtp_sender") or "").strip()
    use_tls = "1" if request.form.get("smtp_use_tls") == "on" else "0"

    if not host or not username:
        flash("SMTP host and username are required.", "warning")
        return redirect(url_for("settings.settings"))

    Setting.set("smtp_host", host)
    Setting.set("smtp_port", port)
    Setting.set("smtp_username", username)
    if password:
        # Only overwrite the stored password if a new one was actually
        # typed - the form re-renders with the field blank for security,
        # so an empty submit should keep the existing credential.
        Setting.set("smtp_password", password)
    Setting.set("smtp_sender", sender)
    Setting.set("smtp_use_tls", use_tls)

    log_action("smtp_settings_updated", user_id=current_user.id, details=f"host={host}")

    flash("SMTP settings saved.", "success")
    return redirect(url_for("settings.settings"))


@settings_bp.route("/smtp/test", methods=["POST"])
@login_required
@admin_required
def test_smtp():
    """Send a real test email using whatever SMTP config is currently saved."""
    to_email = (request.form.get("test_email") or current_user.email or "").strip()
    if not to_email:
        return jsonify({"success": False, "message": "No recipient email address available."}), 400

    success, message = send_email(
        to_email,
        subject="SentinelASM - SMTP Test Email",
        body=(
            "This is a test email from SentinelASM.\n\n"
            "If you received this, your SMTP configuration is working correctly."
        ),
    )
    return jsonify({"success": success, "message": message}), (200 if success else 502)


@settings_bp.route("/notifications", methods=["POST"])
@login_required
def update_notifications():
    from app.models import Setting

    for key, _label, _sub, _default in NOTIFICATION_DEFS:
        checked = request.form.get(key) == "on"
        Setting.set(_pref_key(current_user.id, key), "1" if checked else "0")

    flash("Notification preferences saved.", "success")
    return redirect(url_for("settings.settings"))


@settings_bp.route("/audit-logs", methods=["GET"])
@login_required
@admin_required
def audit_logs():
    page = request.args.get("page", 1, type=int)
    pagination = Log.query.order_by(Log.created_at.desc()).paginate(
        page=page, per_page=25, error_out=False
    )
    return render_template(
        "settings/audit_logs.html",
        active_page="settings",
        logs=pagination.items,
        pagination=pagination,
    )
