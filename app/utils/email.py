"""
SentinelASM - Email Helper
=============================

Lightweight email dispatch used for password reset notifications.

No third-party mail library is required at this stage - this module wraps
Python's standard `smtplib` using the MAIL_* configuration values. If mail
is not configured (development environments), the message is logged
instead of sent so developers can retrieve reset links without a live SMTP
server.
"""

import smtplib
from email.message import EmailMessage

from flask import current_app


def _smtp_config():
    """
    Resolve effective SMTP configuration.

    Admin-configured values stored in the `settings` table (via the
    Settings > SMTP screen) take priority over the MAIL_* environment/
    config defaults, so the app config values act as a fallback the very
    first time an admin visits the page before anything is saved.
    """
    from app.models import Setting

    stored_tls = Setting.get("smtp_use_tls")
    return {
        "server": Setting.get("smtp_host") or current_app.config.get("MAIL_SERVER"),
        "port": int(Setting.get("smtp_port") or current_app.config.get("MAIL_PORT", 587)),
        "username": Setting.get("smtp_username") or current_app.config.get("MAIL_USERNAME"),
        "password": Setting.get("smtp_password") or current_app.config.get("MAIL_PASSWORD"),
        "use_tls": (stored_tls == "1") if stored_tls is not None else bool(current_app.config.get("MAIL_USE_TLS")),
        "sender": Setting.get("smtp_sender") or current_app.config.get("MAIL_DEFAULT_SENDER"),
    }


def send_email(to_email: str, subject: str, body: str):
    """
    Send a plaintext email using the effective SMTP configuration.

    Returns (success: bool, message: str) so callers (e.g. the "Send Test
    Email" button) can surface a precise error instead of a generic failure.
    """
    cfg = _smtp_config()

    if not cfg["server"] or not cfg["username"]:
        return False, "SMTP is not configured yet. Fill in host and username first."

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = cfg["sender"] or cfg["username"]
    message["To"] = to_email
    message.set_content(body)

    try:
        with smtplib.SMTP(cfg["server"], cfg["port"], timeout=10) as smtp:
            if cfg["use_tls"]:
                smtp.starttls()
            if cfg["password"]:
                smtp.login(cfg["username"], cfg["password"])
            smtp.send_message(message)
        return True, f"Test email sent to {to_email}."
    except (smtplib.SMTPException, OSError) as exc:
        current_app.logger.error("SMTP send failed: %s", exc)
        return False, f"Failed to send: {exc}"


def send_password_reset_email(to_email: str, reset_url: str) -> bool:
    """
    Send a password reset email to `to_email` containing `reset_url`.

    Returns True if the message was dispatched (or logged in dev mode),
    False if a send failure occurred.
    """
    subject = "SentinelASM - Password Reset Request"
    body = (
        "You requested a password reset for your SentinelASM account.\n\n"
        f"Reset your password using the link below:\n{reset_url}\n\n"
        "This link will expire shortly. If you did not request this, "
        "you can safely ignore this email."
    )

    cfg = _smtp_config()

    # In local/dev environments without real SMTP credentials configured,
    # avoid attempting a network call - just log the link for convenience.
    if not cfg["server"] or not cfg["username"]:
        current_app.logger.info(
            "MAIL not configured - password reset link for %s: %s",
            to_email,
            reset_url,
        )
        return True

    success, message = send_email(to_email, subject, body)
    if not success:
        current_app.logger.error("Failed to send password reset email: %s", message)
    return success
