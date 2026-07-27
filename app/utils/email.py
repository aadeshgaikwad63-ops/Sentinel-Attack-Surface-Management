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

    mail_server = current_app.config.get("MAIL_SERVER")
    mail_username = current_app.config.get("MAIL_USERNAME")

    # In local/dev environments without real SMTP credentials configured,
    # avoid attempting a network call - just log the link for convenience.
    if not mail_server or not mail_username:
        current_app.logger.info(
            "MAIL not configured - password reset link for %s: %s",
            to_email,
            reset_url,
        )
        return True

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = current_app.config.get("MAIL_DEFAULT_SENDER")
    message["To"] = to_email
    message.set_content(body)

    try:
        with smtplib.SMTP(mail_server, current_app.config.get("MAIL_PORT", 587)) as smtp:
            if current_app.config.get("MAIL_USE_TLS"):
                smtp.starttls()
            smtp.login(mail_username, current_app.config.get("MAIL_PASSWORD"))
            smtp.send_message(message)
        return True
    except (smtplib.SMTPException, OSError) as exc:
        current_app.logger.error("Failed to send password reset email: %s", exc)
        return False
