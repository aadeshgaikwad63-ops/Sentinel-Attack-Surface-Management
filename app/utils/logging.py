"""
SentinelASM - Logging Configuration
======================================

Configures both:
    1. Standard Python/Flask application logging (rotating file handler),
       used for operational/debugging logs.
    2. Database-backed audit logging (via the `Log` model), used for
       security-relevant events such as logins and password resets.
"""

import logging
import os
from logging.handlers import RotatingFileHandler

from flask import has_request_context, request


class RequestContextFilter(logging.Filter):
    """Injects the requesting IP address into log records when available."""

    def filter(self, record):
        if has_request_context():
            record.remote_addr = request.remote_addr
        else:
            record.remote_addr = "-"
        return True


def configure_logging(app):
    """Attach a rotating file handler (and console handler) to the Flask app."""
    log_level = getattr(logging, app.config.get("LOG_LEVEL", "INFO").upper(), logging.INFO)
    app.logger.setLevel(log_level)

    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)s in %(module)s (ip=%(remote_addr)s): %(message)s"
    )
    context_filter = RequestContextFilter()

    # Console handler - always enabled.
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.addFilter(context_filter)
    console_handler.setLevel(log_level)
    app.logger.addHandler(console_handler)

    # Rotating file handler - optional, controlled via LOG_TO_FILE.
    if app.config.get("LOG_TO_FILE", True):
        log_dir = app.config.get("LOG_DIR")
        os.makedirs(log_dir, exist_ok=True)
        file_handler = RotatingFileHandler(
            os.path.join(log_dir, "sentinelasm.log"),
            maxBytes=5 * 1024 * 1024,  # 5 MB per file
            backupCount=5,
        )
        file_handler.setFormatter(formatter)
        file_handler.addFilter(context_filter)
        file_handler.setLevel(log_level)
        app.logger.addHandler(file_handler)

    app.logger.info("SentinelASM logging initialized (level=%s)", app.config.get("LOG_LEVEL"))


def log_action(action: str, user_id: int = None, details: str = None, level: str = "info"):
    """
    Persist a security/audit event to the database `Log` table, capturing
    the current request's IP address and User-Agent when available.

    This is deliberately import-local (rather than a top-level import) to
    avoid circular imports between utils and models.
    """
    from app.models import Log

    ip_address = request.remote_addr if has_request_context() else None
    user_agent = (
        request.headers.get("User-Agent", "")[:255] if has_request_context() else None
    )
    Log.record(
        action=action,
        user_id=user_id,
        details=details,
        ip_address=ip_address,
        user_agent=user_agent,
        level=level,
    )
