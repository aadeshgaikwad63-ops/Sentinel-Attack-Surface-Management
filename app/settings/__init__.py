"""
SentinelASM - Settings Blueprint
==================================

Global/workspace configuration (notifications, API, security, SMTP) backed
by the key/value `Setting` model, plus an admin-only audit log view.
"""

from flask import Blueprint

settings_bp = Blueprint(
    "settings",
    __name__,
    url_prefix="/settings",
)

from app.settings import routes  # noqa: E402,F401
