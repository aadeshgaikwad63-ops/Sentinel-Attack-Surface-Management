"""
SentinelASM - Error Handling Blueprint
==========================================

Centralized HTTP error handlers (404, 403, 401, 500, CSRF failures, rate
limit exceeded) with content negotiation: JSON for API clients, HTML for
browser clients.
"""

from flask import Blueprint

errors_bp = Blueprint("errors", __name__, template_folder="../templates/errors")

from app.errors import handlers  # noqa: E402,F401
