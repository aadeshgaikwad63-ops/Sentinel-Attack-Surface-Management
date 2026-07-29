"""
SentinelASM - General API Blueprint
======================================

Root namespace for the platform's REST API (`/api`). This blueprint is
intentionally minimal - it only exposes a health/version endpoint here.

Other teams building feature APIs (scanners, dashboard, reports, AI, etc.)
should register their own blueprints under the `/api/<feature>` prefix in
their own modules and wire them into the application factory. Do not add
feature-specific routes to this file; extend it only with endpoints that
belong to the platform foundation itself.
"""

from flask import Blueprint

api_bp = Blueprint("api", __name__, url_prefix="/api")

from app.api import routes  # noqa: E402,F401
