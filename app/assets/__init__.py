"""
SentinelASM - Asset Management Blueprint
=========================================

Derives the organization's asset inventory (domains, subdomains, hosts)
directly from historical scan data rather than a separate, hand-maintained
table - every scanned target automatically becomes a tracked asset, and
its latest scan always reflects its current risk posture.
"""

from flask import Blueprint

assets_bp = Blueprint(
    "assets",
    __name__,
    url_prefix="/assets",
)

from app.assets import routes  # noqa: E402,F401
