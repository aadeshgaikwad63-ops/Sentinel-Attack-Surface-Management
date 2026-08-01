"""
SentinelASM - Foundation API Routes
======================================

Minimal platform-level endpoints (health check, version info). Feature
teams (scanners, AI, dashboard, reports) should implement their own
blueprints rather than extending this module.
"""

from flask import current_app, jsonify

from app.api import api_bp
from app.extensions import csrf 
"""
from app.scanner.scanner_manager import ScannerManager
"""

# Health checks are typically hit by load balancers/monitoring without a
# CSRF-bearing session, so this namespace is exempt from CSRF checks.
csrf.exempt(api_bp)


@api_bp.route("/health", methods=["GET"])
def health():
    """Simple liveness/readiness probe for the backend service."""
    return jsonify({"status": "ok", "service": "SentinelASM"}), 200


@api_bp.route("/version", methods=["GET"])
def version():
    """Report the running application version/environment."""
    return (
        jsonify(
            {
                "name": "SentinelASM",
                "version": current_app.config.get("APP_VERSION", "0.1.0"),
                "environment": current_app.config.get("FLASK_ENV", "unknown"),
            }
        ),
        200,
    )
