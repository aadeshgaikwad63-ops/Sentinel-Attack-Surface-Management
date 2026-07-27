"""
SentinelASM - Authentication Blueprint
=========================================

Handles user-facing authentication pages (register/login/logout/password
reset) as well as the JSON REST Authentication API used by non-browser
clients (e.g. CLI tools, other SentinelASM services).
"""

from flask import Blueprint

auth_bp = Blueprint(
    "auth", __name__, template_folder="../templates/auth", url_prefix="/auth"
)

api_auth_bp = Blueprint("api_auth", __name__, url_prefix="/api/auth")

# Import routes at the bottom to avoid circular imports while still
# registering all view functions on the blueprints above.
from app.auth import routes, api  # noqa: E402,F401
