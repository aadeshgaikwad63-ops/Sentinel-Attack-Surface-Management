"""
SentinelASM - User Profile Blueprint
========================================

Handles the authenticated user's own profile: viewing account details,
updating profile fields, changing password, and managing personal API
access tokens.
"""

from flask import Blueprint

profile_bp = Blueprint(
    "profile", __name__, template_folder="../templates/profile", url_prefix="/profile"
)

from app.profile import routes  # noqa: E402,F401
