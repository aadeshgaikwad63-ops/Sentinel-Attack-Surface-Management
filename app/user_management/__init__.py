"""
SentinelASM - User Management Blueprint
=========================================

Admin-only screens for managing platform users: inviting, editing roles,
suspending/activating, and removing accounts. Restricted to the "admin"
RBAC role via app.utils.decorators.admin_required.
"""

from flask import Blueprint

user_management_bp = Blueprint(
    "user_management",
    __name__,
    url_prefix="/user-management",
)

from app.user_management import routes  # noqa: E402,F401
