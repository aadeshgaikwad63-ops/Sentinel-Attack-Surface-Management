from flask import Blueprint

dashboard_bp = Blueprint(
    "dashboard",
    __name__,
    url_prefix="/dashboard",
)

# Import routes after blueprint creation to avoid circular imports.
# NOTE: this import was previously missing, which meant dashboard/routes.py
# was never executed and none of its view functions were ever attached to
# dashboard_bp - every dashboard URL 404'd despite the code existing.
from app.dashboard import routes  # noqa: E402,F401