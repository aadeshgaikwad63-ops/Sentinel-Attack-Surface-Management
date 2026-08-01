from flask import render_template, jsonify
from flask_login import login_required, current_user

from app.models.scan import Scan
from app.dashboard import dashboard_bp
from app.dashboard.analytics import build_overview


@dashboard_bp.route("/")
@login_required
def dashboard():
    overview = build_overview(current_user.id)
    return render_template(
        "dashboard/dashboard.html",
        active_page="dashboard",
        overview=overview,
    )


@dashboard_bp.route("/overview")
@login_required
def overview_data():
    """
    JSON feed for the dashboard's manual "Refresh" action and for the
    initial Chart.js bootstrap. Same aggregation used to render the
    page server-side on load, exposed as an endpoint so the widgets can
    be refreshed without a full page reload.
    """
    return jsonify(build_overview(current_user.id))

@dashboard_bp.route("/latest")
@login_required
def latest_scan():
    latest_scan = (
        Scan.query
        .filter_by(user_id=current_user.id)
        .order_by(Scan.created_at.desc())
        .first()
    )

    if latest_scan is None:
        return jsonify({})

    return jsonify({
        "data": latest_scan.scan_data,
        "ai_analysis": latest_scan.ai_analysis,
        "created_at": latest_scan.created_at.isoformat()
    })