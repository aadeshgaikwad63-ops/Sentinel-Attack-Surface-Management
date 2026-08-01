"""
SentinelASM - Scanner Routes
============================

REST API endpoints for the Attack Surface Management scanner.
"""

from __future__ import annotations

from flask import jsonify, request, render_template, redirect, url_for
from flask_login import current_user, login_required

from app.extensions import csrf
from app.scanner import scanner_bp
from app.scanner.scanner_manager import ScannerManager
from app.ai.scanner_adapter import ScannerAdapter
from app.services.analysis_pipeline import AnalysisPipeline
from app.extensions import db
from app.models import Scan

# Scanner APIs are consumed by JavaScript/AJAX requests.
csrf.exempt(scanner_bp)

scanner_manager = ScannerManager()

@scanner_bp.route("/")
@login_required
def scanner_home():
    # No standalone scanner.html landing page exists; the new-scan form is
    # the natural entry point for this blueprint.
    return redirect(url_for("scanner.new_scan"))

@scanner_bp.route("/new")
@login_required
def new_scan():
    return render_template("scanner/new_scan.html", target=request.args.get("target", ""))

@scanner_bp.route("/results")
@login_required
def scan_results():
    return render_template("scanner/scan_results.html")



@scanner_bp.route("/health", methods=["GET"])
def health():
    """
    Health check endpoint.
    """
    return jsonify(
        {
            "status": "healthy",
            "service": "Scanner Module"
        }
    ), 200


@scanner_bp.route("/scan", methods=["POST"])
def scan():
    """
    Perform a complete attack surface scan.

    Request JSON:
    {
        "target": "google.com"
    }
    """

    if not request.is_json:
        return jsonify(
            {
                "success": False,
                "message": "Content-Type must be application/json."
            }
        ), 400

    data = request.get_json(silent=True)

    if not data:
        return jsonify(
            {
                "success": False,
                "message": "Invalid JSON body."
            }
        ), 400

    target = data.get("target")

    if not target:
        return jsonify(
            {
                "success": False,
                "message": "Target is required."
            }
        ), 400

    modules = None
    raw_modules = data.get("modules")
    if raw_modules is not None:
        if not isinstance(raw_modules, list) or not raw_modules:
            return jsonify(
                {
                    "success": False,
                    "message": "Select at least one scan module."
                }
            ), 400
        unknown = set(raw_modules) - set(ScannerManager.ALL_MODULES)
        if unknown:
            return jsonify(
                {
                    "success": False,
                    "message": f"Unknown scan module(s): {', '.join(sorted(unknown))}."
                }
            ), 400
        modules = set(raw_modules)

    try:
        result = scanner_manager.scan(target, modules=modules)

        ai_input = ScannerAdapter.convert(result)

        analysis = AnalysisPipeline().analyze(ai_input)

        if current_user.is_authenticated:

            scan = Scan(
                user_id=current_user.id,
                target=target,
                scan_data=result.to_dict(),
                ai_analysis=analysis
            )

            db.session.add(scan)
            db.session.commit()

        response = {
            "success": True,
            "data": result.to_dict(),
            "ai_analysis": analysis
        }
        return jsonify(response), 200

    except Exception as exc:
        return jsonify(
            {
                "success": False,
                "message": str(exc)
            }
        ), 500


@scanner_bp.route("/version", methods=["GET"])
def version():
    """
    Scanner version endpoint.
    """

    return jsonify(
        {
            "module": "Scanner",
            "version": "1.0.0"
        }
    ), 200