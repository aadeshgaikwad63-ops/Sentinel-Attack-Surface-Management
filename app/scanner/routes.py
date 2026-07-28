"""
SentinelASM - Scanner Routes
============================

REST API endpoints for the Attack Surface Management scanner.
"""

from __future__ import annotations

from flask import jsonify, request

from app.extensions import csrf
from app.scanner import scanner_bp
from app.scanner.scanner_manager import ScannerManager
from app.ai.scanner_adapter import ScannerAdapter
from app.services.analysis_pipeline import AnalysisPipeline

# Scanner APIs are consumed by JavaScript/AJAX requests.
csrf.exempt(scanner_bp)

scanner_manager = ScannerManager()


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
        "success": True,
        "scan_data": result.to_dict(),
        "ai_analysis": analysis
    }
), 200

    try:
        result = scanner_manager.scan(target)
        ai_input = ScannerAdapter.convert(result)

        analysis = AnalysisPipeline().analyze(ai_input)

        return jsonify(
            {
                "success": True,
                "data": result.to_dict()
            }
        ), 200

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