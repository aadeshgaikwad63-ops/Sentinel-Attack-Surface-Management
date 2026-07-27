"""
SentinelASM - Error Handlers
===============================

Implements handlers for common HTTP error conditions. Responses are
content-negotiated: JSON API/AJAX clients receive structured JSON errors,
while browser clients receive rendered HTML error pages.
"""

from flask import jsonify, render_template, request
from flask_wtf.csrf import CSRFError

from app.errors import errors_bp
from app.extensions import db


def _wants_json() -> bool:
    """Determine whether the client expects a JSON error response."""
    if request.path.startswith("/api/"):
        return True
    best = request.accept_mimetypes.best_match(["application/json", "text/html"])
    return (
        best == "application/json"
        and request.accept_mimetypes[best] > request.accept_mimetypes["text/html"]
    )


def _error_response(status_code: int, name: str, message: str):
    if _wants_json():
        return jsonify({"error": name, "message": message}), status_code
    template_map = {
        400: "errors/400.html",
        401: "errors/401.html",
        403: "errors/403.html",
        404: "errors/404.html",
        429: "errors/429.html",
        500: "errors/500.html",
    }
    template = template_map.get(status_code, "errors/500.html")
    return render_template(template, message=message), status_code


@errors_bp.app_errorhandler(400)
def bad_request(error):
    return _error_response(400, "bad_request", "The request could not be understood.")


@errors_bp.app_errorhandler(401)
def unauthorized(error):
    return _error_response(401, "unauthorized", "Authentication is required.")


@errors_bp.app_errorhandler(403)
def forbidden(error):
    return _error_response(403, "forbidden", "You do not have permission to do that.")


@errors_bp.app_errorhandler(404)
def not_found(error):
    return _error_response(404, "not_found", "The requested resource was not found.")


@errors_bp.app_errorhandler(429)
def rate_limit_exceeded(error):
    return _error_response(
        429, "rate_limit_exceeded", "Too many requests. Please try again later."
    )


@errors_bp.app_errorhandler(CSRFError)
def csrf_error(error):
    return _error_response(400, "csrf_error", "Your session has expired. Please try again.")


@errors_bp.app_errorhandler(500)
def internal_server_error(error):
    # Ensure any partially-committed transaction from the failing request
    # doesn't leave the session in a broken state for subsequent requests.
    db.session.rollback()
    return _error_response(500, "internal_server_error", "An unexpected error occurred.")
