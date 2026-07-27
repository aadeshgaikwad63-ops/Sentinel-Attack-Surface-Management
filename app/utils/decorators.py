"""
SentinelASM - Access Control Decorators
==========================================

Provides:
    - roles_required : restrict a view to one or more RBAC roles.
    - api_token_required : authenticate REST API requests via Bearer token
      instead of a browser session.
"""

from functools import wraps

from flask import abort, current_app, g, request
from flask_login import current_user

from app.models import APIToken


def roles_required(*role_names):
    """
    Restrict access to a view to users holding one of the given roles.

    Usage:
        @roles_required("admin")
        def admin_only_view():
            ...
    """

    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            if not current_user.has_role(*role_names):
                current_app.logger.warning(
                    "Access denied for user=%s to role-protected resource=%s",
                    getattr(current_user, "username", "anonymous"),
                    request.path,
                )
                abort(403)
            return view_func(*args, **kwargs)

        return wrapped

    return decorator


def admin_required(view_func):
    """Shortcut decorator restricting a view to the 'admin' role only."""
    return roles_required("admin")(view_func)


def api_token_required(view_func):
    """
    Authenticate a REST API request using an `Authorization: Bearer <token>`
    header. On success, `g.current_user` and `g.api_token` are populated.
    """

    @wraps(view_func)
    def wrapped(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return {
                "error": "unauthorized",
                "message": "Missing or malformed Authorization header.",
            }, 401

        raw_token = auth_header.split(" ", 1)[1].strip()
        token = APIToken.verify(raw_token)
        if token is None:
            return {
                "error": "unauthorized",
                "message": "Invalid or expired API token.",
            }, 401

        g.current_user = token.user
        g.api_token = token
        return view_func(*args, **kwargs)

    return wrapped
