"""
SentinelASM - REST Authentication API
========================================

JSON API for authentication, intended for non-browser clients (CLI tools,
other SentinelASM microservices, third-party integrations).

Authentication model:
    - POST /api/auth/register -> create account
    - POST /api/auth/login    -> verify credentials, issue a personal API
                                  access token (Bearer)
    - POST /api/auth/logout   -> revoke the presented API token
    - GET  /api/auth/me       -> return the authenticated user's profile

All endpoints are CSRF-exempt (stateless, token-based auth rather than
cookies) but remain protected by rate limiting and strict input
validation.
"""

from flask import g, jsonify, request

from app.auth import api_auth_bp
from app.extensions import csrf, db, limiter
from app.models import APIToken, Role, User
from app.utils.decorators import api_token_required
from app.utils.logging import log_action
from app.utils.validators import validate_registration_payload

# Stateless JSON endpoints authenticate via Bearer tokens, not session
# cookies, so they are exempt from Flask-WTF's session-based CSRF checks.
csrf.exempt(api_auth_bp)


@api_auth_bp.route("/register", methods=["POST"])
@limiter.limit("10 per hour")
def api_register():
    """Register a new user account via the REST API."""
    data = request.get_json(silent=True) or {}
    errors = validate_registration_payload(data)
    if errors:
        return jsonify({"error": "validation_error", "messages": errors}), 400

    username = data["username"].strip()
    email = data["email"].strip().lower()

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "conflict", "message": "Username already taken."}), 409
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "conflict", "message": "Email already registered."}), 409

    viewer_role = Role.query.filter_by(name=Role.VIEWER).first()
    user = User(username=username, email=email, role=viewer_role)
    user.set_password(data["password"])
    db.session.add(user)
    db.session.commit()

    log_action("api_user_registered", user_id=user.id, details=f"username={username}")

    return (
        jsonify(
            {
                "message": "Account created successfully.",
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "role": user.role.name,
                },
            }
        ),
        201,
    )


@api_auth_bp.route("/login", methods=["POST"])
@limiter.limit("15 per 5 minutes")
def api_login():
    """Verify credentials and issue a new personal API access token."""
    data = request.get_json(silent=True) or {}
    identity = (data.get("identity") or data.get("username") or "").strip()
    password = data.get("password") or ""

    if not identity or not password:
        return (
            jsonify(
                {
                    "error": "validation_error",
                    "message": "Both 'identity' (username or email) and "
                    "'password' are required.",
                }
            ),
            400,
        )

    user = User.query.filter(
        (User.username == identity) | (User.email == identity.lower())
    ).first()

    if user is None or not user.check_password(password):
        log_action("api_login_failed", details=f"identity={identity}", level="warning")
        return jsonify({"error": "unauthorized", "message": "Invalid credentials."}), 401

    if not user.is_active_account:
        return jsonify({"error": "forbidden", "message": "Account is deactivated."}), 403

    token, raw_token = APIToken.generate(
        user, name="api-login-token", expires_in_days=30
    )
    log_action("api_login_success", user_id=user.id)

    return jsonify(
        {
            "message": "Authentication successful.",
            "access_token": raw_token,
            "token_type": "Bearer",
            "expires_at": token.expires_at.isoformat() if token.expires_at else None,
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role.name,
            },
        }
    )


@api_auth_bp.route("/logout", methods=["POST"])
@api_token_required
def api_logout():
    """Revoke the API token presented in the Authorization header."""
    g.api_token.revoke()
    log_action("api_logout", user_id=g.current_user.id)
    return jsonify({"message": "Token revoked successfully."})


@api_auth_bp.route("/me", methods=["GET"])
@api_token_required
def api_me():
    """Return the authenticated user's profile."""
    user = g.current_user
    return jsonify(
        {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role.name,
            "is_active": user.is_active_account,
            "is_email_verified": user.is_email_verified,
            "created_at": user.created_at.isoformat(),
            "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
        }
    )
