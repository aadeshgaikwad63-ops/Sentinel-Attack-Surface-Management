"""
SentinelASM - User Model
==========================

Represents a platform user. Handles password hashing/verification,
password reset token generation, and Flask-Login integration.
"""

from datetime import datetime, timezone

from flask import current_app
from flask_login import UserMixin
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash

from app.extensions import db, login_manager


class User(UserMixin, db.Model):
    """Application user account."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    # --- Identity ---------------------------------------------------------
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

    # --- Profile ------------------------------------------------------
    full_name = db.Column(db.String(120), nullable=True)
    bio = db.Column(db.Text, nullable=True)
    avatar_url = db.Column(db.String(255), nullable=True)

    # --- RBAC ---------------------------------------------------------
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id"), nullable=False)
    role = db.relationship("Role", back_populates="users")

    # --- Account state --------------------------------------------------
    is_active_account = db.Column(db.Boolean, default=True, nullable=False)
    is_email_verified = db.Column(db.Boolean, default=False, nullable=False)

    # --- Timestamps -----------------------------------------------------
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    last_login_at = db.Column(db.DateTime, nullable=True)
    last_login_ip = db.Column(db.String(45), nullable=True)

    # --- Relationships ----------------------------------------------------
    logs = db.relationship(
        "Log", back_populates="user", lazy="dynamic", cascade="all, delete-orphan"
    )
    api_tokens = db.relationship(
        "APIToken",
        back_populates="user",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )

    scans = db.relationship(
        "Scan",
        back_populates="user",
        lazy="dynamic",
        cascade="all, delete-orphan"
    )

    # Flask-Login requires `is_active` - map to our own account flag.
    @property
    def is_active(self):
        return self.is_active_account

    # ------------------------------------------------------------------
    # Password handling
    # ------------------------------------------------------------------
    def set_password(self, raw_password: str) -> None:
        """Hash and store the given plaintext password."""
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password: str) -> bool:
        """Verify a plaintext password against the stored hash."""
        return check_password_hash(self.password_hash, raw_password)

    # ------------------------------------------------------------------
    # Password reset tokens (itsdangerous, time-limited & signed)
    # ------------------------------------------------------------------
    @staticmethod
    def _serializer() -> URLSafeTimedSerializer:
        return URLSafeTimedSerializer(current_app.config["SECRET_KEY"])

    def generate_reset_token(self) -> str:
        """Generate a signed, time-limited password reset token."""
        return self._serializer().dumps(self.email, salt="password-reset-salt")

    @staticmethod
    def verify_reset_token(token: str):
        """Return the User for a valid token, or None if invalid/expired."""
        max_age = current_app.config["PASSWORD_RESET_TOKEN_MAX_AGE_SECONDS"]
        try:
            email = User._serializer().loads(
                token, salt="password-reset-salt", max_age=max_age
            )
        except (BadSignature, SignatureExpired):
            return None
        return User.query.filter_by(email=email).first()

    # ------------------------------------------------------------------
    # RBAC helpers
    # ------------------------------------------------------------------
    def has_role(self, *role_names: str) -> bool:
        """Check whether this user holds one of the given role names."""
        return self.role is not None and self.role.name in role_names

    @property
    def is_admin(self) -> bool:
        return self.has_role("admin")

    def __repr__(self):  # pragma: no cover - debug helper
        return f"<User {self.username}>"


@login_manager.user_loader
def load_user(user_id: str):
    """Flask-Login callback used to reload a user from the session."""
    return User.query.get(int(user_id))
