"""
SentinelASM - API Token Model
================================

Personal access tokens used to authenticate against the REST Authentication
API (Bearer token auth) independently of browser sessions/cookies.

Only a salted hash of the token is ever persisted - the plaintext token is
shown to the user exactly once, at creation time.
"""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from app.extensions import db

TOKEN_BYTES = 32
TOKEN_PREFIX = "sasm_"


def _as_utc(value: datetime) -> datetime:
    """
    Normalize a datetime to timezone-aware UTC.

    SQLite (unlike PostgreSQL) does not preserve timezone information, so
    datetimes read back from the database are naive even though they were
    always stored as UTC. This treats naive values as UTC to keep
    comparisons against `datetime.now(timezone.utc)` safe on both backends.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


class APIToken(db.Model):
    """Hashed personal access token bound to a single user."""

    __tablename__ = "api_tokens"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    user = db.relationship("User", back_populates="api_tokens")

    name = db.Column(db.String(100), nullable=False)
    token_hash = db.Column(db.String(128), unique=True, nullable=False, index=True)
    # First characters of the plaintext token, stored for display purposes
    # only (e.g. "sasm_ab12...") so users can identify tokens in a list.
    token_preview = db.Column(db.String(16), nullable=False)

    is_active = db.Column(db.Boolean, default=True, nullable=False)

    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    expires_at = db.Column(db.DateTime, nullable=True)
    last_used_at = db.Column(db.DateTime, nullable=True)

    def __repr__(self):  # pragma: no cover - debug helper
        return f"<APIToken {self.name} user_id={self.user_id}>"

    # ------------------------------------------------------------------
    # Token lifecycle helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _hash(raw_token: str) -> str:
        return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    @classmethod
    def generate(cls, user, name: str, expires_in_days: int = None):
        """
        Create a new APIToken for `user`.

        Returns a tuple of (APIToken instance, plaintext token). The
        plaintext token must be shown to the caller once and is never
        recoverable afterwards.
        """
        raw_token = f"{TOKEN_PREFIX}{secrets.token_urlsafe(TOKEN_BYTES)}"
        expires_at = None
        if expires_in_days:
            expires_at = datetime.now(timezone.utc) + timedelta(days=expires_in_days)

        token = cls(
            user_id=user.id,
            name=name,
            token_hash=cls._hash(raw_token),
            token_preview=raw_token[:12],
            expires_at=expires_at,
        )
        db.session.add(token)
        db.session.commit()
        return token, raw_token

    @classmethod
    def verify(cls, raw_token: str):
        """Return the matching, valid APIToken for a plaintext token, else None."""
        if not raw_token:
            return None
        token = cls.query.filter_by(token_hash=cls._hash(raw_token)).first()
        if token is None or not token.is_active:
            return None
        if token.expires_at and _as_utc(token.expires_at) < datetime.now(timezone.utc):
            return None
        token.last_used_at = datetime.now(timezone.utc)
        db.session.commit()
        return token

    def revoke(self):
        """Deactivate this token."""
        self.is_active = False
        db.session.commit()
