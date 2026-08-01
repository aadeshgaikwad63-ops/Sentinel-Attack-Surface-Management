"""
SentinelASM - Role Model
==========================

Represents Role Based Access Control (RBAC) roles assigned to users.
Default roles: admin, analyst, viewer.
"""

from datetime import datetime, timezone

from app.extensions import db


class Role(db.Model):
    """RBAC role assigned to one or more users."""

    __tablename__ = "roles"

    # Well-known role name constants, used across the codebase to avoid
    # sprinkling magic strings throughout auth/access-control logic.
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"

    ALL_ROLES = (ADMIN, ANALYST, VIEWER)

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False, index=True)
    description = db.Column(db.String(255), nullable=True)
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    # One-to-many: a role can be assigned to many users.
    users = db.relationship("User", back_populates="role", lazy="dynamic")

    def __repr__(self):  # pragma: no cover - debug helper
        return f"<Role {self.name}>"

    @staticmethod
    def seed_default_roles():
        """Ensure the default RBAC roles exist. Idempotent."""
        descriptions = {
            Role.ADMIN: "Full administrative access to SentinelASM.",
            Role.ANALYST: "Can operate scanning/analysis features.",
            Role.VIEWER: "Read-only access to the platform.",
        }
        for role_name in Role.ALL_ROLES:
            if not Role.query.filter_by(name=role_name).first():
                db.session.add(
                    Role(name=role_name, description=descriptions[role_name])
                )
        db.session.commit()
