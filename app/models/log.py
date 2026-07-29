"""
SentinelASM - Log Model
==========================

Persists audit/security events (logins, failed attempts, password resets,
administrative actions, etc.) for traceability and compliance.
"""

from datetime import datetime, timezone

from app.extensions import db


class Log(db.Model):
    """Audit log entry describing a user or system action."""

    __tablename__ = "logs"

    id = db.Column(db.Integer, primary_key=True)

    # Nullable because system-level events may not be tied to a user
    # (e.g. anonymous failed login attempts).
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    user = db.relationship("User", back_populates="logs")

    action = db.Column(db.String(100), nullable=False, index=True)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)

    # info | warning | error | critical
    level = db.Column(db.String(20), default="info", nullable=False)

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    def __repr__(self):  # pragma: no cover - debug helper
        return f"<Log {self.action} user_id={self.user_id}>"

    @staticmethod
    def record(action, user_id=None, details=None, ip_address=None,
               user_agent=None, level="info"):
        """Create and persist a new audit log entry."""
        entry = Log(
            action=action,
            user_id=user_id,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
            level=level,
        )
        db.session.add(entry)
        db.session.commit()
        return entry
