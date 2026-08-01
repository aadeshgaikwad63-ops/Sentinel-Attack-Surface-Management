"""
SentinelASM - Conversation Model
================================

Stores AI conversation history for each user.
"""

from datetime import datetime, timezone

from app.extensions import db


class Conversation(db.Model):

    __tablename__ = "conversations"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False
    )

    user_message = db.Column(
        db.Text,
        nullable=False
    )

    ai_response = db.Column(
        db.Text,
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    user = db.relationship(
        "User",
        backref=db.backref(
            "conversations",
            lazy="dynamic",
            cascade="all, delete-orphan"
        )
    )

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "user_message": self.user_message,
            "ai_response": self.ai_response,
            "created_at": self.created_at.isoformat()
        }