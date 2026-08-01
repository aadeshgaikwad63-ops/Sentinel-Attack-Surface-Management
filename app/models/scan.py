from datetime import datetime, timezone

from app.extensions import db


class Scan(db.Model):

    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False
    )

    target = db.Column(db.String(255), nullable=False)

    scan_data = db.Column(db.JSON, nullable=False)

    ai_analysis = db.Column(db.JSON, nullable=False)

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc)
    )

    user = db.relationship(
        "User",
        back_populates="scans"
    )