"""
SentinelASM - Setting Model
==============================

Simple key/value store for global application settings that need to be
configurable at runtime without redeploying (e.g. feature flags, platform
options used by other modules such as the scanners or dashboard).
"""

from datetime import datetime, timezone

from app.extensions import db


class Setting(db.Model):
    """Global application configuration setting (key/value pair)."""

    __tablename__ = "settings"

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False, index=True)
    value = db.Column(db.Text, nullable=True)
    description = db.Column(db.String(255), nullable=True)

    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self):  # pragma: no cover - debug helper
        return f"<Setting {self.key}={self.value!r}>"

    @staticmethod
    def get(key: str, default=None):
        """Retrieve a setting value by key, falling back to `default`."""
        setting = Setting.query.filter_by(key=key).first()
        return setting.value if setting else default

    @staticmethod
    def set(key: str, value: str, description: str = None):
        """Create or update a setting value."""
        setting = Setting.query.filter_by(key=key).first()
        if setting is None:
            setting = Setting(key=key, value=value, description=description)
            db.session.add(setting)
        else:
            setting.value = value
            if description is not None:
                setting.description = description
        db.session.commit()
        return setting
