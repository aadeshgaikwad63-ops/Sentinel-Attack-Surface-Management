"""
SentinelASM - Models Package
===============================

Aggregates all SQLAlchemy models so that they register with the metadata
of the shared `db` instance as soon as `app.models` is imported. This is
required for Flask-Migrate autogeneration and for `db.create_all()`.
"""

from app.models.api_token import APIToken
from app.models.log import Log
from app.models.role import Role
from app.models.setting import Setting
from app.models.user import User
from app.models.scan import Scan
from app.models.conversation import Conversation

__all__ = ["User", "Role", "Log", "Setting", "APIToken", "Scan", "Conversation"]
