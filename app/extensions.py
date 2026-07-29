"""
SentinelASM - Flask Extensions
=================================

Extension instances are created here (uninitialized) so they can be
imported anywhere in the codebase without triggering circular imports.
They are bound to the actual Flask app inside the application factory
(`app/__init__.py`) via each extension's `init_app()` method.
"""

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect

# --- Database ORM -----------------------------------------------------
db = SQLAlchemy()

# --- Schema migrations --------------------------------------------------
migrate = Migrate()

# --- Session-based authentication --------------------------------------
login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "warning"
login_manager.session_protection = "strong"

# --- CSRF protection for form/session based routes ----------------------
csrf = CSRFProtect()

# --- Rate limiting for sensitive endpoints (e.g. login, register) -------
limiter = Limiter(key_func=get_remote_address)
