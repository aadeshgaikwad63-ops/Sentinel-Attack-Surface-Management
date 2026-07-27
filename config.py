"""
SentinelASM - Application Configuration
=========================================

Defines environment-specific configuration classes used by the Flask
application factory. Values are sourced from environment variables
(via python-dotenv) so that no secrets are hard-coded in source control.

Configurations provided:
    - Config              : Shared base configuration.
    - DevelopmentConfig    : Local development (SQLite, verbose logging).
    - TestingConfig        : Automated test suite (in-memory SQLite).
    - ProductionConfig     : Production deployment (PostgreSQL ready).
"""

import os
from datetime import timedelta

from dotenv import load_dotenv

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")

# Load variables from a local .env file if present.
load_dotenv(os.path.join(BASE_DIR, ".env"))


def _bool_env(key: str, default: bool = False) -> bool:
    """Parse a boolean-like environment variable."""
    value = os.environ.get(key)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class Config:
    """Base configuration shared by all environments."""

    # --- Core Flask ---------------------------------------------------
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-insecure-secret-key")
    FLASK_ENV = os.environ.get("FLASK_ENV", "production")

    # --- Database -------------------------------------------------------
    # NOTE: Flask-SQLAlchemy resolves *relative* "sqlite:///" URIs against
    # the Flask app's instance folder, not the process working directory.
    # To avoid ambiguity (and accidental double "instance/instance/..."
    # paths) we always default to an absolute sqlite path here. If you set
    # DATABASE_URL yourself for local overrides, prefer an absolute path
    # too, e.g. sqlite:////absolute/path/to/sentinelasm.db (4 slashes).
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:///" + os.path.join(INSTANCE_DIR, "sentinelasm.db")
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}

    # --- Sessions / Cookies ---------------------------------------------
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _bool_env("SESSION_COOKIE_SECURE", False)
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)

    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_SECURE = _bool_env("REMEMBER_COOKIE_SECURE", False)
    REMEMBER_COOKIE_DURATION = timedelta(
        days=int(os.environ.get("REMEMBER_COOKIE_DURATION_DAYS", 14))
    )

    # --- CSRF -------------------------------------------------------------
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None

    # --- Password Reset -----------------------------------------------
    PASSWORD_RESET_TOKEN_MAX_AGE_SECONDS = int(
        os.environ.get("PASSWORD_RESET_TOKEN_MAX_AGE_SECONDS", 1800)
    )

    # --- Mail (placeholders, wire real provider in production) -----------
    MAIL_SERVER = os.environ.get("MAIL_SERVER", "localhost")
    MAIL_PORT = int(os.environ.get("MAIL_PORT", 25))
    MAIL_USE_TLS = _bool_env("MAIL_USE_TLS", True)
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = os.environ.get(
        "MAIL_DEFAULT_SENDER", "SentinelASM <no-reply@sentinelasm.local>"
    )

    # --- Rate Limiting -----------------------------------------------------
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_HEADERS_ENABLED = True

    # --- Logging -------------------------------------------------------
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
    LOG_TO_FILE = _bool_env("LOG_TO_FILE", True)
    LOG_DIR = os.path.join(BASE_DIR, "logs")

    # --- Pagination / Misc -------------------------------------------------
    ITEMS_PER_PAGE = 25

    @staticmethod
    def init_app(app):
        """Hook for environment-specific runtime initialization."""
        pass


class DevelopmentConfig(Config):
    """Local development configuration."""

    DEBUG = True
    TESTING = False
    SQLALCHEMY_ECHO = False


class TestingConfig(Config):
    """Configuration used by the automated test suite."""

    DEBUG = False
    TESTING = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "TEST_DATABASE_URL", "sqlite:///:memory:"
    )
    RATELIMIT_ENABLED = False


class ProductionConfig(Config):
    """Production deployment configuration (PostgreSQL ready)."""

    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True

    @staticmethod
    def init_app(app):
        Config.init_app(app)
        if app.config["SECRET_KEY"] == "dev-insecure-secret-key":
            raise RuntimeError(
                "SECRET_KEY must be set via environment variable in production."
            )


config = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
