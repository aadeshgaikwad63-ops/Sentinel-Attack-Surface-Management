"""
SentinelASM - Application Factory
====================================

Constructs and configures the Flask application instance using the
Application Factory pattern. All extensions, blueprints, error handlers,
and logging are wired up here.

Other developers extending SentinelASM with new feature modules
(scanners, AI, dashboard, reports, etc.) should register their own
blueprints inside `create_app()` following the same pattern used below -
do not modify the blueprints already registered here.
"""

import os

from flask import Flask

from app.extensions import csrf, db, limiter, login_manager, migrate
from app.utils.logging import configure_logging
from config import config


def create_app(config_name=None):
    """
    Application factory.

    Args:
        config_name: One of "development", "testing", "production", or
            None to fall back to the FLASK_ENV environment variable
            (defaulting to "development").

    Returns:
        A fully configured Flask application instance.
    """
    if config_name is None:
        config_name = os.environ.get("FLASK_ENV", "development")

    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config.get(config_name, config["default"]))
    config[config_name].init_app(app) if config_name in config else None

    # Ensure the instance folder exists (holds the default SQLite DB, etc.)
    os.makedirs(app.instance_path, exist_ok=True)

    _register_extensions(app)
    _register_blueprints(app)
    _register_cli_commands(app)

    configure_logging(app)

    return app


def _register_extensions(app):
    """Bind shared extension instances to this Flask app."""
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # Import models so they register with SQLAlchemy metadata (required
    # for Flask-Migrate autogeneration and db.create_all()).
    with app.app_context():
        from app import models  # noqa: F401


def _register_blueprints(app):
    """Register all application blueprints."""
    from app.api import api_bp
    from app.auth import api_auth_bp, auth_bp
    from app.errors import errors_bp
    from app.profile import profile_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(api_auth_bp)
    app.register_blueprint(profile_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(errors_bp)

    # Root route: redirect to login (kept minimal - dashboard team owns "/").
    @app.route("/")
    def index():
        from flask import redirect, url_for

        return redirect(url_for("auth.login"))


def _register_cli_commands(app):
    """Register custom `flask` CLI commands for database bootstrapping."""

    @app.cli.command("seed-roles")
    def seed_roles():
        """Seed the default RBAC roles (admin, analyst, viewer)."""
        from app.models import Role

        Role.seed_default_roles()
        print("Default roles seeded successfully.")

    @app.cli.command("create-admin")
    def create_admin():
        """Interactively create the first administrator account."""
        import getpass

        from app.extensions import db
        from app.models import Role, User

        username = input("Admin username: ").strip()
        email = input("Admin email: ").strip().lower()
        password = getpass.getpass("Admin password: ")

        admin_role = Role.query.filter_by(name=Role.ADMIN).first()
        if admin_role is None:
            Role.seed_default_roles()
            admin_role = Role.query.filter_by(name=Role.ADMIN).first()

        if User.query.filter((User.username == username) | (User.email == email)).first():
            print("A user with that username or email already exists.")
            return

        user = User(username=username, email=email, role=admin_role, is_email_verified=True)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        print(f"Administrator '{username}' created successfully.")
