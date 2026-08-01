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
from flask_cors import CORS

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
    CORS(app)
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
    from app.scanner import scanner_bp
    from app.dashboard import dashboard_bp
    from app.reports import reports_bp
    from app.assets import assets_bp
    from app.user_management import user_management_bp
    from app.settings import settings_bp
    from app.assistant import ai_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(api_auth_bp)
    app.register_blueprint(profile_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(scanner_bp)
    app.register_blueprint(errors_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(assets_bp)
    app.register_blueprint(user_management_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(ai_bp)

    # Root route: public marketing landing page (was a redirect straight to
    # login). Authenticated areas are unaffected - this only changes what a
    # signed-out visitor sees at "/".
    @app.route("/")
    def index():
        from flask import render_template

        return render_template("landing.html")

    @app.template_filter("sentinel_markdown")
    def sentinel_markdown(text):
        """
        Minimal, safe markdown-lite renderer for AI Assistant replies.

        The assistant only ever emits **bold** and newlines (see
        app/ai/ai_assistant.py) - not full markdown - so rather than pull in
        a markdown dependency this escapes the text first (never trust
        stored content as raw HTML) and then converts just those two
        constructs.
        """
        import re as _re

        from markupsafe import Markup, escape

        escaped = str(escape(text or ""))
        escaped = _re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", escaped)
        escaped = _re.sub(r"^\d+\.\s", lambda m: "<br>" + m.group(0), escaped, flags=_re.MULTILINE)
        escaped = escaped.replace("\n", "<br>")
        return Markup(escaped)

    @app.context_processor
    def inject_current_year():
        from datetime import datetime

        return {"current_year": datetime.utcnow().year}

    @app.context_processor
    def inject_theme_prefs():
        from flask_login import current_user

        if current_user.is_authenticated:
            from app.settings.routes import get_user_accent, get_user_theme

            return {
                "user_theme": get_user_theme(current_user.id),
                "user_accent": get_user_accent(current_user.id),
            }
        return {"user_theme": "dark", "user_accent": "green"}

    # --- Public marketing/legal pages -----------------------------------
    # Phase 1 step 1 (branding + landing) wires up the routes so nav/footer
    # links resolve and the app stays fully runnable. Full written content
    # for each of these lands in Phase 1 step 3 (legal + content pass) -
    # for now they render a lightweight, on-brand placeholder via the same
    # shared nav/footer partials the landing page uses.
    def _stub_page(eyebrow, title, description):
        from flask import render_template

        return render_template(
            "public_stub.html",
            page_eyebrow=eyebrow,
            page_title=title,
            page_description=description,
        )

    @app.route("/about")
    def about():
        return _stub_page("Company", "About SentinelASM", "Learn about SentinelASM's mission and team.")

    @app.route("/contact")
    def contact():
        return _stub_page("Contact", "Contact us", "Get in touch with the SentinelASM team.")

    @app.route("/docs")
    def docs():
        return _stub_page("Resources", "Documentation", "SentinelASM product documentation.")

    @app.route("/privacy-policy")
    def privacy_policy():
        return _stub_page("Legal", "Privacy Policy", "How SentinelASM collects, uses and protects your data.")

    @app.route("/terms-and-conditions")
    def terms():
        return _stub_page("Legal", "Terms & Conditions", "The terms governing use of SentinelASM.")

    @app.route("/cookie-policy")
    def cookie_policy():
        return _stub_page("Legal", "Cookie Policy", "How SentinelASM uses cookies.")

    @app.route("/security-policy")
    def security_policy():
        return _stub_page("Resources", "Security Policy", "SentinelASM's approach to platform and data security.")

    @app.route("/responsible-disclosure")
    def responsible_disclosure():
        return _stub_page(
            "Resources",
            "Responsible Disclosure",
            "How to report a security vulnerability in SentinelASM.",
        )


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
