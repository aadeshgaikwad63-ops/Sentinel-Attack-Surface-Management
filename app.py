"""
SentinelASM - Application Entry Point
========================================

Used by:
    - `flask run` / `python app.py` for local development.
    - Gunicorn in production: `gunicorn "app:app"`.

Loads the Flask application instance via the application factory,
selecting the configuration environment from the FLASK_ENV variable.
"""

import os

from app import create_app

app = create_app(os.environ.get("FLASK_ENV", "development"))


if __name__ == "__main__":
    debug_mode = app.config.get("DEBUG", False)
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=debug_mode)
