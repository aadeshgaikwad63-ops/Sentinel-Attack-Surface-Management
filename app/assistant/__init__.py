"""
SentinelASM - AI Assistant Blueprint
=======================================

Serves the conversational AI Security Assistant screen. Named "assistant"
as a Python package (to avoid clashing with the existing app.ai engines
package) but registered under the Flask blueprint name "ai" so it matches
url_for('ai.ai_assistant') used throughout the templates.
"""

from flask import Blueprint

ai_bp = Blueprint(
    "ai",
    __name__,
    url_prefix="/assistant",
)

from app.assistant import routes  # noqa: E402,F401
