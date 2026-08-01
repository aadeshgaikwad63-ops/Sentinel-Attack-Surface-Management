"""
SentinelASM - AI Assistant Routes
===================================
"""

from __future__ import annotations

from flask import jsonify, render_template, request
from flask_login import current_user, login_required

from app.ai.ai_assistant import AIAssistant
from app.ai.conversation_memory import ConversationMemory
from app.assistant import ai_bp
from app.extensions import csrf
from app.models import Scan, Conversation

assistant = AIAssistant()
memory = ConversationMemory()

# The chat endpoint is consumed by JS fetch() from the assistant page.
csrf.exempt(ai_bp)


def _latest_scan():
    return (
        Scan.query.filter_by(user_id=current_user.id)
        .order_by(Scan.created_at.desc())
        .first()
    )


@ai_bp.route("/", methods=["GET"])
@login_required
def ai_assistant():
    history = (
        Conversation.query.filter_by(user_id=current_user.id)
        .order_by(Conversation.created_at.desc())
        .limit(10)
        .all()
    )
    return render_template(
        "ai/ai_assistant.html",
        active_page="ai_assistant",
        history=list(reversed(history)),
    )


@ai_bp.route("/chat", methods=["POST"])
@login_required
def chat():
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    if not message:
        return jsonify({"success": False, "message": "Message cannot be empty."}), 400

    scan = _latest_scan()
    analysis = scan.ai_analysis if scan else None
    target = scan.target if scan else None

    reply = assistant.respond(message, analysis, target)
    memory.save_conversation(message, reply)

    return jsonify({"success": True, "reply": reply})


@ai_bp.route("/history", methods=["GET"])
@login_required
def history():
    return jsonify(memory.get_history())
