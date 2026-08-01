"""
Database Conversation Memory
"""

from flask_login import current_user

from app.extensions import db
from app.models.conversation import Conversation



class ConversationMemory:



    def save_conversation(
            self,
            user_message,
            ai_response
    ):


        conversation = Conversation(

            user_id=current_user.id,

            user_message=user_message,

            ai_response=ai_response

        )


        db.session.add(
            conversation
        )


        db.session.commit()


        return conversation.to_dict()



    def get_history(self):


        conversations = (
            Conversation.query
            .filter_by(user_id=current_user.id)
            .order_by(Conversation.created_at.desc())
            .all()
        )


        return [

            c.to_dict()

            for c in conversations

        ]