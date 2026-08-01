"""
SentinelASM - Profile Forms
==============================

Forms used on the authenticated user's profile page: editing personal
details and changing the account password.
"""

from flask_login import current_user
from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError

from app.models import User
from app.utils.validators import PASSWORD_MIN_LENGTH


class UpdateProfileForm(FlaskForm):
    """Update the current user's editable profile fields."""

    full_name = StringField("Full Name", validators=[Length(max=120)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=255)])
    bio = TextAreaField("Bio", validators=[Length(max=2000)])
    submit = SubmitField("Save Changes")

    def validate_email(self, field):
        existing = User.query.filter_by(email=field.data.strip().lower()).first()
        if existing and existing.id != current_user.id:
            raise ValidationError("That email is already in use by another account.")


class ChangePasswordForm(FlaskForm):
    """Change the current user's password (requires current password)."""

    current_password = PasswordField("Current Password", validators=[DataRequired()])
    new_password = PasswordField(
        "New Password", validators=[DataRequired(), Length(min=PASSWORD_MIN_LENGTH)]
    )
    confirm_password = PasswordField(
        "Confirm New Password",
        validators=[DataRequired(), EqualTo("new_password", message="Passwords must match.")],
    )
    submit = SubmitField("Update Password")

    def validate_current_password(self, field):
        if not current_user.check_password(field.data):
            raise ValidationError("Current password is incorrect.")
