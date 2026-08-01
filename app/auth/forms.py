"""
SentinelASM - Authentication Forms
=====================================

Flask-WTF forms backing the server-rendered authentication pages.
Provide CSRF protection automatically and centralize input validation.
"""

from flask_wtf import FlaskForm
from wtforms import BooleanField, PasswordField, StringField, SubmitField
from wtforms.validators import (
    DataRequired,
    Email,
    EqualTo,
    Length,
    Regexp,
    ValidationError,
)

from app.models import User
from app.utils.validators import PASSWORD_MIN_LENGTH, password_policy_message


class RegistrationForm(FlaskForm):
    """New user registration form."""

    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=3, max=64),
            Regexp(
                r"^[a-zA-Z0-9_.-]+$",
                message="Username may only contain letters, numbers, dots, "
                "underscores, and hyphens.",
            ),
        ],
    )
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=255)])
    full_name = StringField("Full Name", validators=[Length(max=120)])
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Length(min=PASSWORD_MIN_LENGTH),
            Regexp(
                r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$",
                message=password_policy_message(),
            ),
        ],
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match.")],
    )
    submit = SubmitField("Create Account")

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError("That username is already taken.")

    def validate_email(self, field):
        if User.query.filter_by(email=field.data.lower()).first():
            raise ValidationError("An account with that email already exists.")


class LoginForm(FlaskForm):
    """User login form with 'remember me' support."""

    identity = StringField(
        "Username or Email", validators=[DataRequired(), Length(max=255)]
    )
    password = PasswordField("Password", validators=[DataRequired()])
    remember_me = BooleanField("Remember Me")
    submit = SubmitField("Log In")


class ForgotPasswordForm(FlaskForm):
    """Request a password reset link via email."""

    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=255)])
    submit = SubmitField("Send Reset Link")


class ResetPasswordForm(FlaskForm):
    """Set a new password given a valid reset token."""

    password = PasswordField(
        "New Password",
        validators=[
            DataRequired(),
            Length(min=PASSWORD_MIN_LENGTH),
            Regexp(
                r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$",
                message=password_policy_message(),
            ),
        ],
    )
    confirm_password = PasswordField(
        "Confirm New Password",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match.")],
    )
    submit = SubmitField("Reset Password")
