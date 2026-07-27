"""
SentinelASM - Input Validation Helpers
=========================================

Shared validation utilities used by both WTForms forms (server-rendered
auth pages) and the raw JSON REST Authentication API, ensuring consistent
validation rules across both entry points.
"""

import re

USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]{3,64}$")
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Requires at least 8 chars, one uppercase, one lowercase, one digit.
PASSWORD_MIN_LENGTH = 8
PASSWORD_PATTERN = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{" + str(PASSWORD_MIN_LENGTH) + r",}$"
)


def is_valid_username(username: str) -> bool:
    """Username: 3-64 chars, letters/digits/underscore/dot/hyphen only."""
    return bool(username) and bool(USERNAME_PATTERN.match(username))


def is_valid_email(email: str) -> bool:
    """Basic structural email validation (format-only, no DNS lookup)."""
    return bool(email) and bool(EMAIL_PATTERN.match(email))


def is_strong_password(password: str) -> bool:
    """
    Enforce a minimum password strength policy:
    at least 8 characters, one uppercase letter, one lowercase letter,
    and one digit.
    """
    return bool(password) and bool(PASSWORD_PATTERN.match(password))


def password_policy_message() -> str:
    """Human-readable description of the password policy, for UI/API errors."""
    return (
        f"Password must be at least {PASSWORD_MIN_LENGTH} characters long and "
        "include an uppercase letter, a lowercase letter, and a digit."
    )


def validate_registration_payload(data: dict) -> list:
    """
    Validate a raw registration payload (dict) as received by the JSON API.
    Returns a list of human-readable error strings (empty list = valid).
    """
    errors = []
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""

    if not is_valid_username(username):
        errors.append(
            "Username must be 3-64 characters and contain only letters, "
            "numbers, dots, underscores, or hyphens."
        )
    if not is_valid_email(email):
        errors.append("A valid email address is required.")
    if not is_strong_password(password):
        errors.append(password_policy_message())

    return errors
