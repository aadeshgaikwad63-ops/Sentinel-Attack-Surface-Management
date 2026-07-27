"""
SentinelASM - Authentication Routes
======================================

Server-rendered authentication pages: register, login, logout,
forgot password, and reset password. Session-based, using Flask-Login.
"""

from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from app.auth import auth_bp
from app.auth.forms import (
    ForgotPasswordForm,
    LoginForm,
    RegistrationForm,
    ResetPasswordForm,
)
from app.extensions import db, limiter
from app.models import Role, User
from app.utils.email import send_password_reset_email
from app.utils.logging import log_action


@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per hour")
def register():
    """Register a new user account with the default 'viewer' role."""

    if current_user.is_authenticated:
        return redirect(url_for("profile.view_profile"))

    form = RegistrationForm()

    if form.validate_on_submit():
        viewer_role = Role.query.filter_by(name=Role.VIEWER).first()

        user = User(
            username=form.username.data.strip(),
            email=form.email.data.strip().lower(),
            full_name=form.full_name.data.strip() if form.full_name.data else None,
            role=viewer_role,
        )

        user.set_password(form.password.data)

        db.session.add(user)
        db.session.commit()

        log_action(
            "user_registered",
            user_id=user.id,
            details=f"username={user.username}"
        )

        flash("Account created successfully. You may now log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html", form=form)


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("15 per 5 minutes")
def login():
    """Authenticate a user via username/email + password, with remember-me."""
    if current_user.is_authenticated:
        return redirect(url_for("profile.view_profile"))

    form = LoginForm()
    if form.validate_on_submit():
        identity = form.identity.data.strip()
        user = User.query.filter(
            (User.username == identity) | (User.email == identity.lower())
        ).first()

        if user is None or not user.check_password(form.password.data):
            log_action(
                "login_failed", details=f"identity={identity}", level="warning"
            )
            flash("Invalid username/email or password.", "danger")
            return render_template("auth/login.html", form=form)

        if not user.is_active_account:
            flash("This account has been deactivated. Contact an administrator.", "danger")
            return render_template("auth/login.html", form=form)

        from datetime import datetime, timezone

        user.last_login_at = datetime.now(timezone.utc)
        user.last_login_ip = request.remote_addr
        db.session.commit()

        login_user(user, remember=form.remember_me.data)
        log_action("login_success", user_id=user.id)

        next_page = request.args.get("next")
        if not next_page or not next_page.startswith("/"):
            next_page = url_for("profile.view_profile")
        return redirect(next_page)

    return render_template("auth/login.html", form=form)


@auth_bp.route("/logout")
@login_required
def logout():
    """Terminate the current user's session."""
    log_action("logout", user_id=current_user.id)
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("5 per hour")
def forgot_password():
    """Request a password reset link be sent to the account's email."""
    if current_user.is_authenticated:
        return redirect(url_for("profile.view_profile"))

    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        user = User.query.filter_by(email=email).first()

        # Always show a generic success message, whether or not the email
        # exists, to avoid leaking which addresses are registered.
        if user is not None:
            token = user.generate_reset_token()
            reset_url = url_for("auth.reset_password", token=token, _external=True)
            send_password_reset_email(user.email, reset_url)
            log_action("password_reset_requested", user_id=user.id)

        flash(
            "If that email is registered, a password reset link has been sent.",
            "info",
        )
        return redirect(url_for("auth.login"))

    return render_template("auth/forgot_password.html", form=form)


@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
@limiter.limit("10 per hour")
def reset_password(token):
    """Consume a password reset token and set a new password."""
    if current_user.is_authenticated:
        return redirect(url_for("profile.view_profile"))

    user = User.verify_reset_token(token)
    if user is None:
        flash("That password reset link is invalid or has expired.", "danger")
        return redirect(url_for("auth.forgot_password"))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        log_action("password_reset_completed", user_id=user.id)
        flash("Your password has been reset. You may now log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/reset_password.html", form=form, token=token)
