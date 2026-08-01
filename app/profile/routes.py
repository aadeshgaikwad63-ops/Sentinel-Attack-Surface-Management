"""
SentinelASM - Profile Routes
===============================

Authenticated views for managing the current user's own profile,
password, and personal API access tokens.
"""

from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.extensions import db
from app.models import APIToken
from app.profile import profile_bp
from app.profile.forms import ChangePasswordForm, UpdateProfileForm
from app.utils.logging import log_action


@profile_bp.route("/", methods=["GET"])
@login_required
def view_profile():
    """Display the current user's profile overview."""
    tokens = current_user.api_tokens.filter_by(is_active=True).all()
    return render_template("profile/profile.html", tokens=tokens)


@profile_bp.route("/edit", methods=["GET", "POST"])
@login_required
def edit_profile():
    """Edit the current user's editable profile fields."""
    form = UpdateProfileForm(obj=current_user)
    if form.validate_on_submit():
        current_user.full_name = form.full_name.data.strip() or None
        current_user.email = form.email.data.strip().lower()
        current_user.bio = form.bio.data.strip() or None
        db.session.commit()
        log_action("profile_updated", user_id=current_user.id)
        flash("Profile updated successfully.", "success")
        return redirect(url_for("profile.view_profile"))

    return render_template("profile/edit_profile.html", form=form)


@profile_bp.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    """Change the current user's password."""
    form = ChangePasswordForm()
    if form.validate_on_submit():
        current_user.set_password(form.new_password.data)
        db.session.commit()
        log_action("password_changed", user_id=current_user.id)
        flash("Password updated successfully.", "success")
        return redirect(url_for("profile.view_profile"))

    return render_template("profile/change_password.html", form=form)


@profile_bp.route("/tokens/create", methods=["POST"])
@login_required
def create_token():
    """Generate a new personal API access token for the current user."""
    name = request.form.get("name", "").strip() or "Unnamed Token"
    _, raw_token = APIToken.generate(current_user, name=name, expires_in_days=90)
    log_action("api_token_created", user_id=current_user.id, details=f"name={name}")
    flash(
        f"New API token created. Copy it now, it will not be shown again: {raw_token}",
        "success",
    )
    return redirect(url_for("profile.view_profile"))


@profile_bp.route("/tokens/<int:token_id>/revoke", methods=["POST"])
@login_required
def revoke_token(token_id):
    """Revoke one of the current user's personal API access tokens."""
    token = APIToken.query.filter_by(id=token_id, user_id=current_user.id).first_or_404()
    token.revoke()
    log_action("api_token_revoked", user_id=current_user.id, details=f"token_id={token_id}")
    flash("API token revoked.", "info")
    return redirect(url_for("profile.view_profile"))
