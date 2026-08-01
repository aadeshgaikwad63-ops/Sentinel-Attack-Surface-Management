"""
SentinelASM - User Management Routes
======================================
"""

from __future__ import annotations

import secrets

from flask import abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.extensions import db
from app.models import Role, User
from app.user_management import user_management_bp
from app.utils.decorators import admin_required
from app.utils.logging import log_action


def _user_row(user: User) -> tuple:
    """Build a (name, email, avatar_seed, role, status, last_active) row."""
    status = "Active" if user.is_active_account else "Suspended"
    last_active = user.last_login_at.strftime("%b %d, %Y %H:%M") if user.last_login_at else "Never"
    avatar_seed = (user.id % 70) + 1
    role_name = user.role.name.capitalize() if user.role else "Viewer"
    return (
        user.full_name or user.username,
        user.email,
        avatar_seed,
        role_name,
        status,
        last_active,
    )


@user_management_bp.route("/", methods=["GET"])
@login_required
def user_management():
    """
    Admins get the full management console (add/remove/edit roles).

    Analysts and viewers are NOT admins, but they should never see a bare
    403 — they get a read-only view of their own account plus the rest of
    the organization's members instead.
    """
    users = User.query.order_by(User.created_at.desc()).all()

    if not current_user.is_admin:
        rows = [_user_row(u) for u in users if u.id != current_user.id]
        return render_template(
            "user_management/members_readonly.html",
            active_page="user_management",
            members=rows,
            member_count=len(users),
        )

    rows = [_user_row(u) for u in users]
    roles = Role.query.order_by(Role.name).all()
    return render_template(
        "user_management/user_management.html",
        active_page="user_management",
        users=rows,
        user_records=users,
        roles=roles,
    )


@user_management_bp.route("/invite", methods=["POST"])
@login_required
@admin_required
def invite_user():
    email = (request.form.get("email") or "").strip().lower()
    role_name = (request.form.get("role") or Role.VIEWER).strip().lower()

    if not email:
        flash("An email address is required to invite a user.", "warning")
        return redirect(url_for("user_management.user_management"))

    if User.query.filter_by(email=email).first():
        flash("A user with that email already exists.", "warning")
        return redirect(url_for("user_management.user_management"))

    role = Role.query.filter_by(name=role_name).first()
    if role is None:
        role = Role.query.filter_by(name=Role.VIEWER).first()

    username = email.split("@")[0] + "-" + secrets.token_hex(2)
    temp_password = secrets.token_urlsafe(9)

    user = User(username=username, email=email, role=role, is_email_verified=False)
    user.set_password(temp_password)
    db.session.add(user)
    db.session.commit()

    log_action(
        "user_invited",
        user_id=current_user.id,
        details=f"invited={email} role={role.name}",
    )
    flash(
        f"User '{email}' created with role {role.name.capitalize()}. "
        f"Temporary password (share securely, shown once): {temp_password}",
        "success",
    )
    return redirect(url_for("user_management.user_management"))


@user_management_bp.route("/<int:user_id>/role", methods=["POST"])
@login_required
@admin_required
def update_role(user_id):
    user = User.query.get_or_404(user_id)
    role_name = (request.form.get("role") or "").strip().lower()
    role = Role.query.filter_by(name=role_name).first()
    if role is None:
        flash("Unknown role.", "danger")
        return redirect(url_for("user_management.user_management"))

    user.role = role
    db.session.commit()
    log_action(
        "user_role_changed",
        user_id=current_user.id,
        details=f"target_user={user.email} new_role={role.name}",
    )
    flash(f"Updated {user.email}'s role to {role.name.capitalize()}.", "success")
    return redirect(url_for("user_management.user_management"))


@user_management_bp.route("/<int:user_id>/toggle-status", methods=["POST"])
@login_required
@admin_required
def toggle_status(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You cannot suspend your own account.", "warning")
        return redirect(url_for("user_management.user_management"))

    user.is_active_account = not user.is_active_account
    db.session.commit()
    state = "activated" if user.is_active_account else "suspended"
    log_action("user_status_changed", user_id=current_user.id, details=f"target_user={user.email} -> {state}")
    flash(f"{user.email} has been {state}.", "success")
    return redirect(url_for("user_management.user_management"))


@user_management_bp.route("/<int:user_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You cannot remove your own account.", "danger")
        return redirect(url_for("user_management.user_management"))

    email = user.email
    db.session.delete(user)
    db.session.commit()
    log_action("user_deleted", user_id=current_user.id, details=f"target_user={email}")
    flash(f"Removed user '{email}'.", "info")
    return redirect(url_for("user_management.user_management"))
