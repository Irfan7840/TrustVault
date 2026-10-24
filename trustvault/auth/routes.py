from urllib.parse import urlparse, urljoin
from flask import Blueprint, render_template, redirect, url_for, flash, request, session, abort
from flask_login import login_user, logout_user, login_required, current_user
from trustvault.extensions import db
from trustvault.models.user import User, UserRole
from trustvault.models.audit import AuditEventType, AuditStatus
from trustvault.auth.forms import RegistrationForm, LoginForm, ChangePasswordForm
from trustvault.services.audit import log_audit_event

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


def is_safe_redirect_url(target: str) -> bool:
    """Validate that redirect target is relative to prevent open-redirect attacks."""
    if not target:
        return False
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("documents.dashboard"))

    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data.strip(),
            email=form.email.data.strip().lower(),
            role=form.role.data,
            is_active=True,
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()

        # Audit log registration
        log_audit_event(
            event_type=AuditEventType.AUTH_REGISTER,
            status=AuditStatus.SUCCESS,
            user=user,
            resource_type="USER",
            resource_id=str(user.id),
            details={"username": user.username, "role": user.role},
        )

        flash("Account created successfully. You may now log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html", form=form)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("documents.dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        login_input = form.username.data.strip()
        user = User.query.filter(
            (User.username == login_input) | (User.email == login_input.lower())
        ).first()

        if user and user.check_password(form.password.data):
            if not user.is_active:
                log_audit_event(
                    event_type=AuditEventType.AUTH_LOGIN_FAILED,
                    status=AuditStatus.DENIED,
                    user=user,
                    resource_type="USER",
                    resource_id=str(user.id),
                    details={"reason": "Account is deactivated"},
                )
                flash("Your account has been deactivated. Please contact an administrator.", "danger")
                return render_template("auth/login.html", form=form)

            # Prevent session fixation
            session.clear()
            login_user(user, remember=form.remember.data)

            log_audit_event(
                event_type=AuditEventType.AUTH_LOGIN_SUCCESS,
                status=AuditStatus.SUCCESS,
                user=user,
                resource_type="USER",
                resource_id=str(user.id),
                details={"role": user.role},
            )

            flash(f"Welcome back, {user.username}!", "success")
            next_page = request.args.get("next")
            if next_page and is_safe_redirect_url(next_page):
                return redirect(next_page)
            return redirect(url_for("documents.dashboard"))

        # Failed attempt
        log_audit_event(
            event_type=AuditEventType.AUTH_LOGIN_FAILED,
            status=AuditStatus.DENIED,
            resource_type="AUTH",
            details={"attempted_username": login_input, "reason": "Invalid credentials"},
        )
        flash("Invalid username or password.", "danger")

    return render_template("auth/login.html", form=form)


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    user = current_user
    log_audit_event(
        event_type=AuditEventType.AUTH_LOGOUT,
        status=AuditStatus.SUCCESS,
        user=user,
        resource_type="USER",
        resource_id=str(user.id),
        details={"username": user.username},
    )
    logout_user()
    session.clear()
    flash("You have been signed out safely.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    """User account settings and security management."""
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.current_password.data):
            flash("Current password entered is incorrect.", "danger")
            return render_template("auth/settings.html", form=form)

        current_user.set_password(form.new_password.data)
        db.session.commit()

        log_audit_event(
            event_type=AuditEventType.AUTH_PASSWORD_CHANGE,
            status=AuditStatus.SUCCESS,
            user=current_user,
            resource_type="USER",
            resource_id=str(current_user.id),
            details="Password successfully changed by user.",
        )
        flash("Your password has been updated successfully.", "success")
        return redirect(url_for("auth.settings"))

    return render_template("auth/settings.html", form=form)
