from datetime import datetime, timezone
from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user
from trustvault.extensions import db
from trustvault.models.user import User, UserRole
from trustvault.models.document import Document
from trustvault.models.audit import AuditLog, AuditEventType, AuditStatus
from trustvault.admin.forms import UserRoleForm
from trustvault.services.access_control import admin_required
from trustvault.services.audit import log_audit_event, verify_audit_trail

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("")
@login_required
@admin_required
def dashboard():
    """Administrative overview and security telemetry."""
    total_users = User.query.count()
    total_documents = Document.query.count()
    total_audit_events = AuditLog.query.count()
    total_denied_events = AuditLog.query.filter_by(status=AuditStatus.DENIED).count()

    recent_alerts = (
        AuditLog.query.filter_by(status=AuditStatus.DENIED)
        .order_by(AuditLog.timestamp.desc())
        .limit(10)
        .all()
    )

    recent_activity = (
        AuditLog.query.order_by(AuditLog.timestamp.desc())
        .limit(10)
        .all()
    )

    return render_template(
        "admin/dashboard.html",
        total_users=total_users,
        total_documents=total_documents,
        total_audit_events=total_audit_events,
        total_denied_events=total_denied_events,
        recent_alerts=recent_alerts,
        recent_activity=recent_activity,
    )


@admin_bp.route("/users")
@login_required
@admin_required
def users_list():
    """Manage users, account states, and role assignments."""
    users = User.query.order_by(User.created_at.desc()).all()
    role_form = UserRoleForm()
    return render_template("admin/users.html", users=users, role_form=role_form)


@admin_bp.route("/users/<int:user_id>/role", methods=["POST"])
@login_required
@admin_required
def update_user_role(user_id: int):
    """Change a user's role with self-lockout prevention."""
    user = db.get_or_404(User, user_id)
    if user.id == current_user.id:
        flash("You cannot modify your own administrative role.", "warning")
        return redirect(url_for("admin.users_list"))

    form = UserRoleForm()
    if form.validate_on_submit():
        old_role = user.role
        new_role = form.role.data
        if new_role not in UserRole.ALL:
            flash("Invalid role specified.", "danger")
            return redirect(url_for("admin.users_list"))

        user.role = new_role
        db.session.commit()

        log_audit_event(
            event_type=AuditEventType.ADMIN_USER_ROLE_CHANGE,
            status=AuditStatus.SUCCESS,
            user=current_user,
            resource_type="USER",
            resource_id=str(user.id),
            details={"target_username": user.username, "old_role": old_role, "new_role": new_role},
        )
        flash(f"Updated role for '{user.username}' from {old_role} to {new_role}.", "success")

    return redirect(url_for("admin.users_list"))


@admin_bp.route("/users/<int:user_id>/toggle-status", methods=["POST"])
@login_required
@admin_required
def toggle_user_status(user_id: int):
    """Activate or deactivate a user account."""
    user = db.get_or_404(User, user_id)
    if user.id == current_user.id:
        flash("You cannot deactivate your own account.", "warning")
        return redirect(url_for("admin.users_list"))

    user.is_active = not user.is_active
    db.session.commit()

    action = "ACTIVATED" if user.is_active else "DEACTIVATED"
    log_audit_event(
        event_type=AuditEventType.ADMIN_USER_STATUS_CHANGE,
        status=AuditStatus.SUCCESS,
        user=current_user,
        resource_type="USER",
        resource_id=str(user.id),
        details={"target_username": user.username, "status": action},
    )
    flash(f"Account for '{user.username}' has been {action.lower()}.", "info")
    return redirect(url_for("admin.users_list"))


@admin_bp.route("/audit-logs")
@login_required
@admin_required
def audit_logs():
    """Search and filter the audit trail."""
    event_type = request.args.get("event_type", "").strip()
    status = request.args.get("status", "").strip()
    username = request.args.get("username", "").strip()
    resource_type = request.args.get("resource_type", "").strip()
    page = request.args.get("page", 1, type=int)

    query = AuditLog.query

    if event_type:
        query = query.filter_by(event_type=event_type)
    if status:
        query = query.filter_by(status=status)
    if username:
        query = query.filter(AuditLog.username.ilike(f"%{username}%"))
    if resource_type:
        query = query.filter_by(resource_type=resource_type)

    paginated_logs = query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=25, error_out=False
    )

    return render_template(
        "admin/audit_logs.html",
        pagination=paginated_logs,
        logs=paginated_logs.items,
        event_type=event_type,
        status=status,
        username=username,
        resource_type=resource_type,
    )


@admin_bp.route("/audit-logs/verify", methods=["GET", "POST"])
@login_required
@admin_required
def verify_audit_log_chain():
    """Cryptographic verification of the append-only audit trail."""
    is_valid, total_records, broken_at_id, error_message = verify_audit_trail()

    log_audit_event(
        event_type=AuditEventType.ADMIN_CHAIN_VERIFY,
        status=AuditStatus.SUCCESS if is_valid else AuditStatus.DENIED,
        user=current_user,
        resource_type="SYSTEM",
        details={
            "is_valid": is_valid,
            "total_records": total_records,
            "broken_at_id": broken_at_id,
            "error_message": error_message,
        },
    )

    if is_valid:
        flash(
            f"Audit ledger integrity verified: all {total_records} records are mathematically cryptographically sound.",
            "success",
        )
    else:
        flash(
            f"INTEGRITY ALERT: Audit chain failure detected at record #{broken_at_id}! {error_message}",
            "danger",
        )

    return redirect(url_for("admin.audit_logs"))
