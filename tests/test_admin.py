from trustvault.extensions import db
from trustvault.models.user import User, UserRole
from trustvault.models.audit import AuditLog, AuditEventType, AuditStatus


def test_non_admin_blocked_from_admin_routes(client, auth, owner_user, app):
    """Ensure non-admin users receive 403 when attempting to access admin endpoints."""
    auth.login("alice_owner", "AliceSecurePass123!")

    assert client.get("/admin").status_code == 403
    assert client.get("/admin/users").status_code == 403
    assert client.get("/admin/audit-logs").status_code == 403


def test_admin_dashboard_and_user_management(client, auth, admin_user, viewer_user, app):
    """Verify administrator can view dashboard, change roles, and deactivate users."""
    auth.login("admin_user", "AdminSecurePass123!")

    # Access dashboard
    dash_resp = client.get("/admin")
    assert dash_resp.status_code == 200
    assert b"Administrative Security Center" in dash_resp.data

    # View user management
    users_resp = client.get("/admin/users")
    assert users_resp.status_code == 200
    assert b"charlie_viewer" in users_resp.data

    # Update viewer role to OWNER
    role_resp = client.post(
        f"/admin/users/{viewer_user}/role",
        data={"role": UserRole.OWNER},
        follow_redirects=True,
    )
    assert role_resp.status_code == 200
    with app.app_context():
        user = db.session.get(User, viewer_user)
        assert user.role == UserRole.OWNER

    # Deactivate user
    toggle_resp = client.post(
        f"/admin/users/{viewer_user}/toggle-status",
        follow_redirects=True,
    )
    assert toggle_resp.status_code == 200
    with app.app_context():
        user = db.session.get(User, viewer_user)
        assert user.is_active is False


def test_admin_cannot_deactivate_or_demote_self(client, auth, admin_user, app):
    """Ensure administrator cannot accidentally lock themselves out."""
    auth.login("admin_user", "AdminSecurePass123!")

    # Try to demote self
    demote_resp = client.post(
        f"/admin/users/{admin_user}/role",
        data={"role": UserRole.VIEWER},
        follow_redirects=True,
    )
    assert demote_resp.status_code == 200
    assert b"You cannot modify your own administrative role" in demote_resp.data

    with app.app_context():
        user = db.session.get(User, admin_user)
        assert user.role == UserRole.ADMIN

    # Try to deactivate self
    deact_resp = client.post(
        f"/admin/users/{admin_user}/toggle-status",
        follow_redirects=True,
    )
    assert deact_resp.status_code == 200
    assert b"You cannot deactivate your own account" in deact_resp.data

    with app.app_context():
        user = db.session.get(User, admin_user)
        assert user.is_active is True


def test_admin_content_isolation_boundary(
    client, auth, admin_user, owner_user, sample_document, app
):
    """CRITICAL SECURITY REQUIREMENT:
    Administrators must NOT automatically inherit document content access.
    Attempting to view or download document contents without explicit grant results in HTTP 403.
    """
    auth.login("admin_user", "AdminSecurePass123!")

    # Admin attempts to view private document details
    view_resp = client.get(f"/documents/{sample_document}")
    assert view_resp.status_code == 403

    # Admin attempts to download document file
    dl_resp = client.get(f"/documents/{sample_document}/download")
    assert dl_resp.status_code == 403

    # Verify audit log captures ACCESS_DENIED for the administrator
    with app.app_context():
        admin_denied_log = AuditLog.query.filter_by(
            event_type=AuditEventType.ACCESS_DENIED,
            status=AuditStatus.DENIED,
            resource_id=str(sample_document),
            user_id=admin_user,
        ).first()
        assert admin_denied_log is not None
        assert "Administrators do not possess implicit access" in admin_denied_log.details
