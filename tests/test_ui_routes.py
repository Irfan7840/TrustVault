from trustvault.models.document import Document
from trustvault.models.permission import DocumentPermission, PermissionLevel
from trustvault.models.audit import AuditLog, AuditEventType, AuditStatus
from trustvault.models.user import User


def test_dashboard_authenticated(client, auth, owner_user, sample_document):
    """Verify the enterprise dashboard renders with real database values."""
    auth.login("alice_owner", "AliceSecurePass123!")

    response = client.get("/documents/dashboard")
    assert response.status_code == 200
    assert b"Security Dashboard" in response.data
    assert b"Total Documents" in response.data
    assert b"Shared With Me" in response.data
    assert b"Audit Events" in response.data
    assert b"Access Denials" in response.data
    assert b"Confidential Strategy Plan" in response.data


def test_documents_category_filtering(client, auth, owner_user, app):
    """Verify that document category filtering returns expected records."""
    auth.login("alice_owner", "AliceSecurePass123!")

    # Create two documents with different categories
    with app.app_context():
        from trustvault.extensions import db
        doc1 = Document(
            uuid_name="uuid-fin-1",
            original_filename="fin.pdf",
            file_size=1024,
            mime_type="application/pdf",
            title="Q3 Balance Sheet",
            category="Financial",
            owner_id=owner_user,
        )
        doc2 = Document(
            uuid_name="uuid-legal-2",
            original_filename="legal.pdf",
            file_size=2048,
            mime_type="application/pdf",
            title="Employment Contract",
            category="Legal",
            owner_id=owner_user,
        )
        db.session.add_all([doc1, doc2])
        db.session.commit()

    # Filter by Financial
    resp_fin = client.get("/documents?category=Financial")
    assert resp_fin.status_code == 200
    assert b"Q3 Balance Sheet" in resp_fin.data
    assert b"Employment Contract" not in resp_fin.data

    # Filter by Legal
    resp_legal = client.get("/documents?category=Legal")
    assert resp_legal.status_code == 200
    assert b"Employment Contract" in resp_legal.data
    assert b"Q3 Balance Sheet" not in resp_legal.data


def test_permissions_center_view(client, auth, owner_user, viewer_user, sample_document, app):
    """Verify the centralized permissions manager displays active grants and revocation triggers."""
    # Grant permission to viewer
    with app.app_context():
        from trustvault.extensions import db
        perm = DocumentPermission(
            document_id=sample_document,
            user_id=viewer_user,
            permission_level=PermissionLevel.READ,
            granted_by_id=owner_user,
        )
        db.session.add(perm)
        db.session.commit()

    auth.login("alice_owner", "AliceSecurePass123!")

    response = client.get("/documents/permissions")
    assert response.status_code == 200
    assert b"Access Permissions Manager" in response.data
    assert b"charlie_viewer" in response.data
    assert b"Revoke Now" in response.data


def test_user_activity_view(client, auth, owner_user, sample_document):
    """Verify user can view their activity log stream."""
    auth.login("alice_owner", "AliceSecurePass123!")

    # Perform a view
    client.get(f"/documents/{sample_document}")

    # Access activity log
    response = client.get("/documents/activity")
    assert response.status_code == 200
    assert b"Activity & Audit Logs" in response.data
    assert b"DOC_VIEW" in response.data


def test_settings_change_password(client, auth, owner_user, app):
    """Verify working password change endpoint with validation and audit logging."""
    auth.login("alice_owner", "AliceSecurePass123!")

    # 1. Invalid current password rejected
    bad_resp = client.post(
        "/auth/settings",
        data={
            "current_password": "WrongPassword999!",
            "new_password": "BrandNewPassword2026!",
            "confirm_new_password": "BrandNewPassword2026!",
        },
        follow_redirects=True,
    )
    assert b"Current password entered is incorrect" in bad_resp.data

    # 2. Valid current password succeeds
    good_resp = client.post(
        "/auth/settings",
        data={
            "current_password": "AliceSecurePass123!",
            "new_password": "BrandNewPassword2026!",
            "confirm_new_password": "BrandNewPassword2026!",
        },
        follow_redirects=True,
    )
    assert b"Your password has been updated successfully" in good_resp.data

    auth.logout()

    # 3. Old password no longer works
    fail_login = auth.login("alice_owner", "AliceSecurePass123!")
    assert b"Invalid username or password" in fail_login.data

    # 4. New password works
    succ_login = auth.login("alice_owner", "BrandNewPassword2026!")
    assert b"Welcome back, alice_owner!" in succ_login.data

    # 5. Check audit log for AUTH_PASSWORD_CHANGE
    with app.app_context():
        pwd_audit = AuditLog.query.filter_by(
            event_type=AuditEventType.AUTH_PASSWORD_CHANGE, user_id=owner_user
        ).first()
        assert pwd_audit is not None
        assert pwd_audit.status == AuditStatus.SUCCESS


def test_health_check_endpoint(client):
    """Verify that the unauthenticated health-check endpoint reports DB status."""
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "ok"
    assert data["db"] is True
