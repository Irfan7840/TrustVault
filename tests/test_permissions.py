from trustvault.models.permission import DocumentPermission, PermissionLevel
from trustvault.models.audit import AuditLog, AuditEventType, AuditStatus


def test_unauthorized_user_idor_blocked(client, auth, second_owner, sample_document, app):
    """Ensure an unauthorized user cannot view or download another user's document (IDOR defense)."""
    # Bob logs in and tries to access Alice's document
    auth.login("bob_owner", "BobSecurePass123!")

    # Attempt to view metadata
    view_resp = client.get(f"/documents/{sample_document}")
    assert view_resp.status_code == 403

    # Attempt to download file
    dl_resp = client.get(f"/documents/{sample_document}/download")
    assert dl_resp.status_code == 403

    # Attempt to edit
    edit_resp = client.post(
        f"/documents/{sample_document}/edit",
        data={"title": "Hacked Title"},
    )
    assert edit_resp.status_code == 403

    # Attempt to delete
    del_resp = client.post(f"/documents/{sample_document}/delete")
    assert del_resp.status_code == 403

    # Verify audit log captures ACCESS_DENIED
    with app.app_context():
        denied_logs = AuditLog.query.filter_by(
            event_type=AuditEventType.ACCESS_DENIED,
            status=AuditStatus.DENIED,
            resource_id=str(sample_document),
        ).all()
        assert len(denied_logs) >= 4


def test_grant_read_permission_and_restrictions(
    client, auth, owner_user, viewer_user, sample_document, app
):
    """Verify owner can grant READ permission; grantee can view and download, but cannot edit or delete."""
    # 1. Alice grants READ to Charlie
    auth.login("alice_owner", "AliceSecurePass123!")
    grant_resp = client.post(
        f"/documents/{sample_document}/permissions/grant",
        data={
            "username_or_email": "charlie_viewer",
            "permission_level": PermissionLevel.READ,
        },
        follow_redirects=True,
    )
    assert grant_resp.status_code == 200
    assert b"Granted READ permission" in grant_resp.data

    auth.logout()

    # 2. Charlie logs in
    auth.login("charlie_viewer", "CharlieSecurePass123!")

    # Charlie can view details
    view_resp = client.get(f"/documents/{sample_document}")
    assert view_resp.status_code == 200
    assert b"Confidential Strategy Plan" in view_resp.data

    # Charlie can download file
    dl_resp = client.get(f"/documents/{sample_document}/download")
    assert dl_resp.status_code == 200
    assert b"%PDF-1.4 Confidential" in dl_resp.data

    # Charlie CANNOT edit (403)
    edit_resp = client.post(
        f"/documents/{sample_document}/edit",
        data={"title": "Unauthorized Change by Reader"},
    )
    assert edit_resp.status_code == 403

    # Charlie CANNOT delete (403)
    del_resp = client.post(f"/documents/{sample_document}/delete")
    assert del_resp.status_code == 403


def test_grant_edit_permission(
    client, auth, owner_user, viewer_user, sample_document, app
):
    """Verify EDIT permission allows editing metadata but strictly prohibits deletion."""
    # Alice grants EDIT to Charlie
    auth.login("alice_owner", "AliceSecurePass123!")
    client.post(
        f"/documents/{sample_document}/permissions/grant",
        data={
            "username_or_email": "charlie_viewer",
            "permission_level": PermissionLevel.EDIT,
        },
        follow_redirects=True,
    )
    auth.logout()

    # Charlie logs in
    auth.login("charlie_viewer", "CharlieSecurePass123!")

    # Charlie edits metadata successfully
    edit_resp = client.post(
        f"/documents/{sample_document}/edit",
        data={"title": "Edited by Permitted Editor", "description": "Legitimate update"},
        follow_redirects=True,
    )
    assert edit_resp.status_code == 200
    assert b"Edited by Permitted Editor" in edit_resp.data

    # Charlie still CANNOT delete document (403)
    del_resp = client.post(f"/documents/{sample_document}/delete")
    assert del_resp.status_code == 403


def test_immediate_permission_revocation(
    client, auth, owner_user, viewer_user, sample_document, app
):
    """Test that permission revocation takes effect immediately on the very next request."""
    # Step 1: Alice grants READ permission to Charlie
    auth.login("alice_owner", "AliceSecurePass123!")
    client.post(
        f"/documents/{sample_document}/permissions/grant",
        data={
            "username_or_email": "charlie_viewer",
            "permission_level": PermissionLevel.READ,
        },
        follow_redirects=True,
    )

    with app.app_context():
        perm = DocumentPermission.query.filter_by(
            document_id=sample_document, user_id=viewer_user
        ).first()
        perm_id = perm.id
        assert perm is not None

    auth.logout()

    # Step 2: Charlie logs in and verifies access
    auth.login("charlie_viewer", "CharlieSecurePass123!")
    first_check = client.get(f"/documents/{sample_document}")
    assert first_check.status_code == 200

    # Step 3: Alice revokes Charlie's permission
    auth.logout()
    auth.login("alice_owner", "AliceSecurePass123!")
    revoke_resp = client.post(
        f"/documents/{sample_document}/permissions/{perm_id}/revoke",
        follow_redirects=True,
    )
    assert revoke_resp.status_code == 200
    assert b"Access revoked immediately" in revoke_resp.data
    auth.logout()

    # Step 4: Charlie makes a request immediately without logging in again
    auth.login("charlie_viewer", "CharlieSecurePass123!")
    immediate_view_resp = client.get(f"/documents/{sample_document}")
    assert immediate_view_resp.status_code == 403

    immediate_dl_resp = client.get(f"/documents/{sample_document}/download")
    assert immediate_dl_resp.status_code == 403
