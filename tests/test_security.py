import io
from pathlib import Path
import pytest
from trustvault import create_app
from trustvault.extensions import db
from trustvault.models.user import User, UserRole
from trustvault.models.document import Document
from trustvault.models.permission import DocumentPermission, PermissionLevel
from trustvault.services.file_storage import (
    save_uploaded_file,
    get_secure_file_path,
    is_allowed_file,
    FileStorageError,
)
from werkzeug.datastructures import FileStorage


def test_path_traversal_in_file_storage_resolver(app):
    """Verify get_secure_file_path raises FileStorageError on traversal attempts."""
    upload_folder = Path(app.config["UPLOAD_FOLDER"])
    with pytest.raises(FileStorageError):
        get_secure_file_path("../../../etc/passwd", upload_folder)

    with pytest.raises(FileStorageError):
        get_secure_file_path("..\\..\\Windows\\System32\\cmd.exe", upload_folder)


def test_null_byte_injection_rejected():
    """Ensure null byte injection attempts in file extensions are rejected."""
    allowed = {"pdf", "txt"}
    assert is_allowed_file("report.php\x00.pdf", allowed) is False
    assert is_allowed_file("valid.pdf", allowed) is True


def test_security_response_headers(client):
    """Verify production security headers are attached to HTTP responses."""
    response = client.get("/auth/login")
    assert response.status_code == 200
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert "Content-Security-Policy" in response.headers
    assert "frame-ancestors 'none'" in response.headers.get("Content-Security-Policy")


def test_csrf_protection_enforcement(tmp_path):
    """Verify that when CSRF protection is active, POST requests without CSRF token are rejected."""
    app_csrf = create_app("testing")
    app_csrf.config["WTF_CSRF_ENABLED"] = True
    app_csrf.config["UPLOAD_FOLDER"] = tmp_path / "uploads"
    app_csrf.config["UPLOAD_FOLDER"].mkdir(parents=True, exist_ok=True)

    with app_csrf.app_context():
        db.create_all()
        client = app_csrf.test_client()

        # Attempt to POST registration without CSRF token
        response = client.post(
            "/auth/register",
            data={
                "username": "attacker",
                "email": "attacker@example.com",
                "role": "OWNER",
                "password": "Password123!",
                "confirm_password": "Password123!",
            },
        )
        assert response.status_code == 400
        db.session.remove()
        db.drop_all()


def test_admin_can_access_when_explicitly_granted(
    client, auth, admin_user, owner_user, sample_document, app
):
    """Verify that while Admins do not have automatic content access,
    they CAN access if the document owner explicitly grants them permission.
    """
    # 1. Initially, admin is blocked (403)
    auth.login("admin_user", "AdminSecurePass123!")
    assert client.get(f"/documents/{sample_document}").status_code == 403
    auth.logout()

    # 2. Owner explicitly grants READ permission to the admin user
    auth.login("alice_owner", "AliceSecurePass123!")
    client.post(
        f"/documents/{sample_document}/permissions/grant",
        data={
            "username_or_email": "admin_user",
            "permission_level": PermissionLevel.READ,
        },
        follow_redirects=True,
    )
    auth.logout()

    # 3. Admin now has legitimate explicit access
    auth.login("admin_user", "AdminSecurePass123!")
    view_resp = client.get(f"/documents/{sample_document}")
    assert view_resp.status_code == 200
    assert b"Confidential Strategy Plan" in view_resp.data

    dl_resp = client.get(f"/documents/{sample_document}/download")
    assert dl_resp.status_code == 200
    assert b"%PDF-1.4 Confidential" in dl_resp.data
