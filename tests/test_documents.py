import io
from pathlib import Path
from trustvault.models.document import Document
from trustvault.models.audit import AuditLog, AuditEventType, AuditStatus
from trustvault.services.file_storage import get_secure_file_path


def test_document_upload_success(client, auth, owner_user, app):
    """Test document owner can successfully upload an allowed file."""
    auth.login("alice_owner", "AliceSecurePass123!")

    file_data = {
        "title": "Quarterly Audit Report",
        "description": "Financial compliance documentation.",
        "document_file": (io.BytesIO(b"Quarterly results data..."), "audit_report.txt"),
    }

    response = client.post(
        "/documents/upload",
        data=file_data,
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Quarterly Audit Report" in response.data

    with app.app_context():
        doc = Document.query.filter_by(title="Quarterly Audit Report").first()
        assert doc is not None
        assert doc.original_filename == "audit_report.txt"
        assert doc.owner_id == owner_user

        # Verify disk file exists using UUID
        upload_folder = Path(app.config["UPLOAD_FOLDER"])
        file_path = get_secure_file_path(doc.uuid_name, upload_folder)
        assert file_path.exists()
        assert file_path.read_bytes() == b"Quarterly results data..."

        # Verify audit log
        audit = AuditLog.query.filter_by(
            event_type=AuditEventType.DOC_UPLOAD, resource_id=str(doc.id)
        ).first()
        assert audit is not None
        assert audit.status == AuditStatus.SUCCESS


def test_viewer_cannot_upload_document(client, auth, viewer_user):
    """Test that users with VIEWER role are prevented from uploading."""
    auth.login("charlie_viewer", "CharlieSecurePass123!")

    response = client.get("/documents/upload", follow_redirects=True)
    assert response.status_code == 200
    assert b"Viewers are not permitted to upload documents" in response.data


def test_disallowed_extension_rejected(client, auth, owner_user):
    """Ensure dangerous file extensions are rejected by whitelist validation."""
    auth.login("alice_owner", "AliceSecurePass123!")

    file_data = {
        "title": "Malicious Script",
        "document_file": (io.BytesIO(b"malicious payload"), "exploit.exe"),
    }
    response = client.post(
        "/documents/upload",
        data=file_data,
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"File type not permitted" in response.data


def test_owner_can_view_and_download(client, auth, owner_user, sample_document):
    """Verify owner can view details and download the file stream."""
    auth.login("alice_owner", "AliceSecurePass123!")

    # View details
    view_resp = client.get(f"/documents/{sample_document}")
    assert view_resp.status_code == 200
    assert b"Confidential Strategy Plan" in view_resp.data

    # Download file
    dl_resp = client.get(f"/documents/{sample_document}/download")
    assert dl_resp.status_code == 200
    assert dl_resp.headers["Content-Disposition"].startswith("attachment")
    assert "confidential_plan.pdf" in dl_resp.headers["Content-Disposition"]
    assert b"%PDF-1.4 Confidential" in dl_resp.data


def test_owner_can_edit_metadata(client, auth, owner_user, sample_document, app):
    """Verify owner can update title and description."""
    auth.login("alice_owner", "AliceSecurePass123!")

    response = client.post(
        f"/documents/{sample_document}/edit",
        data={
            "title": "Updated Strategy Plan",
            "description": "Updated notes for executive review.",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Updated Strategy Plan" in response.data

    with app.app_context():
        from trustvault.extensions import db
        doc = db.session.get(Document, sample_document)
        assert doc.title == "Updated Strategy Plan"
        assert doc.description == "Updated notes for executive review."


def test_owner_can_delete_document(client, auth, owner_user, sample_document, app):
    """Verify document deletion removes DB row and disk file."""
    auth.login("alice_owner", "AliceSecurePass123!")

    with app.app_context():
        from trustvault.extensions import db
        doc = db.session.get(Document, sample_document)
        uuid_name = doc.uuid_name
        upload_folder = Path(app.config["UPLOAD_FOLDER"])
        file_path = get_secure_file_path(uuid_name, upload_folder)
        assert file_path.exists()

    response = client.post(f"/documents/{sample_document}/delete", follow_redirects=True)
    assert response.status_code == 200
    assert b"has been deleted permanently" in response.data

    with app.app_context():
        assert db.session.get(Document, sample_document) is None
        assert not file_path.exists()
