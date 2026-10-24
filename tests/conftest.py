import io
import shutil
from pathlib import Path
import pytest
from trustvault import create_app
from trustvault.extensions import db
from trustvault.models.user import User, UserRole
from trustvault.models.document import Document
from trustvault.models.permission import DocumentPermission, PermissionLevel
from trustvault.services.file_storage import save_uploaded_file
from werkzeug.datastructures import FileStorage


@pytest.fixture
def app(tmp_path):
    """Create and configure a testing Flask application instance."""
    app = create_app("testing")
    app.config["UPLOAD_FOLDER"] = tmp_path / "uploads"
    app.config["UPLOAD_FOLDER"].mkdir(parents=True, exist_ok=True)
    app.config["WTF_CSRF_ENABLED"] = False  # Disabled for endpoint testing convenience

    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

    # Clean up test uploads
    if app.config["UPLOAD_FOLDER"].exists():
        shutil.rmtree(app.config["UPLOAD_FOLDER"], ignore_errors=True)


@pytest.fixture
def client(app):
    """A test client for the application."""
    return app.test_client()


@pytest.fixture
def runner(app):
    """A test runner for the application's Click commands."""
    return app.test_cli_runner()


class AuthHelper:
    def __init__(self, client):
        self.client = client

    def login(self, username="owner1", password="Password123!"):
        return self.client.post(
            "/auth/login",
            data={"username": username, "password": password},
            follow_redirects=True,
        )

    def logout(self):
        return self.client.post("/auth/logout", follow_redirects=True)


@pytest.fixture
def auth(client):
    return AuthHelper(client)


@pytest.fixture
def admin_user(app):
    with app.app_context():
        user = User(
            username="admin_user",
            email="admin@trustvault.local",
            role=UserRole.ADMIN,
            is_active=True,
        )
        user.set_password("AdminSecurePass123!")
        db.session.add(user)
        db.session.commit()
        return user.id


@pytest.fixture
def owner_user(app):
    with app.app_context():
        user = User(
            username="alice_owner",
            email="alice@trustvault.local",
            role=UserRole.OWNER,
            is_active=True,
        )
        user.set_password("AliceSecurePass123!")
        db.session.add(user)
        db.session.commit()
        return user.id


@pytest.fixture
def second_owner(app):
    with app.app_context():
        user = User(
            username="bob_owner",
            email="bob@trustvault.local",
            role=UserRole.OWNER,
            is_active=True,
        )
        user.set_password("BobSecurePass123!")
        db.session.add(user)
        db.session.commit()
        return user.id


@pytest.fixture
def viewer_user(app):
    with app.app_context():
        user = User(
            username="charlie_viewer",
            email="charlie@trustvault.local",
            role=UserRole.VIEWER,
            is_active=True,
        )
        user.set_password("CharlieSecurePass123!")
        db.session.add(user)
        db.session.commit()
        return user.id


@pytest.fixture
def sample_document(app, owner_user):
    with app.app_context():
        upload_folder = Path(app.config["UPLOAD_FOLDER"])
        fake_content = b"%PDF-1.4 Confidential TrustVault Document Content..."
        storage = FileStorage(
            stream=io.BytesIO(fake_content),
            filename="confidential_plan.pdf",
            content_type="application/pdf",
        )
        uuid_name, orig_name, file_size, mime_type = save_uploaded_file(
            storage, upload_folder, app.config["ALLOWED_EXTENSIONS"]
        )

        doc = Document(
            uuid_name=uuid_name,
            original_filename=orig_name,
            file_size=file_size,
            mime_type=mime_type,
            title="Confidential Strategy Plan",
            description="Restricted company strategy plan for Q4.",
            owner_id=owner_user,
        )
        db.session.add(doc)
        db.session.commit()
        return doc.id
