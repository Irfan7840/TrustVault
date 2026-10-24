import pytest
from trustvault.models.user import User, UserRole
from trustvault.models.audit import AuditLog, AuditEventType, AuditStatus


def test_user_password_hashing(app):
    """Verify passwords are never stored in plaintext and match Werkzeug hash."""
    with app.app_context():
        user = User(username="security_tester", email="test@sec.com", role=UserRole.OWNER)
        user.set_password("ComplexPass99#")
        assert user.password_hash != "ComplexPass99#"
        assert user.check_password("ComplexPass99#") is True
        assert user.check_password("WrongPassword123") is False


def test_registration_success(client, app):
    """Test standard user registration flow."""
    response = client.post(
        "/auth/register",
        data={
            "username": "new_user_1",
            "email": "new_user@example.com",
            "role": UserRole.OWNER,
            "password": "SecurePassword123!",
            "confirm_password": "SecurePassword123!",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Account created successfully" in response.data

    with app.app_context():
        user = User.query.filter_by(username="new_user_1").first()
        assert user is not None
        assert user.email == "new_user@example.com"
        assert user.role == UserRole.OWNER
        assert user.is_active is True

        # Check audit log
        audit = AuditLog.query.filter_by(
            event_type=AuditEventType.AUTH_REGISTER, user_id=user.id
        ).first()
        assert audit is not None
        assert audit.status == AuditStatus.SUCCESS


def test_registration_weak_password_rejected(client, app):
    """Ensure weak passwords failing complexity rules are rejected."""
    response = client.post(
        "/auth/register",
        data={
            "username": "weak_pwd_user",
            "email": "weak@example.com",
            "role": UserRole.VIEWER,
            "password": "weak",
            "confirm_password": "weak",
        },
    )
    assert response.status_code == 200
    assert b"Password must be at least 8 characters" in response.data


def test_login_success(client, auth, owner_user):
    """Test successful login redirects and creates session."""
    response = auth.login("alice_owner", "AliceSecurePass123!")
    assert response.status_code == 200
    assert b"Welcome back, alice_owner!" in response.data
    assert b"alice_owner" in response.data


def test_login_invalid_password_logged(client, auth, owner_user, app):
    """Test invalid credentials fail and generate security audit entry."""
    response = auth.login("alice_owner", "IncorrectPassword!")
    assert response.status_code == 200
    assert b"Invalid username or password" in response.data

    with app.app_context():
        failed_audit = AuditLog.query.filter_by(
            event_type=AuditEventType.AUTH_LOGIN_FAILED, status=AuditStatus.DENIED
        ).first()
        assert failed_audit is not None
        assert "Invalid credentials" in failed_audit.details


def test_login_deactivated_account_blocked(client, auth, owner_user, app):
    """Ensure deactivated accounts cannot log in."""
    with app.app_context():
        from trustvault.extensions import db
        user = db.session.get(User, owner_user)
        user.is_active = False
        db.session.commit()

    response = auth.login("alice_owner", "AliceSecurePass123!")
    assert response.status_code == 200
    assert b"Your account has been deactivated" in response.data


def test_logout(client, auth, owner_user, app):
    """Test logout invalidates session and logs audit event."""
    auth.login("alice_owner", "AliceSecurePass123!")
    response = auth.logout()
    assert response.status_code == 200
    assert b"You have been signed out safely" in response.data

    with app.app_context():
        logout_audit = AuditLog.query.filter_by(
            event_type=AuditEventType.AUTH_LOGOUT, user_id=owner_user
        ).first()
        assert logout_audit is not None
