from datetime import datetime, timezone
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from trustvault.extensions import db


class UserRole:
    ADMIN = "ADMIN"
    OWNER = "OWNER"
    VIEWER = "VIEWER"

    ALL = {ADMIN, OWNER, VIEWER}


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default=UserRole.OWNER)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    # Relationships
    documents_owned = db.relationship(
        "Document", back_populates="owner", cascade="all, delete-orphan", lazy="dynamic"
    )
    permissions_received = db.relationship(
        "DocumentPermission",
        foreign_keys="DocumentPermission.user_id",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )
    permissions_granted = db.relationship(
        "DocumentPermission",
        foreign_keys="DocumentPermission.granted_by_id",
        back_populates="granted_by",
        lazy="dynamic",
    )

    def set_password(self, password: str) -> None:
        """Hash password using Werkzeug's secure PBKDF2/scrypt implementation."""
        if not password or len(password) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Verify password against stored hash."""
        if not self.password_hash or not password:
            return False
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self) -> bool:
        return self.role == UserRole.ADMIN

    @property
    def is_owner(self) -> bool:
        return self.role == UserRole.OWNER

    @property
    def is_viewer(self) -> bool:
        return self.role == UserRole.VIEWER

    def __repr__(self) -> str:
        return f"<User {self.username} ({self.role})>"
