from datetime import datetime, timezone
from trustvault.extensions import db


class PermissionLevel:
    READ = "READ"
    EDIT = "EDIT"

    ALL = {READ, EDIT}


class DocumentPermission(db.Model):
    __tablename__ = "document_permissions"
    __table_args__ = (
        db.UniqueConstraint("document_id", "user_id", name="uq_doc_user_permission"),
    )

    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(
        db.Integer, db.ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    permission_level = db.Column(db.String(10), nullable=False, default=PermissionLevel.READ)
    granted_by_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False
    )
    granted_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    # Relationships
    document = db.relationship("Document", back_populates="permissions")
    user = db.relationship("User", foreign_keys=[user_id], back_populates="permissions_received")
    granted_by = db.relationship("User", foreign_keys=[granted_by_id], back_populates="permissions_granted")

    def __repr__(self) -> str:
        return f"<DocumentPermission doc={self.document_id} user={self.user_id} level={self.permission_level}>"
