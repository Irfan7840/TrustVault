import hashlib
from datetime import datetime, timezone
from trustvault.extensions import db


class AuditEventType:
    # Auth events
    AUTH_REGISTER = "AUTH_REGISTER"
    AUTH_LOGIN_SUCCESS = "AUTH_LOGIN_SUCCESS"
    AUTH_LOGIN_FAILED = "AUTH_LOGIN_FAILED"
    AUTH_LOGOUT = "AUTH_LOGOUT"
    AUTH_PASSWORD_CHANGE = "AUTH_PASSWORD_CHANGE"
    
    # Document events
    DOC_UPLOAD = "DOC_UPLOAD"
    DOC_VIEW = "DOC_VIEW"
    DOC_DOWNLOAD = "DOC_DOWNLOAD"
    DOC_UPDATE = "DOC_UPDATE"
    DOC_DELETE = "DOC_DELETE"
    
    # Permission events
    PERM_GRANT = "PERM_GRANT"
    PERM_REVOKE = "PERM_REVOKE"
    
    # Security events
    ACCESS_DENIED = "ACCESS_DENIED"
    
    # Admin events
    ADMIN_USER_ROLE_CHANGE = "ADMIN_USER_ROLE_CHANGE"
    ADMIN_USER_STATUS_CHANGE = "ADMIN_USER_STATUS_CHANGE"
    ADMIN_CHAIN_VERIFY = "ADMIN_CHAIN_VERIFY"


class AuditStatus:
    SUCCESS = "SUCCESS"
    DENIED = "DENIED"


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True
    )
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    username = db.Column(db.String(64), nullable=True)  # Snapshot of username at log time
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    event_type = db.Column(db.String(50), nullable=False, index=True)
    status = db.Column(db.String(20), nullable=False, default=AuditStatus.SUCCESS, index=True)
    resource_type = db.Column(db.String(50), nullable=True)  # e.g. "DOCUMENT", "USER", "SYSTEM"
    resource_id = db.Column(db.String(100), nullable=True)   # e.g. document ID
    details = db.Column(db.Text, nullable=True)
    
    # Cryptographic Tamper-Evidence
    previous_hash = db.Column(db.String(64), nullable=False, default="GENESIS")
    entry_hash = db.Column(db.String(64), nullable=False)

    user = db.relationship("User", foreign_keys=[user_id])

    def compute_hash(self, prev_hash: str) -> str:
        """Calculate the SHA-256 hash of this entry combined with previous_hash.
        Normalizes timestamp to a deterministic UTC format to ensure consistency across DB engines.
        """
        if self.timestamp:
            time_str = self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        else:
            time_str = ""
        raw = (
            f"{time_str}|{self.user_id}|{self.username}|{self.ip_address}|"
            f"{self.event_type}|{self.status}|{self.resource_type}|"
            f"{self.resource_id}|{self.details}|{prev_hash}"
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def __repr__(self) -> str:
        return f"<AuditLog id={self.id} event={self.event_type} status={self.status} user={self.username}>"
