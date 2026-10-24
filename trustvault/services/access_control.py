from functools import wraps
from typing import Optional, Tuple
from flask import abort, flash, redirect, request, url_for
from flask_login import current_user
from trustvault.models.audit import AuditEventType, AuditStatus
from trustvault.models.document import Document
from trustvault.models.permission import DocumentPermission, PermissionLevel
from trustvault.models.user import UserRole
from trustvault.services.audit import log_audit_event


class AccessDeniedError(Exception):
    """Exception raised when an authorization check fails."""
    def __init__(self, message: str, doc_id: Optional[int] = None, action: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.doc_id = doc_id
        self.action = action


def evaluate_document_access(
    document: Document,
    user,
    required_action: str = "READ",  # "READ", "EDIT", "DELETE", "MANAGE_PERMISSIONS"
) -> Tuple[bool, str]:
    """Evaluate whether the given user has permission to perform required_action on document.
    
    Returns:
        (is_allowed: bool, reason: str)
    """
    if not user or not user.is_authenticated:
        return False, "User is not authenticated."

    if not user.is_active:
        return False, "User account is deactivated."

    # 1. Document Owner has full access to their own documents
    if document.owner_id == user.id:
        return True, "User is the document owner."

    # 2. DELETE and MANAGE_PERMISSIONS are strictly reserved for the document owner
    if required_action in ("DELETE", "MANAGE_PERMISSIONS"):
        return False, f"Only the document owner can perform '{required_action}'."

    # 3. Check explicit permission grants in database (immediate verification, no cache)
    permission = DocumentPermission.query.filter_by(
        document_id=document.id, user_id=user.id
    ).first()

    if permission:
        if required_action == "READ":
            return True, f"User has explicit '{permission.permission_level}' permission."
        if required_action == "EDIT":
            if permission.permission_level == PermissionLevel.EDIT:
                return True, "User has explicit 'EDIT' permission."
            else:
                return False, "User has 'READ' permission but requires 'EDIT' permission."

    # 4. Strict Administrator Boundary:
    # Administrators do NOT automatically inherit content or document access rights.
    if user.is_admin:
        return False, (
            "Access denied: Administrators do not possess implicit access to document "
            "contents. Explicit permission must be granted by the document owner."
        )

    return False, "No access permission granted for this document."


def require_document_access(document: Document, required_action: str = "READ") -> None:
    """Enforce document access or abort with HTTP 403 and record an audit log."""
    allowed, reason = evaluate_document_access(document, current_user, required_action)
    if not allowed:
        # Record security event in audit trail
        log_audit_event(
            event_type=AuditEventType.ACCESS_DENIED,
            status=AuditStatus.DENIED,
            user=current_user,
            resource_type="DOCUMENT",
            resource_id=str(document.id),
            details={
                "action": required_action,
                "reason": reason,
                "document_title": document.title,
                "owner_id": document.owner_id,
            },
        )
        abort(403, description=reason)


def admin_required(f):
    """Decorator to protect routes restricted to administrators."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("auth.login", next=request.url))
        if not current_user.is_admin:
            log_audit_event(
                event_type=AuditEventType.ACCESS_DENIED,
                status=AuditStatus.DENIED,
                user=current_user,
                resource_type="ADMIN_ROUTE",
                resource_id=request.path,
                details="Non-admin user attempted to access administrative route.",
            )
            abort(403, description="Administrator privileges required.")
        return f(*args, **kwargs)
    return decorated_function
