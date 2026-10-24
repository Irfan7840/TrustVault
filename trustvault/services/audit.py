import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
from flask import request
from flask_login import current_user
from trustvault.extensions import db
from trustvault.models.audit import AuditLog, AuditStatus


def log_audit_event(
    event_type: str,
    status: str = AuditStatus.SUCCESS,
    user: Any = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    details: Optional[Dict[str, Any] | str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> AuditLog:
    """Record a tamper-evident audit log entry with cryptographic hash chaining."""
    # Determine user identity
    if user is None:
        user = current_user if current_user and current_user.is_authenticated else None

    user_id = user.id if user and hasattr(user, "id") else None
    username = user.username if user and hasattr(user, "username") else None

    # Determine network context if inside request
    if ip_address is None:
        if request:
            # Respect reverse proxy headers safely if configured, fallback to remote_addr
            ip_address = request.headers.get("X-Forwarded-For", request.remote_addr)
            if ip_address and "," in ip_address:
                ip_address = ip_address.split(",")[0].strip()
        else:
            ip_address = "127.0.0.1"

    if user_agent is None:
        if request and request.user_agent:
            user_agent = request.user_agent.string[:255]
        else:
            user_agent = "System/CLI"

    # Format details as JSON string if dict passed
    if isinstance(details, dict):
        details_str = json.dumps(details, default=str)
    else:
        details_str = str(details) if details else ""

    # Fetch last audit entry to maintain hash chain
    last_log = (
        AuditLog.query.order_by(AuditLog.id.desc()).first()
    )
    previous_hash = last_log.entry_hash if last_log and last_log.entry_hash else "GENESIS"

    log_entry = AuditLog(
        timestamp=datetime.now(timezone.utc).replace(microsecond=0),
        user_id=user_id,
        username=username,
        ip_address=ip_address[:45] if ip_address else "unknown",
        user_agent=user_agent[:255] if user_agent else "unknown",
        event_type=event_type,
        status=status,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        details=details_str,
        previous_hash=previous_hash,
    )
    # Compute the SHA-256 hash
    log_entry.entry_hash = log_entry.compute_hash(previous_hash)

    db.session.add(log_entry)
    db.session.commit()
    return log_entry


def verify_audit_trail() -> Tuple[bool, int, Optional[int], Optional[str]]:
    """Verify cryptographic integrity of the entire audit chain.
    Returns:
        (is_valid, total_records, broken_at_id, error_message)
    """
    logs = AuditLog.query.order_by(AuditLog.id.asc()).all()
    if not logs:
        return True, 0, None, None

    expected_prev_hash = "GENESIS"
    for log in logs:
        # 1. Verify previous hash pointer matches previous entry's hash
        if log.previous_hash != expected_prev_hash:
            return (
                False,
                len(logs),
                log.id,
                f"Hash link broken at log #{log.id}: expected previous_hash {expected_prev_hash}, found {log.previous_hash}",
            )

        # 2. Verify current entry's calculated hash matches stored entry_hash
        recomputed_hash = log.compute_hash(log.previous_hash)
        if recomputed_hash != log.entry_hash:
            return (
                False,
                len(logs),
                log.id,
                f"Tampering detected at log #{log.id}: stored hash {log.entry_hash} does not match computed hash {recomputed_hash}",
            )

        expected_prev_hash = log.entry_hash

    return True, len(logs), None, None
