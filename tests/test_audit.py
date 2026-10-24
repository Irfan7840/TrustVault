from trustvault.extensions import db
from trustvault.models.audit import AuditLog, AuditEventType, AuditStatus
from trustvault.services.audit import verify_audit_trail, log_audit_event


def test_audit_log_cryptographic_chain(app):
    """Verify that sequentially generated audit logs form a valid SHA-256 hash chain."""
    with app.app_context():
        log1 = log_audit_event(
            event_type=AuditEventType.AUTH_LOGIN_SUCCESS,
            status=AuditStatus.SUCCESS,
            resource_type="USER",
            resource_id="1",
            details="User logged in",
        )
        assert log1.previous_hash == "GENESIS"
        assert log1.entry_hash is not None

        log2 = log_audit_event(
            event_type=AuditEventType.DOC_VIEW,
            status=AuditStatus.SUCCESS,
            resource_type="DOCUMENT",
            resource_id="42",
            details="Viewed document 42",
        )
        assert log2.previous_hash == log1.entry_hash

        log3 = log_audit_event(
            event_type=AuditEventType.ACCESS_DENIED,
            status=AuditStatus.DENIED,
            resource_type="DOCUMENT",
            resource_id="99",
            details="Unauthorized attempt",
        )
        assert log3.previous_hash == log2.entry_hash

        # Run verification tool
        is_valid, count, broken_id, err = verify_audit_trail()
        assert is_valid is True
        assert count == 3
        assert broken_id is None


def test_tamper_detection_in_audit_chain(app):
    """Ensure direct tampering with an existing audit row is detected by the cryptographic validator."""
    with app.app_context():
        log_audit_event(event_type="EVENT_A", details="Original state")
        target_log = log_audit_event(event_type="EVENT_B", details="Crucial transaction")
        log_audit_event(event_type="EVENT_C", details="Subsequent event")

        # Initial chain is intact
        is_valid, _, _, _ = verify_audit_trail()
        assert is_valid is True

        # Malicious insider alters details in target_log without updating entry_hash
        target_log.details = "Malicious alteration concealing access"
        db.session.commit()

        # Run verification tool
        is_valid, total, broken_id, err = verify_audit_trail()
        assert is_valid is False
        assert broken_id == target_log.id
        assert "Tampering detected" in err
