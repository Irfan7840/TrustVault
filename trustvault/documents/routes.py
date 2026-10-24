from datetime import datetime, timezone
from pathlib import Path
from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    flash,
    request,
    current_app,
    send_file,
    abort,
)
from flask_login import login_required, current_user
from trustvault.extensions import db
from trustvault.models.user import User, UserRole
from trustvault.models.document import Document
from trustvault.models.permission import DocumentPermission, PermissionLevel
from trustvault.models.audit import AuditLog, AuditEventType, AuditStatus
from trustvault.documents.forms import DocumentUploadForm, DocumentEditForm, GrantPermissionForm
from trustvault.services.access_control import require_document_access, evaluate_document_access
from trustvault.services.file_storage import (
    save_uploaded_file,
    get_secure_file_path,
    delete_stored_file,
    FileStorageError,
)
from trustvault.services.audit import log_audit_event

documents_bp = Blueprint("documents", __name__, url_prefix="/documents")


@documents_bp.route("/dashboard")
@login_required
def dashboard():
    """Enterprise security dashboard with real-time database KPIs and telemetry."""
    # 1. Total Documents
    if current_user.is_admin:
        total_docs = Document.query.count()
    else:
        total_docs = Document.query.filter_by(owner_id=current_user.id).count()

    # 2. Shared with me
    shared_perms = DocumentPermission.query.filter_by(user_id=current_user.id).all()
    shared_docs_count = len(shared_perms)

    # User's owned document IDs
    owned_docs = Document.query.filter_by(owner_id=current_user.id).all()
    owned_ids = [str(d.id) for d in owned_docs]

    # 3. Activity Counts & Security Denials
    if current_user.is_admin:
        activity_count = AuditLog.query.count()
        denials_count = AuditLog.query.filter_by(status=AuditStatus.DENIED).count()
        recent_activity = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(8).all()
    else:
        # User's activity or activity on user's documents
        activity_query = AuditLog.query.filter(
            (AuditLog.user_id == current_user.id) |
            ((AuditLog.resource_type == "DOCUMENT") & (AuditLog.resource_id.in_(owned_ids) if owned_ids else False))
        )
        activity_count = activity_query.count()
        denials_count = activity_query.filter_by(status=AuditStatus.DENIED).count()
        recent_activity = activity_query.order_by(AuditLog.timestamp.desc()).limit(8).all()

    # 4. Recent documents (combination of owned and shared)
    recent_owned = (
        Document.query.filter_by(owner_id=current_user.id)
        .order_by(Document.updated_at.desc())
        .limit(6)
        .all()
    )

    # 5. Category breakdown
    category_counts = {}
    categories = ["General", "Financial", "Legal", "Security", "Technical", "Operations"]
    for cat in categories:
        if current_user.is_admin:
            c_count = Document.query.filter_by(category=cat).count()
        else:
            c_count = Document.query.filter_by(owner_id=current_user.id, category=cat).count()
        category_counts[cat] = c_count

    return render_template(
        "documents/dashboard.html",
        total_docs=total_docs,
        shared_docs_count=shared_docs_count,
        activity_count=activity_count,
        denials_count=denials_count,
        recent_owned=recent_owned,
        recent_activity=recent_activity,
        category_counts=category_counts,
    )


@documents_bp.route("")
@login_required
def list_documents():
    """List documents with tab filtering, category, search, and sorting."""
    tab = request.args.get("tab", "all").strip().lower()
    query_search = request.args.get("q", "").strip()
    category = request.args.get("category", "").strip()
    sort = request.args.get("sort", "newest").strip().lower()

    # Base query for owned
    owned_query = Document.query.filter_by(owner_id=current_user.id)
    if query_search:
        owned_query = owned_query.filter(
            (Document.title.ilike(f"%{query_search}%"))
            | (Document.original_filename.ilike(f"%{query_search}%"))
            | (Document.description.ilike(f"%{query_search}%"))
        )
    if category:
        owned_query = owned_query.filter_by(category=category)

    if sort == "oldest":
        owned_query = owned_query.order_by(Document.created_at.asc())
    elif sort == "name":
        owned_query = owned_query.order_by(Document.title.asc())
    else:
        owned_query = owned_query.order_by(Document.created_at.desc())

    owned_docs = owned_query.all()

    # Base query for shared
    shared_query = (
        DocumentPermission.query.filter_by(user_id=current_user.id)
        .join(Document)
    )
    if query_search:
        shared_query = shared_query.filter(
            (Document.title.ilike(f"%{query_search}%"))
            | (Document.original_filename.ilike(f"%{query_search}%"))
            | (Document.description.ilike(f"%{query_search}%"))
        )
    if category:
        shared_query = shared_query.filter(Document.category == category)

    if sort == "oldest":
        shared_query = shared_query.order_by(DocumentPermission.granted_at.asc())
    elif sort == "name":
        shared_query = shared_query.order_by(Document.title.asc())
    else:
        shared_query = shared_query.order_by(DocumentPermission.granted_at.desc())

    shared_permissions = shared_query.all()

    # Total counts for tab badges
    total_owned_count = Document.query.filter_by(owner_id=current_user.id).count()
    total_shared_count = DocumentPermission.query.filter_by(user_id=current_user.id).count()

    categories = ["General", "Financial", "Legal", "Security", "Technical", "Operations"]

    return render_template(
        "documents/list.html",
        tab=tab,
        owned_docs=owned_docs,
        shared_permissions=shared_permissions,
        query_search=query_search,
        selected_category=category,
        sort=sort,
        categories=categories,
        total_owned_count=total_owned_count,
        total_shared_count=total_shared_count,
    )


@documents_bp.route("/permissions")
@login_required
def permissions_center():
    """Centralized permission manager for documents owned by current user."""
    # Fetch all permissions granted on documents owned by current user
    active_shares = (
        DocumentPermission.query.join(Document)
        .filter(Document.owner_id == current_user.id)
        .order_by(DocumentPermission.granted_at.desc())
        .all()
    )

    owned_docs = Document.query.filter_by(owner_id=current_user.id).all()

    return render_template(
        "documents/permissions.html",
        active_shares=active_shares,
        owned_docs=owned_docs,
    )


@documents_bp.route("/activity")
@login_required
def user_activity():
    """Activity logs relevant to current user and their owned documents."""
    page = request.args.get("page", 1, type=int)
    event_type = request.args.get("event_type", "").strip()
    status = request.args.get("status", "").strip()

    if current_user.is_admin:
        query = AuditLog.query
    else:
        owned_docs = Document.query.filter_by(owner_id=current_user.id).all()
        owned_ids = [str(d.id) for d in owned_docs]
        query = AuditLog.query.filter(
            (AuditLog.user_id == current_user.id) |
            ((AuditLog.resource_type == "DOCUMENT") & (AuditLog.resource_id.in_(owned_ids) if owned_ids else False))
        )

    if event_type:
        query = query.filter_by(event_type=event_type)
    if status:
        query = query.filter_by(status=status)

    paginated_logs = query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=20, error_out=False
    )

    return render_template(
        "documents/activity.html",
        pagination=paginated_logs,
        logs=paginated_logs.items,
        event_type=event_type,
        status=status,
    )


@documents_bp.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    """Upload a new document with strict validation and isolated storage."""
    # Check if user role allows uploading
    if current_user.is_viewer:
        flash("Viewers are not permitted to upload documents.", "warning")
        return redirect(url_for("documents.list_documents"))

    form = DocumentUploadForm()
    if form.validate_on_submit():
        uploaded_file = form.document_file.data
        upload_folder = Path(current_app.config["UPLOAD_FOLDER"])
        allowed_exts = current_app.config["ALLOWED_EXTENSIONS"]

        try:
            uuid_name, orig_name, file_size, mime_type = save_uploaded_file(
                uploaded_file, upload_folder, allowed_exts
            )

            document = Document(
                uuid_name=uuid_name,
                original_filename=orig_name,
                file_size=file_size,
                mime_type=mime_type,
                title=form.title.data.strip(),
                category=form.category.data if form.category.data else "General",
                description=form.description.data.strip() if form.description.data else None,
                owner_id=current_user.id,
            )
            db.session.add(document)
            db.session.commit()

            # Audit record
            log_audit_event(
                event_type=AuditEventType.DOC_UPLOAD,
                status=AuditStatus.SUCCESS,
                user=current_user,
                resource_type="DOCUMENT",
                resource_id=str(document.id),
                details={
                    "title": document.title,
                    "filename": document.original_filename,
                    "file_size": document.file_size,
                    "mime_type": document.mime_type,
                },
            )

            flash(f"Document '{document.title}' uploaded successfully.", "success")
            return redirect(url_for("documents.view_document", doc_id=document.id))

        except FileStorageError as e:
            flash(str(e), "danger")
        except Exception as e:
            db.session.rollback()
            current_app.logger.exception("Document upload error")
            flash("An unexpected error occurred while saving the file.", "danger")

    return render_template("documents/upload.html", form=form)


@documents_bp.route("/<int:doc_id>")
@login_required
def view_document(doc_id: int):
    """View document metadata, authorized permissions, and activity."""
    document = db.get_or_404(Document, doc_id)
    # Enforce READ access
    require_document_access(document, "READ")

    # Record view event in audit log
    log_audit_event(
        event_type=AuditEventType.DOC_VIEW,
        status=AuditStatus.SUCCESS,
        user=current_user,
        resource_type="DOCUMENT",
        resource_id=str(document.id),
        details={"title": document.title},
    )

    # Calculate permissions status for the UI
    is_owner = (document.owner_id == current_user.id)
    can_edit, _ = evaluate_document_access(document, current_user, "EDIT")
    grant_form = GrantPermissionForm() if is_owner else None

    # Load active permissions if owner
    active_permissions = []
    if is_owner:
        active_permissions = DocumentPermission.query.filter_by(
            document_id=document.id
        ).all()

    # Load recent audit activity for this document
    doc_audits = (
        AuditLog.query.filter_by(resource_type="DOCUMENT", resource_id=str(document.id))
        .order_by(AuditLog.timestamp.desc())
        .limit(25)
        .all()
    )

    return render_template(
        "documents/view.html",
        document=document,
        is_owner=is_owner,
        can_edit=can_edit,
        grant_form=grant_form,
        active_permissions=active_permissions,
        doc_audits=doc_audits,
    )


@documents_bp.route("/<int:doc_id>/download")
@login_required
def download(doc_id: int):
    """Stream document content securely with strict headers and audit logging."""
    document = db.get_or_404(Document, doc_id)
    # Enforce READ access (strictly denies administrators unless explicitly permitted!)
    require_document_access(document, "READ")

    upload_folder = Path(current_app.config["UPLOAD_FOLDER"])
    try:
        file_path = get_secure_file_path(document.uuid_name, upload_folder)
    except FileStorageError as e:
        flash(f"Storage error: {str(e)}", "danger")
        return redirect(url_for("documents.view_document", doc_id=doc_id))

    # Log successful download in audit trail
    log_audit_event(
        event_type=AuditEventType.DOC_DOWNLOAD,
        status=AuditStatus.SUCCESS,
        user=current_user,
        resource_type="DOCUMENT",
        resource_id=str(document.id),
        details={
            "title": document.title,
            "filename": document.original_filename,
            "file_size": document.file_size,
        },
    )

    response = send_file(
        file_path,
        as_attachment=True,
        download_name=document.original_filename,
        mimetype=document.mime_type,
    )
    # Prevent MIME sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@documents_bp.route("/<int:doc_id>/edit", methods=["GET", "POST"])
@login_required
def edit(doc_id: int):
    """Edit document title and description (Owner or EDIT grantee)."""
    document = db.get_or_404(Document, doc_id)
    require_document_access(document, "EDIT")

    form = DocumentEditForm(obj=document)
    if form.validate_on_submit():
        old_title = document.title
        document.title = form.title.data.strip()
        document.category = form.category.data if form.category.data else "General"
        document.description = form.description.data.strip() if form.description.data else None
        document.updated_at = datetime.now(timezone.utc)
        db.session.commit()

        log_audit_event(
            event_type=AuditEventType.DOC_UPDATE,
            status=AuditStatus.SUCCESS,
            user=current_user,
            resource_type="DOCUMENT",
            resource_id=str(document.id),
            details={"old_title": old_title, "new_title": document.title},
        )

        flash("Document details updated successfully.", "success")
        return redirect(url_for("documents.view_document", doc_id=document.id))

    return render_template("documents/edit.html", form=form, document=document)


@documents_bp.route("/<int:doc_id>/delete", methods=["POST"])
@login_required
def delete(doc_id: int):
    """Delete document and its physical disk file (strictly Owner only)."""
    document = db.get_or_404(Document, doc_id)
    # Strict DELETE authorization check
    require_document_access(document, "DELETE")

    doc_id_val = document.id
    doc_title = document.title
    uuid_name = document.uuid_name
    upload_folder = Path(current_app.config["UPLOAD_FOLDER"])

    # Remove from DB first
    db.session.delete(document)
    db.session.commit()

    # Safely remove file on disk
    delete_stored_file(uuid_name, upload_folder)

    log_audit_event(
        event_type=AuditEventType.DOC_DELETE,
        status=AuditStatus.SUCCESS,
        user=current_user,
        resource_type="DOCUMENT",
        resource_id=str(doc_id_val),
        details={"title": doc_title},
    )

    flash(f"Document '{doc_title}' has been deleted permanently.", "info")
    return redirect(url_for("documents.list_documents"))


@documents_bp.route("/<int:doc_id>/permissions/grant", methods=["POST"])
@login_required
def grant_permission(doc_id: int):
    """Grant or update named user permission on a document (Owner only)."""
    document = db.get_or_404(Document, doc_id)
    require_document_access(document, "MANAGE_PERMISSIONS")

    form = GrantPermissionForm()
    if form.validate_on_submit():
        target_input = form.username_or_email.data.strip()
        target_user = User.query.filter(
            (User.username == target_input) | (User.email == target_input.lower())
        ).first()

        if not target_user:
            flash(f"User '{target_input}' not found.", "danger")
            return redirect(url_for("documents.view_document", doc_id=document.id))

        if target_user.id == current_user.id:
            flash("You cannot grant permissions to yourself.", "warning")
            return redirect(url_for("documents.view_document", doc_id=document.id))

        level = form.permission_level.data
        existing_perm = DocumentPermission.query.filter_by(
            document_id=document.id, user_id=target_user.id
        ).first()

        if existing_perm:
            old_level = existing_perm.permission_level
            existing_perm.permission_level = level
            existing_perm.granted_by_id = current_user.id
            existing_perm.granted_at = datetime.now(timezone.utc)
            db.session.commit()

            log_audit_event(
                event_type=AuditEventType.PERM_GRANT,
                status=AuditStatus.SUCCESS,
                user=current_user,
                resource_type="DOCUMENT",
                resource_id=str(document.id),
                details={
                    "grantee_id": target_user.id,
                    "grantee_username": target_user.username,
                    "old_level": old_level,
                    "new_level": level,
                    "action": "UPDATE",
                },
            )
            flash(f"Updated permission for '{target_user.username}' to {level}.", "success")
        else:
            new_perm = DocumentPermission(
                document_id=document.id,
                user_id=target_user.id,
                permission_level=level,
                granted_by_id=current_user.id,
            )
            db.session.add(new_perm)
            db.session.commit()

            log_audit_event(
                event_type=AuditEventType.PERM_GRANT,
                status=AuditStatus.SUCCESS,
                user=current_user,
                resource_type="DOCUMENT",
                resource_id=str(document.id),
                details={
                    "grantee_id": target_user.id,
                    "grantee_username": target_user.username,
                    "level": level,
                    "action": "GRANT",
                },
            )
            flash(f"Granted {level} permission to '{target_user.username}'.", "success")

    return redirect(url_for("documents.view_document", doc_id=document.id))


@documents_bp.route("/<int:doc_id>/permissions/<int:perm_id>/revoke", methods=["POST"])
@login_required
def revoke_permission(doc_id: int, perm_id: int):
    """Immediately revoke a user's permission on a document (Owner only)."""
    document = db.get_or_404(Document, doc_id)
    require_document_access(document, "MANAGE_PERMISSIONS")

    permission = db.session.query(DocumentPermission).filter_by(
        id=perm_id, document_id=document.id
    ).first()
    if not permission:
        abort(404)

    revoked_user_id = permission.user_id
    revoked_username = permission.user.username if permission.user else "Unknown"
    revoked_level = permission.permission_level

    # Delete permission from DB (takes immediate effect on next request)
    db.session.delete(permission)
    db.session.commit()

    log_audit_event(
        event_type=AuditEventType.PERM_REVOKE,
        status=AuditStatus.SUCCESS,
        user=current_user,
        resource_type="DOCUMENT",
        resource_id=str(document.id),
        details={
            "revoked_user_id": revoked_user_id,
            "revoked_username": revoked_username,
            "revoked_level": revoked_level,
        },
    )

    flash(f"Access revoked immediately for '{revoked_username}'.", "info")
    return redirect(url_for("documents.view_document", doc_id=document.id))
