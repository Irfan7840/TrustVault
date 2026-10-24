import os
from flask import Flask, render_template, redirect, url_for, jsonify
from flask_login import current_user
from config import config_by_name
from trustvault.extensions import db, migrate, login_manager, csrf
from trustvault.models import User, Document, DocumentPermission, AuditLog


def create_app(config_name: str = "default") -> Flask:
    """Application factory for TrustVault."""
    app = Flask(__name__)
    config_obj = config_by_name.get(config_name, config_by_name["default"])
    app.config.from_object(config_obj)

    # Ensure upload folder exists
    upload_folder = app.config.get("UPLOAD_FOLDER")
    if upload_folder:
        os.makedirs(upload_folder, exist_ok=True)

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)

    # Enable ProxyFix to correctly detect HTTPS when behind Pinggy, Cloudflare, or cloud proxies
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

    @login_manager.user_loader
    def load_user(user_id):
        # Refresh user from DB on each request — ensures revoked/deactivated
        # accounts are detected immediately.
        return db.session.get(User, int(user_id))

    # Register Blueprints
    from trustvault.auth.routes import auth_bp
    from trustvault.documents.routes import documents_bp
    from trustvault.admin.routes import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(documents_bp)
    app.register_blueprint(admin_bp)

    # Root route
    @app.route("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("documents.dashboard"))
        return redirect(url_for("auth.login"))

    # Health-check endpoint — unauthenticated; used by Render/Railway
    @app.route("/health")
    def health():
        try:
            db.session.execute(db.text("SELECT 1"))
            db_ok = True
        except Exception:
            db_ok = False
        payload = {"status": "ok" if db_ok else "degraded", "db": db_ok}
        return jsonify(payload), 200 if db_ok else 503

    # Security Response Headers
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "frame-ancestors 'none';"
        )
        return response

    # Global Error Handlers
    @app.errorhandler(400)
    def bad_request(error):
        return render_template("errors/400.html", error=error), 400

    @app.errorhandler(403)
    def forbidden(error):
        return render_template("errors/403.html", error=error), 403

    @app.errorhandler(404)
    def not_found(error):
        return render_template("errors/404.html", error=error), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template("errors/500.html", error=error), 500

    # Register CLI commands
    register_commands(app)

    return app


def register_commands(app: Flask):
    import click
    from trustvault.models.user import UserRole

    @app.cli.command("init-db")
    def init_db():
        """Initialize database schema tables."""
        with app.app_context():
            db.create_all()
            click.echo("Initialized the database tables successfully.")

    @app.cli.command("create-admin")
    @click.argument("username")
    @click.argument("email")
    @click.argument("password")
    def create_admin(username, email, password):
        """Create or promote an administrator account."""
        with app.app_context():
            user = User.query.filter(
                (User.username == username) | (User.email == email.lower())
            ).first()

            if user:
                user.role = UserRole.ADMIN
                user.set_password(password)
                click.echo(f"Updated existing user '{user.username}' to ADMIN.")
            else:
                user = User(
                    username=username.strip(),
                    email=email.strip().lower(),
                    role=UserRole.ADMIN,
                    is_active=True,
                )
                user.set_password(password)
                db.session.add(user)
                click.echo(f"Created new ADMIN user '{username}'.")

            db.session.commit()
            click.echo("Admin account ready.")

    @app.cli.command("seed-demo")
    def seed_demo():
        """Seed realistic demo accounts and sample documents for demonstrations."""
        import io
        from pathlib import Path
        from werkzeug.datastructures import FileStorage
        from trustvault.models.document import Document
        from trustvault.models.permission import DocumentPermission, PermissionLevel
        from trustvault.models.audit import AuditEventType, AuditStatus
        from trustvault.services.file_storage import save_uploaded_file
        from trustvault.services.audit import log_audit_event

        with app.app_context():
            # ── Demo users ─────────────────────────────────────────────────
            demo_users = [
                dict(username="alice", email="alice@demo.local",
                     password="Demo@Alice1", role=UserRole.OWNER),
                dict(username="bob",   email="bob@demo.local",
                     password="Demo@Bob12", role=UserRole.VIEWER),
            ]

            created = {}
            for ud in demo_users:
                u = User.query.filter_by(username=ud["username"]).first()
                if not u:
                    u = User(username=ud["username"], email=ud["email"],
                             role=ud["role"], is_active=True)
                    u.set_password(ud["password"])
                    db.session.add(u)
                    db.session.flush()
                    click.echo(f"  Created user: {ud['username']}")
                else:
                    click.echo(f"  User already exists: {ud['username']}")
                created[ud["username"]] = u

            db.session.commit()

            # ── Sample documents ────────────────────────────────────────────
            alice = created["alice"]
            bob   = created["bob"]
            upload_folder = Path(app.config["UPLOAD_FOLDER"])
            allowed_exts = app.config["ALLOWED_EXTENSIONS"]

            sample_docs = [
                dict(filename="Q4_Financial_Report.pdf",
                     title="Q4 Financial Report",
                     category="Financial",
                     description="Q4 Financial Summary for executive review.",
                     content=b"Q4 Financial Summary - CONFIDENTIAL\n\nRevenue: $4.2M\nExpenses: $2.8M\nNet: $1.4M"),
                dict(filename="Employee_Handbook_2026.pdf",
                     title="Employee Handbook 2026",
                     category="Operations",
                     description="Company operational policies and handbook.",
                     content=b"TrustVault Employee Handbook 2026\n\nWelcome to the team."),
                dict(filename="Product_Roadmap_v2.pdf",
                     title="Product Roadmap 2026-2027",
                     category="Technical",
                     description="Confidential engineering architecture roadmap.",
                     content=b"TrustVault Product Roadmap 2026-2027\n\nPhase 1: Core security\nPhase 2: Enterprise SSO"),
            ]

            for sd in sample_docs:
                existing = Document.query.filter_by(
                    original_filename=sd["filename"], owner_id=alice.id
                ).first()
                if existing:
                    click.echo(f"  Document already exists: {sd['filename']}")
                    continue

                fake_file = FileStorage(
                    stream=io.BytesIO(sd["content"]),
                    filename=sd["filename"],
                    content_type="application/pdf",
                )

                uuid_name, orig_name, file_size, mime_type = save_uploaded_file(
                    fake_file, upload_folder, allowed_exts
                )

                doc = Document(
                    uuid_name=uuid_name,
                    original_filename=orig_name,
                    title=sd["title"],
                    category=sd["category"],
                    description=sd["description"],
                    file_size=file_size,
                    mime_type=mime_type,
                    owner_id=alice.id,
                )
                db.session.add(doc)
                db.session.flush()

                # Grant bob READ on the first document
                if sd["filename"] == "Q4_Financial_Report.pdf":
                    perm = DocumentPermission(
                        document_id=doc.id,
                        user_id=bob.id,
                        permission_level=PermissionLevel.READ,
                        granted_by_id=alice.id,
                    )
                    db.session.add(perm)

                log_audit_event(
                    event_type=AuditEventType.DOC_UPLOAD,
                    status=AuditStatus.SUCCESS,
                    user=alice,
                    resource_type="DOCUMENT",
                    resource_id=str(doc.id),
                    details={
                        "title": doc.title,
                        "filename": doc.original_filename,
                        "file_size": doc.file_size,
                    },
                )
                click.echo(f"  Created document: {sd['filename']}")

            db.session.commit()
            click.echo("\nDemo seed complete.")
            click.echo("  alice / Demo@Alice1  (OWNER)")
            click.echo("  bob   / Demo@Bob12   (VIEWER — READ on Q4 report)")
