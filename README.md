# TrustVault — Secure Document Sharing with a Real Audit Trail

**TrustVault** is an enterprise-grade, security-hardened document-sharing web application built with Python 3 and Flask. Unlike conventional CRUD applications, TrustVault is designed under the **Principle of Least Privilege**, featuring **server-side object-level authorization (ACL)**, **instantaneous permission revocation**, **path traversal and injection defense**, and an **append-only, cryptographically chained audit ledger**.

---

## 1. Architectural Highlights & Security Model

```
+-----------------------------------------------------------------------------------+
|                                Client Browser                                     |
+-----------------------------------------------------------------------------------+
                                         |  HTTPS + CSRF Token + SameSite Cookies
                                         v
+-----------------------------------------------------------------------------------+
|                          Flask Security Middleware                                |
|        (CSP, Frame-Ancestors 'none', X-Content-Type-Options: nosniff, HSTS)        |
+-----------------------------------------------------------------------------------+
                                         |
         +-------------------------------+-------------------------------+
         |                               |                               |
         v                               v                               v
+------------------+           +-------------------+           +-------------------+
|  auth_bp (/auth) |           |  documents_bp     |           |  admin_bp (/admin)|
|  - PBKDF2 Hash   |           |  (/documents)     |           |  - User Management|
|  - Session Regen |           |  - Upload/View/DL |           |  - Audit Log Stream|
|  - Invalidation  |           |  - Grant/Revoke   |           |  - Ledger Verify  |
+------------------+           +---------+---------+           +-------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                     Centralized Access Control Engine                             |
|  1. Document Owner: full control (view, download, edit metadata, grant, delete)   |
|  2. Shared Users: READ (view/download) or EDIT (download/edit metadata)           |
|  3. Immediate Revocation: active DB lookup on every request; zero session lag     |
|  4. Admin Content Isolation: Admins DO NOT have implicit document read access!    |
|  5. Security Gate: Any unauthorized attempt aborts with HTTP 403 & logs incident  |
+----------------------------------------+------------------------------------------+
                                         |
         +-------------------------------+-------------------------------+
         |                                                               |
         v                                                               v
+----------------------------------+            +----------------------------------+
|          SQLAlchemy ORM          |            |     Isolated Secure Storage      |
|  - Users, Documents, Permissions |            |  - UUIDv4 Disk Keys (.dat)       |
|  - AuditLog (SHA-256 Hash Chain) |            |  - Strict Whitelist & MIME Check |
|  - SQLite (Dev/Test) / Postgres  |            |  - Path Traversal Blockade       |
+----------------------------------+            +----------------------------------+
```

### 1.1 Three Roles & Privilege Boundaries
* **Administrator**:
  * Accesses the administrative dashboard, user management, and security telemetry.
  * Can change user roles and toggle account active status.
  * Can search, filter, and cryptographically verify the audit ledger.
  * **Strict Content Isolation Policy**: Administrators **do not** automatically inherit document content access. Attempting to view or download a private document without explicit owner grant triggers an HTTP 403 and records an `ACCESS_DENIED` security incident.
* **Document Owner**:
  * Uploads and manages documents they own.
  * Grants named users `READ` or `EDIT` permissions by username or email.
  * Immediately revokes user permissions.
  * Views real-time access and download activity for their documents.
  * Deletes documents through an authorized server-side transaction that unlinks the disk file.
* **Viewer**:
  * Views metadata and downloads documents explicitly shared with them.
  * Cannot upload documents, edit metadata (unless upgraded to `EDIT`), delete documents, or grant access.
  * Any attempt to tamper with URLs (IDOR) is blocked and logged.

### 1.2 Immediate Permission Revocation
In many systems, user permissions are cached in web tokens or session cookies, causing a dangerous security window where revoked users can continue accessing confidential files until their session expires.
**TrustVault's Mitigation**:
* Document permissions are **never** stored in user session cookies.
* Every request evaluates the active database record inside the SQL transaction before streaming content or metadata.
* When an owner clicks "Revoke", the revocation takes effect **instantly on the very next request**.

### 1.3 Cryptographically Chained Audit Trail
TrustVault records both successful actions and unauthorized attempts:
* Every entry records: UTC timestamp, user ID, username, IP address, user agent, event type, status (`SUCCESS` / `DENIED`), resource, and details.
* **Hash Chaining**: Each entry stores `previous_hash` and `entry_hash`, where:
  $$\text{entry\_hash} = \text{SHA256}(\text{timestamp} \parallel \text{user\_id} \parallel \text{username} \parallel \text{ip} \parallel \text{event} \parallel \text{status} \parallel \text{resource} \parallel \text{details} \parallel \text{previous\_hash})$$
* **Tamper-Evidence**: Administrators can run "Verify Cryptographic Ledger" at any time. If an attacker or corrupt DBA alters or deletes a row, the cryptographic hash link breaks, identifying the exact tampered record ID.

---

## 2. Technology Stack

* **Backend**: Python 3.12 & Flask 3.x
* **Database & ORM**: SQLAlchemy 2.x & Flask-SQLAlchemy 3.x with Flask-Migrate (Alembic)
* **Authentication**: Flask-Login with strict session protection & Werkzeug password hashing
* **Form & Input Validation**: Flask-WTF & WTForms with CSRF tokens
* **Frontend**: Bootstrap 5.3, Bootstrap Icons, HTML5, CSS3, Vanilla JavaScript
* **Automated Testing**: pytest with in-memory SQLite and Flask test client
* **Configuration**: `python-dotenv` with `.env` and environment-specific configs

---

## 3. Project Directory Structure

```
TrustVault/
├── .env.example              # Sample configuration
├── .env                      # Local environment secrets (not committed)
├── .gitignore                # Git exclusions
├── config.py                 # Development, Testing, Production configurations
├── requirements.txt          # Pinned dependency requirements
├── run.py                    # Application entry point
├── pytest.ini                # Pytest configuration
├── migrations/               # Database migrations (Alembic)
├── storage/
│   └── documents/            # Isolated document repository (UUID-keyed)
├── trustvault/
│   ├── __init__.py           # Application Factory, security headers, error handlers
│   ├── extensions.py         # SQLAlchemy, Migrate, LoginManager, CSRFProtect
│   ├── models/
│   │   ├── __init__.py
│   │   ├── user.py           # User model & roles (ADMIN, OWNER, VIEWER)
│   │   ├── document.py       # Document model & metadata
│   │   ├── permission.py     # Object-Level Access Control (READ, EDIT)
│   │   └── audit.py          # Cryptographically chained AuditLog
│   ├── services/
│   │   ├── access_control.py # Authorization engine & route decorators
│   │   ├── audit.py          # Audit logging & cryptographic verification
│   │   └── file_storage.py   # Path traversal defense & UUID file storage
│   ├── auth/                 # Authentication Blueprint
│   ├── documents/            # Documents & Permissions Blueprint
│   ├── admin/                # Security Administration Blueprint
│   ├── templates/            # Jinja2 HTML5 templates
│   └── static/               # CSS styles & client enhancements
└── tests/
    ├── conftest.py           # Pytest fixtures & test helpers
    ├── test_auth.py          # Registration, login, session, password hashing
    ├── test_documents.py     # Upload, download, edit, delete, storage
    ├── test_permissions.py   # ACL, IDOR prevention, immediate revocation
    ├── test_audit.py         # Audit logging & hash chain tamper detection
    ├── test_admin.py         # Admin boundaries & content isolation policy
    └── test_security.py      # Traversal, null-byte, CSRF, security headers
```

---

## 4. Comprehensive Documentation Index

In addition to this README, TrustVault includes full technical documentation:

| Document | Purpose & Contents |
|---|---|
| [**THREATS.md**](file:///c:/Users/moham/Downloads/TrustVault/THREATS.md) | STRIDE threat model, OWASP Top 10 mitigations, detailed attack path walkthroughs, accepted risks. |
| [**API.md**](file:///c:/Users/moham/Downloads/TrustVault/API.md) | Comprehensive endpoint reference for Auth, Documents, and Admin routes (methods, roles, responses). |
| [**DATABASE.md**](file:///c:/Users/moham/Downloads/TrustVault/DATABASE.md) | Data dictionary, ER diagrams, indexes, SHA-256 Merkle chain mechanics, and Alembic migrations. |
| [**DEMO_SCRIPT.md**](file:///c:/Users/moham/Downloads/TrustVault/DEMO_SCRIPT.md) | 5-minute structured walkthrough testing all roles, uploads, permission grant/revoke, and audit. |
| [**SECURITY_TEST_REPORT.md**](file:///c:/Users/moham/Downloads/TrustVault/SECURITY_TEST_REPORT.md) | Automated test results (34/34 passing), vulnerability verification matrix, and security controls. |
| [**DEPLOYMENT.md**](file:///c:/Users/moham/Downloads/TrustVault/DEPLOYMENT.md) | Production setup for Render / Railway with PostgreSQL, persistent volumes, and health monitoring. |
| [**PROMPTS.md**](file:///c:/Users/moham/Downloads/TrustVault/PROMPTS.md) | Five dated AI-interaction logs documenting engineering requests, discoveries, and corrections. |

---

## 5. Setup & Running Locally

### 5.1 Prerequisites
* Python 3.10+ (Tested on Python 3.12)
* Windows, Linux, or macOS

### 5.2 Quickstart Commands

1. **Activate virtual environment**:
   ```bash
   # Windows PowerShell:
   .\.venv\Scripts\Activate.ps1
   # macOS / Linux:
   source .venv/bin/activate
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment**:
   Copy `.env.example` to `.env` (or configure desired environment variables).

4. **Initialize database & seed demo accounts**:
   ```bash
   # Apply migrations to head
   flask db upgrade

   # Seed synthetic demo accounts and sample documents
   flask seed-demo

   # (Optional) Create custom admin user
   flask create-admin admin admin@trustvault.local AdminVault2026!
   ```

5. **Start development server**:
   ```bash
   flask run
   ```
   Open your browser at `http://localhost:5000`.

### 5.3 Demo Credentials

| Role | Username | Password | Purpose |
|---|---|---|---|
| Administrator | `admin` | `AdminVault2026!` | Platform oversight, user management, audit ledger verification |
| Document Owner | `alice` | `Demo@Alice1` | Upload documents, categorize, grant/revoke permissions |
| Viewer | `bob` | `Demo@Bob12` | Read/download explicitly shared files (`Q4_Financial_Report.pdf`) |

---

## 6. Running Automated Security Tests

TrustVault includes a comprehensive automated test suite of **34 tests** with 100% pass rate.

Run all tests:
```bash
python -m pytest -v
```

Health check verification:
```bash
curl http://localhost:5000/health
# Response: {"db": true, "status": "ok"}
```

### Test Coverage Highlights:
| Test File | Security Property Tested |
|---|---|
| `test_auth.py` | PBKDF2 password hashing, registration complexity, invalid password audit logging, deactivated account lockdown, session cleanup |
| `test_documents.py` | Secure UUID file mapping, whitelist extension validation, traversal checks, safe disk unlinking upon deletion |
| `test_permissions.py` | IDOR prevention, READ vs EDIT capability enforcement, immediate permission revocation without session lag |
| `test_audit.py` | Cryptographic SHA-256 hash chaining, tamper detection algorithm catching row alteration |
| `test_admin.py` | Admin RBAC boundary, lockout prevention, **Admin Content Isolation Policy** |
| `test_security.py` | Path traversal attacks (`../../`), null byte injection (`\x00`), CSRF protection, HTTP security response headers |

---

## 6. Threat Model & OWASP Mitigations

| Vulnerability | Attack Vector | TrustVault Mitigation |
|---|---|---|
| **A01: Broken Access Control (IDOR)** | Changing document ID in URL to access unshared files | Object-level authorization via `evaluate_document_access()` verifies ownership or active ACL row on **every single request**. Returns 403 and records security audit incident. |
| **A01: Admin Privilege Escalation** | Admin snooping on sensitive employee documents | Policy enforced: Admins do not possess implicit content access. Only explicit owner grant permits read/download. |
| **A02: Cryptographic Failures** | Plaintext password or session compromise | Werkzeug PBKDF2/scrypt password hashing with unique salts. Cryptographic SHA-256 audit ledger with genesis chaining. |
| **A03: Injection & Path Traversal** | Uploading `../../win.ini` or executable scripts | Original client filename is stripped; stored on disk strictly as `<uuid4>.dat`. Destination verified via `os.path.commonpath`. Whitelist file extensions only. |
| **A05: Security Misconfiguration** | Clickjacking & MIME-sniffing | Headers attached on all responses: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: frame-ancestors 'none'`. |
| **A07: Identification & Authentication Failures** | Brute force & session fixation | `session.clear()` on login and logout; strong session protection; deactivated user lockouts. |
| **A08: Software and Data Integrity Failures** | Malicious DB row alteration to hide audit records | Append-only hash chain linking each audit record to the previous one. Chain integrity validator detects any discrepancy. |
| **A09: Security Logging & Monitoring Failures** | Silent unauthorized access attempts | Every 403 Forbidden automatically records an `ACCESS_DENIED` event with actor IP, timestamp, target doc ID, and action attempted. |

---

## 7. Production Deployment Guidelines

For deployment to a production environment (e.g., Docker, Linux VM, AWS):
1. **Database**: Point `DATABASE_URL` in `.env` to a managed PostgreSQL cluster (e.g. `postgresql://user:password@host:5432/trustvault`). Run `flask db upgrade`.
2. **Secrets**: Generate a cryptographically secure `SECRET_KEY` (`python -c "import secrets; print(secrets.token_hex(32))"`).
3. **Cookies**: Set `SESSION_COOKIE_SECURE=True` to ensure cookies only transmit over HTTPS.
4. **WSGI Server**: Serve the application using `gunicorn -w 4 -b 0.0.0.0:8000 "run:app"`.
5. **Reverse Proxy**: Place behind Nginx with TLS 1.3 certificates, client max body limits (16MB), and rate limiting.
