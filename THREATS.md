# TrustVault Threat Model

> **Version:** 1.0  
> **Last Updated:** October 2026  
> **Scope:** TrustVault web application — authentication, document management, permission control, and audit logging.

---

## Overview

TrustVault is a Flask-based secure document storage and sharing platform. Users upload files, manage access permissions per document, and every action is recorded in a tamper-evident, hash-chained audit log. The system supports three roles — `ADMIN`, `OWNER`, and `VIEWER` — each with distinct capabilities enforced server-side.

This threat model covers:

- The web application layer (Flask routes, session management, CSRF protection)
- The data layer (SQLite in development, PostgreSQL in production via SQLAlchemy)
- The file storage layer (disk-based, UUID-named files in the `storage/` directory)
- The access control layer (`evaluate_document_access()` in `trustvault/services/access_control.py`)
- The audit trail layer (SHA-256 hash-chained log entries in `trustvault/services/audit.py`)

**Primary assets to protect:**

| Asset | Sensitivity | Why |
|---|---|---|
| Uploaded document files | High | May contain confidential personal or business data |
| User credentials (password hashes) | Critical | Compromise leads to account takeover |
| Audit log integrity | High | Tampered logs undermine non-repudiation |
| Permission records | High | Incorrect permissions expose data to unauthorized users |
| Session tokens | High | Token theft leads to session hijacking |

---

## Trust Boundaries

TrustVault operates across three principal trust boundaries. Each boundary is a potential attack surface and must be protected independently.

### Browser ↔ Flask (HTTPS)

All traffic between client browsers and the Flask application must travel over HTTPS (TLS). This boundary is exposed to:

- Passive network eavesdroppers (mitigated by TLS encryption)
- Active man-in-the-middle attackers (mitigated by valid TLS certificates and HSTS headers)
- Unauthenticated or session-forged HTTP requests (mitigated by Flask-Login and CSRF tokens)
- Malicious form submissions or crafted HTTP requests (mitigated by input validation and server-side authorization)

In production (Render), HTTPS is enforced by the platform's reverse proxy. In development, it is the developer's responsibility to use HTTPS or accept the reduced security posture.

### Flask ↔ SQLite / PostgreSQL

This boundary separates the application logic from the database engine. The risks here include:

- SQL injection (mitigated by SQLAlchemy ORM parameterized queries — raw SQL is not used)
- Unauthorized direct database access (mitigated by keeping the database file or connection string out of public reach)
- Data exfiltration if the database file is readable by OS-level users (mitigated by file permissions on `instance/trustvault.db`)

In production (PostgreSQL on Render), the connection string in `DATABASE_URL` must be stored as a secret environment variable and never committed to version control.

### Flask ↔ Disk (File Storage)

Uploaded files are written to and read from the `storage/` directory. The risks here include:

- Path traversal attacks that attempt to read arbitrary files outside `storage/` (mitigated by UUID-based `storage_filename` field and path validation)
- Null byte injection in filenames (mitigated by server-side filename sanitization)
- Storage exhaustion (denial of service via large uploads — future mitigation: per-user quotas and file size limits)
- Symlink attacks (mitigated by not resolving symlinks and validating the resolved path stays within `storage/`)

---

## STRIDE Analysis

STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) is a structured threat categorization framework. Each category is analyzed below for TrustVault's specific context.

---

### Spoofing Identity

Spoofing involves an attacker pretending to be a legitimate user or service.

#### Threat S-1: Credential Brute-Force

**Description:** An attacker submits a high volume of login requests with different passwords to guess a valid user's credentials. Because TrustVault currently has no rate limiting on the `/auth/login` endpoint, an automated tool could submit thousands of attempts per minute.

**Impact:** Account takeover. If an OWNER account is compromised, all of that user's documents become accessible to the attacker. If an ADMIN account is compromised, the attacker gains full platform visibility.

**Mitigations Implemented:**
- Passwords are stored as bcrypt hashes (via Flask-Login / Werkzeug `generate_password_hash`). Even if the database is exfiltrated, brute-forcing bcrypt hashes offline is computationally expensive.
- Flask-Login session protection is set to `"strong"`, which regenerates the session cookie on privilege change and invalidates sessions when the user-agent changes unexpectedly.
- All failed login attempts are recorded in the audit log with the actor's IP address, enabling post-incident forensics.

**Residual Risk:** No in-application rate limiting is currently implemented. This is a **known limitation** (see Known Limitations section). Future mitigation: Flask-Limiter with a Redis backend.

---

#### Threat S-2: Session Token Theft (Session Hijacking)

**Description:** If a session cookie is transmitted over HTTP (not HTTPS), a network attacker can intercept it. Alternatively, if XSS is present, JavaScript can read `document.cookie` and exfiltrate the token.

**Impact:** Attacker assumes the identity of the authenticated user for the duration of the session.

**Mitigations Implemented:**
- Session cookies are configured with `HttpOnly=True` to prevent JavaScript access.
- Session cookies are configured with `SameSite=Lax` to mitigate CSRF.
- In production, `SESSION_COOKIE_SECURE=True` ensures cookies are only transmitted over HTTPS.
- Flask-Login's `"strong"` session protection invalidates sessions on IP or user-agent change.

---

#### Threat S-3: Forged Requests (CSRF)

**Description:** A malicious website causes an authenticated TrustVault user's browser to submit a state-changing request (e.g., granting document permissions, deleting a document) without the user's knowledge.

**Impact:** An attacker could silently grant themselves read or edit access to a victim's documents, or modify/delete documents.

**Mitigations Implemented:**
- Flask-WTF CSRF protection is enforced on all state-changing POST/PUT/DELETE endpoints.
- CSRF tokens are embedded in every HTML form and verified server-side before any mutation is applied.
- Covered by: `test_csrf_protection_enforcement`

---

### Tampering

Tampering involves unauthorized modification of data, code, or communications.

#### Threat T-1: Direct Database Modification (Audit Log Tampering)

**Description:** An attacker with database-level access (e.g., a compromised server, a malicious insider, or a SQL injection chain) attempts to modify or delete audit log records to cover their tracks.

**Impact:** Non-repudiation is undermined. A user could deny performing an action that they actually performed, or evidence of an attack could be erased.

**Mitigations Implemented:**
- Every `audit_log` record contains a `record_hash` field: a SHA-256 hash computed over `(event_type + actor_id + document_id + status + timestamp + previous_hash)`.
- Each record's `previous_hash` chains it to the preceding record, forming a hash chain analogous to a blockchain.
- The `verify_audit_trail()` function in `trustvault/services/audit.py` recomputes every hash in sequence and raises an integrity error if any record has been modified or deleted.
- Covered by: `test_audit_trail_hash_chain_integrity`

**Residual Risk:** If an attacker has write access to both the database and the source code, they could recompute the entire hash chain after modification. Defense in depth requires taking the database offline and generating a signed snapshot for archival.

---

#### Threat T-2: Document File Replacement

**Description:** An attacker with access to the server filesystem (or via path traversal) replaces a stored document file with a malicious or modified version.

**Impact:** A user downloads a document they believe is authentic but receives a tampered file.

**Mitigations Implemented:**
- Stored files are named by UUID (`storage_filename`), not by user-supplied filenames, making it impossible to predict file paths.
- The `storage/` directory should be configured with restrictive OS permissions (readable/writable only by the application process user).
- Future enhancement: per-file content hash stored at upload time for integrity verification on download.

---

#### Threat T-3: Tampering with HTTP Requests in Transit

**Description:** A man-in-the-middle attacker modifies HTTP request or response bodies.

**Impact:** Could alter permission grant payloads, inject malicious content into responses, or corrupt uploaded files.

**Mitigations Implemented:**
- All traffic in production is TLS-encrypted (Render's reverse proxy enforces HTTPS).
- CSRF tokens prevent blind request forgery even if traffic were somehow interceptable.

---

### Repudiation

Repudiation involves a user denying they performed an action, or the system lacking evidence to prove otherwise.

#### Threat R-1: User Denies Performing a Sensitive Action

**Description:** A user (or their legal representative) claims they did not upload a document, did not grant a permission, or did not delete a file.

**Impact:** Without verifiable logs, the system cannot provide forensic evidence.

**Mitigations Implemented:**
- Every significant action (login, logout, document upload, document download, permission grant, permission revoke, document delete, access denial) is recorded in `audit_logs` with:
  - `actor_id` (who performed the action)
  - `event_type` (what action was taken)
  - `document_id` (which document was affected, where applicable)
  - `status` (SUCCESS or DENIED)
  - `ip_address` (client IP at the time of the action)
  - `timestamp` (UTC timestamp)
- The hash-chain integrity mechanism (see T-1) ensures logs cannot be silently modified after the fact.
- All audit records are append-only by application design (no UPDATE or DELETE operations on `audit_logs` through the application layer).

---

#### Threat R-2: Admin Denies Reading a User's Documents

**Description:** An admin claims they did not access a restricted document.

**Impact:** Users cannot verify whether their documents were accessed by platform administrators.

**Mitigations Implemented:**
- Every document download attempt (whether successful or denied) is recorded in the audit log.
- The Admin Content Isolation Policy (see dedicated section below) enforces that admins cannot access document file contents without an explicit permission grant from the document owner, and any such access attempt is logged.

---

### Information Disclosure

Information disclosure involves sensitive data being exposed to unauthorized parties.

#### Threat I-1: Cross-User Document Read (IDOR)

**Description:** An authenticated user manipulates a document ID in a URL or API parameter to access a document owned by another user for which they have no permission.

**Example:** User B knows that document ID `42` belongs to User A. User B navigates to `/documents/42/download` expecting to receive User A's file.

**Impact:** Confidential documents are exposed to unauthorized users.

**Mitigations Implemented:**
- Every document endpoint calls `evaluate_document_access()` in `trustvault/services/access_control.py` before serving any content.
- `evaluate_document_access()` checks: (1) is the requesting user the document owner? (2) does the requesting user have an explicit `READ` or `EDIT` permission record for this document? If neither check passes, access is denied with HTTP 403.
- The denial is recorded in the audit log.
- Covered by: `test_unauthorized_user_idor_blocked`

---

#### Threat I-2: Path Traversal in File Download

**Description:** An attacker manipulates a file download request to include path traversal sequences (e.g., `../../etc/passwd`) in order to read arbitrary files from the server filesystem.

**Impact:** Attacker reads sensitive server files (configuration, private keys, the database file itself, `/etc/shadow`, etc.).

**Mitigations Implemented:**
- The application never uses a user-supplied filename to resolve the physical file path. Instead, it looks up the `storage_filename` (a UUID) from the database for the given document ID, then constructs the path as `os.path.join(STORAGE_PATH, storage_filename)`.
- The resolved path is validated to confirm it begins with the `storage/` directory prefix before the file is opened.
- Covered by: `test_path_traversal_in_file_storage_resolver`

---

#### Threat I-3: Null Byte Injection in Filenames

**Description:** An attacker uploads a file with a null byte (`\x00`) in the filename (e.g., `report.pdf\x00.sh`). In some environments, C-based string functions truncate at null bytes, causing the system to treat the file as `report.pdf` while the filesystem stores it under a different extension.

**Impact:** Bypasses extension-based file type validation; could lead to server-side script execution or incorrect MIME type serving.

**Mitigations Implemented:**
- The application sanitizes uploaded filenames and rejects any filename containing null bytes before saving.
- The physical storage name is always a UUID (not derived from the original filename), so even a crafted filename cannot affect the stored path.
- Covered by: `test_null_byte_injection_rejected`

---

#### Threat I-4: Password Hash Exposure via Database Exfiltration

**Description:** An attacker exfiltrates the SQLite database file (`instance/trustvault.db`) or a PostgreSQL dump and extracts password hashes.

**Impact:** Offline password cracking could recover plaintext passwords, especially for users with weak passwords.

**Mitigations Implemented:**
- Passwords are hashed with bcrypt (via Werkzeug), which uses a work factor (cost) to make brute-forcing computationally expensive.
- Each hash includes a unique per-user salt, preventing rainbow table attacks.
- The `.gitignore` excludes `instance/trustvault.db` to prevent the database from being committed to version control.

---

#### Threat I-5: Sensitive Data in Error Messages

**Description:** Unhandled exceptions or debug tracebacks expose internal implementation details (file paths, SQL queries, stack traces) in HTTP responses.

**Impact:** Attacker learns the application's internal structure, making subsequent targeted attacks easier.

**Mitigations Implemented:**
- Flask's `DEBUG=False` is enforced in production (controlled via the `FLASK_ENV` / `FLASK_DEBUG` environment variables).
- Custom error handlers return generic error messages without internal details.

---

### Denial of Service

Denial of Service (DoS) involves making the system unavailable to legitimate users.

#### Threat D-1: Large File Upload Exhausting Disk Space

**Description:** An authenticated user uploads extremely large files repeatedly, filling the server's disk and preventing other users from uploading documents or the application from functioning.

**Impact:** Complete service outage for all users.

**Mitigations Implemented:**
- Flask's `MAX_CONTENT_LENGTH` setting limits the maximum upload size per request.
- Files exceeding this limit result in HTTP 413 without being written to disk.

**Residual Risk:** A user could upload many files each approaching the size limit. Future mitigation: per-user storage quotas enforced at the application layer.

---

#### Threat D-2: Login Endpoint Flooding

**Description:** An attacker floods the `/auth/login` endpoint with requests, consuming server resources and blocking legitimate logins.

**Impact:** Legitimate users cannot log in; server resources (CPU, memory, database connections) are exhausted.

**Mitigations Implemented:**
- bcrypt's computational cost naturally slows down mass login attempts (each bcrypt comparison takes ~100ms).
- Flask-Login session protection limits the impact of a successful brute-force.

**Residual Risk:** No explicit rate limiting is implemented. This is a **known limitation**. Future mitigation: Flask-Limiter.

---

#### Threat D-3: Database Query Flooding (Application-Level DoS)

**Description:** An authenticated attacker repeatedly triggers expensive database queries (e.g., listing all documents, querying audit logs) to exhaust database connections or response capacity.

**Impact:** Increased response times; potential service degradation.

**Mitigations Implemented:**
- SQLAlchemy connection pooling limits concurrent database connections.
- Appropriate database indexes are defined on commonly queried columns (see DATABASE.md for index list).

---

### Elevation of Privilege

Elevation of privilege involves an attacker gaining access rights beyond what they are authorized for.

#### Threat E-1: Role Manipulation via API Tampering

**Description:** An attacker with a `VIEWER` role submits a crafted request to change their own role to `ADMIN` or `OWNER`, either by manipulating form fields or by directly calling an admin endpoint.

**Impact:** Attacker gains administrative access to the entire platform.

**Mitigations Implemented:**
- User roles are stored in the database and enforced server-side. No client-provided role value is trusted.
- Admin-only routes are protected by a `@admin_required` decorator that checks `current_user.role == Role.ADMIN` on every request.
- There is no application endpoint that allows a user to set their own role. Role assignment is an admin-only operation.
- Covered by: server-side role checks on every protected endpoint.

---

#### Threat E-2: Permission Grant to Self

**Description:** A `VIEWER` user attempts to grant themselves `READ` or `EDIT` permission on a document they do not own.

**Impact:** Unauthorized document access.

**Mitigations Implemented:**
- The permission-granting endpoint verifies that the requesting user is the document owner or an admin before creating any `document_permissions` record.
- A user cannot grant permissions on a document they do not own, regardless of what data they submit.
- Admin content isolation policy additionally prevents admins from granting themselves content-level access without it being reflected in permission records (see Admin Content Isolation Policy section).
- Covered by: admin policies and server-side authorization checks.

---

#### Threat E-3: Horizontal Privilege Escalation (Accessing Another User's Actions)

**Description:** A user attempts to view, modify, or delete another user's documents, permissions, or audit records by manipulating IDs in URLs.

**Impact:** Unauthorized access to another user's data.

**Mitigations Implemented:**
- All resource-level endpoints perform ownership checks before allowing any action.
- `evaluate_document_access()` is the authoritative gate for all document-related resource access.
- Audit log access is restricted: regular users see only their own logs; admins see all logs.

---

## OWASP Top 10 Coverage

The following table maps TrustVault's security controls to the OWASP Top 10 (2021).

| # | OWASP Category | Addressed? | How TrustVault Addresses It |
|---|---|---|---|
| A01 | **Broken Access Control** | ✅ Yes | `evaluate_document_access()` enforces per-document authorization. IDOR is blocked (test: `test_unauthorized_user_idor_blocked`). Role-based route protection via `@admin_required`. |
| A02 | **Cryptographic Failures** | ✅ Yes | Passwords hashed with bcrypt. HTTPS enforced in production. Session cookies are `HttpOnly` and `Secure`. Sensitive config stored in environment variables, not code. |
| A03 | **Injection** | ✅ Yes | SQLAlchemy ORM is used exclusively — no raw SQL string construction. Filenames are sanitized. Null byte injection is rejected (test: `test_null_byte_injection_rejected`). |
| A04 | **Insecure Design** | ✅ Partial | Hash-chain audit trail provides tamper evidence. Admin content isolation ensures platform operators cannot silently read user data. Rate limiting is not yet implemented (known gap). |
| A05 | **Security Misconfiguration** | ✅ Yes | `DEBUG=False` in production. Secret key loaded from environment variable. `.env` excluded from version control. Separate `config.py` for dev/prod settings. |
| A06 | **Vulnerable and Outdated Components** | ⚠️ Ongoing | `requirements.txt` pins dependency versions. Regular updates are the operator's responsibility. No automated dependency scanning (future: Dependabot or pip-audit). |
| A07 | **Identification and Authentication Failures** | ✅ Yes | Flask-Login manages sessions. `"strong"` session protection is enabled. Passwords validated against bcrypt hash. Session cookie security flags set. |
| A08 | **Software and Data Integrity Failures** | ✅ Yes | Audit log hash chain detects post-write tampering (test: `test_audit_trail_hash_chain_integrity`). UUID-based storage filenames prevent path-based tampering. |
| A09 | **Security Logging and Monitoring Failures** | ✅ Yes | Every sensitive action is audit-logged with actor, document, IP, timestamp, and status. Tamper detection via hash chain. |
| A10 | **Server-Side Request Forgery (SSRF)** | ✅ N/A | TrustVault does not make outbound HTTP requests based on user input. SSRF surface does not apply in the current architecture. |

---

## Attack Paths (Detailed)

The following section walks through eight concrete attack paths, describing what the attacker attempts, how the server responds, and which automated test covers the scenario.

---

### 1. Cross-User Document Read (IDOR)

**What the attacker does:**

An authenticated user (e.g., `alice`, role: `VIEWER`) discovers that a document belonging to `bob` has ID `42`. Alice navigates directly to `/documents/42/download` (or submits a crafted request) hoping to receive `bob`'s file without holding any explicit permission on it.

**What the server does:**

1. Flask-Login confirms Alice is authenticated; her session is valid.
2. The route handler looks up document `42` in the database — it exists and is owned by `bob`.
3. `evaluate_document_access()` is called with `current_user=alice` and `document=document_42`.
4. The function checks: Is Alice the owner? No (`alice.id != bob.id`). Does Alice have a `document_permissions` record for document `42`? No.
5. Access is denied. The function returns `False`.
6. The route handler returns HTTP 403 Forbidden.
7. The denial is written to `audit_logs` with `event_type=ACCESS_DENIED`, `actor_id=alice.id`, `document_id=42`, `status=DENIED`.

**Test coverage:** `test_unauthorized_user_idor_blocked`

---

### 2. Path Traversal in File Download

**What the attacker does:**

An authenticated user crafts a document download request attempting to read a file outside the `storage/` directory. For example, they manipulate the request to reference a `storage_filename` value of `../../instance/trustvault.db` or `../../etc/passwd`, hoping the application will open an arbitrary file.

**What the server does:**

1. The application receives the request with document ID `X`.
2. It queries the database for document `X`'s `storage_filename`. The `storage_filename` is always a UUID string (e.g., `3f4e2a1b-...`), not a user-controlled value. The attacker cannot inject a path traversal sequence through the normal document ID lookup.
3. If the attacker somehow provides a crafted filename in a different flow, the application calls `os.path.realpath()` on the constructed path and verifies the result starts with the absolute `storage/` directory path.
4. If the resolved path escapes `storage/`, the request is rejected with HTTP 400 / 403 before any file is opened.

**Test coverage:** `test_path_traversal_in_file_storage_resolver`

---

### 3. Null Byte Injection

**What the attacker does:**

An attacker uploads a file with a carefully crafted filename containing a null byte: e.g., `legitimate.pdf\x00malicious.sh`. The intent is to confuse filename parsing, bypass extension validation, or cause the file to be stored with a different extension than what the application expects.

**What the server does:**

1. The upload handler receives the `multipart/form-data` request with the crafted filename.
2. Before any processing, the application scans the filename for null bytes (`\x00`).
3. If a null byte is detected, the upload is immediately rejected with HTTP 400 Bad Request and an appropriate error message.
4. No file is written to disk. The event is logged.
5. The actual physical storage name is always a UUID regardless of the original filename, providing defense in depth even if the null byte check were bypassed.

**Test coverage:** `test_null_byte_injection_rejected`

---

### 4. Permission Grant to Self

**What the attacker does:**

A `VIEWER` user attempts to grant themselves `READ` or `EDIT` access to a document they do not own. They might do this by:

- Submitting a POST request to the permission-grant endpoint with their own `user_id` and a target `document_id` they do not own.
- Attempting to replay or forge a permission-grant request from the document owner.

**What the server does:**

1. The permission-grant endpoint is called.
2. CSRF token validation occurs first; a forged or replayed form without a valid token is rejected immediately.
3. Flask-Login confirms the requesting user is authenticated.
4. The handler looks up the document and checks: Is the requesting user the document owner? No.
5. Is the requesting user an admin? If no, the request is rejected with HTTP 403.
6. Even if the requesting user is an admin, admin content isolation policy applies — admins can grant permissions on behalf of the platform but this is logged and subject to audit.
7. The denial is recorded in the audit log.

**Policy coverage:** Admin content isolation policies; server-side ownership checks.

---

### 5. Audit Log Tampering

**What the attacker does:**

An attacker who has gained direct database access (e.g., via a compromised server or insider threat) attempts to modify or delete audit log records to erase evidence of their actions. They might UPDATE a row to change `actor_id`, `event_type`, or `status`, or DELETE rows entirely.

**What the server does (at verification time):**

1. An administrator or automated monitor runs `verify_audit_trail()` from `trustvault/services/audit.py`.
2. The function fetches all audit log records ordered by `id` (insertion order).
3. For each record, it recomputes the expected `record_hash` from `(event_type + actor_id + document_id + status + timestamp + previous_hash)` using SHA-256.
4. It compares the recomputed hash against the stored `record_hash`.
5. If any record has been modified, the recomputed hash will not match the stored hash, and the function raises an integrity violation error, identifying the first record at which the chain breaks.
6. If a record was deleted from the middle of the chain, the `previous_hash` link will be broken and the discrepancy will be detected on the next record.

**Test coverage:** `test_audit_trail_hash_chain_integrity`

---

### 6. CSRF on Permission Changes

**What the attacker does:**

A malicious website (or email) tricks an authenticated TrustVault user into visiting a page containing a hidden HTML form that auto-submits a POST request to TrustVault's permission-grant endpoint. The browser automatically includes the user's TrustVault session cookie, so the request arrives at the server as if it came from the victim.

**What the server does:**

1. The permission-grant endpoint receives the POST request.
2. Flask-WTF's CSRF middleware checks for the CSRF token in the request body (or `X-CSRFToken` header for AJAX requests).
3. The request from the malicious site does not include a valid CSRF token (it cannot obtain one due to Same-Origin Policy).
4. The CSRF check fails; Flask-WTF returns HTTP 400 Bad Request.
5. No permission change occurs. The session remains valid for legitimate use.

**Test coverage:** `test_csrf_protection_enforcement`

---

### 7. Brute-Force Login

**What the attacker does:**

An attacker uses an automated tool to submit thousands of login requests to `/auth/login` with a known username (or an enumerated set of usernames) and a dictionary or generated list of passwords.

**What the server (current implementation) does:**

1. Each login attempt triggers a bcrypt hash comparison. bcrypt is intentionally slow (~100ms per comparison on typical hardware), limiting an attacker to roughly 10 attempts per second per process without parallelism.
2. Flask-Login's `"strong"` session protection is active. If a session is established and then the user-agent or IP changes significantly, the session is invalidated.
3. All failed login attempts are recorded in the audit log with the actor's IP address, providing a record for post-incident review.
4. After a successful brute-force login, any document access is still controlled by `evaluate_document_access()` — the attacker only gains access to that user's owned documents and explicitly shared documents.

**Residual risk and future mitigation:** No real-time rate limiting or account lockout is currently implemented. Flask-Limiter (with a Redis backend) is the planned mitigation. This remains a **known limitation**.

---

### 8. Privilege Escalation via Role Manipulation

**What the attacker does:**

An attacker with a `VIEWER` account intercepts or crafts an HTTP request and adds a `role=ADMIN` parameter to a profile update, registration, or login request, hoping the server will trust the client-provided role value and elevate their privileges.

**What the server does:**

1. Role assignment is never read from user-submitted form data or query parameters during authentication or profile updates.
2. The `role` field on the `User` model can only be changed through an explicit admin action — specifically, an endpoint that is itself protected by `@admin_required`.
3. The `@admin_required` decorator checks `current_user.role == Role.ADMIN` against the value stored in the database (loaded fresh from the session-backed user loader), not from any client-provided value.
4. Any crafted `role=ADMIN` parameter in a form body is silently ignored by the application; it is never passed to the ORM for the user's record.

**Policy coverage:** Server-side role checks; `@admin_required` decorator.

---

## Admin Content Isolation Policy

### Policy Statement

Administrators have full platform visibility — they can see all users, all document metadata (filenames, sizes, upload dates, categories), all permission records, and the complete audit trail. **However, admins CANNOT read the actual file contents of any document unless the document owner explicitly grants them `READ` or `EDIT` permission.**

This distinction is critical: knowing that a document named `Q3_financials.xlsx` exists is very different from being able to open and read that file. TrustVault enforces this separation at the access control layer.

### Enforcement Mechanism

This policy is enforced in `evaluate_document_access()` located in [`trustvault/services/access_control.py`](file:///c:/Users/moham/Downloads/TrustVault/trustvault/services/access_control.py).

The function applies the following logic for every document content access (download, preview, or inline view):

```
function evaluate_document_access(user, document):
    if user is the document owner:
        return ALLOW

    if user has a document_permissions record for this document
    with level READ or EDIT:
        return ALLOW

    # Even if user.role == ADMIN:
    return DENY
```

The `ADMIN` role is explicitly **not** a bypass condition in this function. Admins receive the same `DENY` response as any other non-owner user without an explicit permission.

### Rationale

This design reflects a principle of least privilege and a zero-trust approach to internal actors. It prevents scenarios such as:

- A platform administrator reading users' confidential legal or medical documents.
- A compromised admin account being used to mass-exfiltrate document contents.
- An insider threat exploiting administrative access to access documents without creating a visible paper trail.

Because every access attempt (successful or denied) is recorded in the audit log, any attempt by an admin to access document contents — even if they subsequently obtain a permission grant — is fully traceable.

---

## Known Limitations

The following security gaps are acknowledged and planned for future remediation. They do not represent design flaws but rather scope decisions for the current development phase.

| Limitation | Risk Level | Planned Mitigation |
|---|---|---|
| **No rate limiting on login endpoint** | Medium | Flask-Limiter with Redis backend; exponential backoff on repeated failures |
| **No multi-factor authentication (MFA)** | Medium | TOTP support via `pyotp`; email-based OTP as a fallback |
| **Ephemeral storage on Render free tier** | High (operational) | Use Render Persistent Disk add-on or migrate file storage to AWS S3 / Cloudflare R2 |
| **Session cookie not encrypted at rest** | Low | Standard for session cookies; Flask's signed cookie provides tamper detection but not confidentiality |
| **No automated dependency vulnerability scanning** | Medium | Integrate `pip-audit` or GitHub Dependabot into CI pipeline |
| **No per-user storage quota** | Low | Implement quota tracking in the database; enforce at upload time |
| **No Content Security Policy (CSP) headers** | Medium | Add Flask-Talisman with a strict CSP to mitigate XSS escalation |
| **Audit log not exported to external SIEM** | Medium | Stream audit events to an external logging service (e.g., Datadog, Splunk, or a self-hosted ELK stack) |

---

*This threat model should be reviewed whenever significant new features are added to TrustVault, and at minimum on a quarterly basis.*
