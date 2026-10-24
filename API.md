# TrustVault — API Reference

> **Version:** 1.0.0  
> **Base URL:** `https://<your-domain>` (e.g. `https://trustvault.onrender.com`)  
> **Protocol:** HTTPS only in production  
> **Content-Type:** `application/x-www-form-urlencoded` for form submissions; `application/json` for the health endpoint

---

## Table of Contents

1. [Authentication Model](#authentication-model)
2. [CSRF Protection](#csrf-protection)
3. [Role & Permission System](#role--permission-system)
4. [Security Headers](#security-headers)
5. [Rate Limiting](#rate-limiting)
6. [Error Responses](#error-responses)
7. [Endpoints — Auth Blueprint (`/auth`)](#endpoints--auth-blueprint-auth)
8. [Endpoints — Documents Blueprint (`/documents`)](#endpoints--documents-blueprint-documents)
9. [Endpoints — Admin Blueprint (`/admin`)](#endpoints--admin-blueprint-admin)
10. [Health Check](#health-check)

---

## Authentication Model

TrustVault uses **server-side session authentication** managed by [Flask-Login](https://flask-login.readthedocs.io/).

| Mechanism | Detail |
|---|---|
| Session storage | Signed cookie (`SECRET_KEY`-backed Flask session) |
| Login | `POST /auth/login` sets the `_user_id` in session via `login_user()` |
| Logout | `POST /auth/logout` calls `logout_user()` and clears session |
| `@login_required` | Redirects unauthenticated requests to `GET /auth/login` |
| Remember-me | Not implemented (session expires on browser close) |
| Password hashing | Werkzeug's secure PBKDF2/scrypt implementation (`generate_password_hash`) |

> [!IMPORTANT]
> All state-changing endpoints (`POST`, `DELETE`) require a valid CSRF token in addition to an active session. Requests missing a valid token are rejected with HTTP 400.

---

## CSRF Protection

TrustVault uses **Flask-WTF** to generate and validate CSRF tokens.

| Property | Detail |
|---|---|
| Token delivery | Rendered in every HTML form as a hidden `<input name="csrf_token">` |
| Validation | Automatic on all `POST` requests handled by WTForms |
| Token lifetime | Tied to the Flask session (rotated on login/logout) |
| Failure response | HTTP 400 Bad Request with error message |
| Test mode | `WTF_CSRF_ENABLED = False` in the test configuration |

---

## Role & Permission System

### Platform Roles (assigned per user)

| Role | Capabilities |
|---|---|
| `ADMIN` | Full platform access: manage users, view all audit logs, access admin dashboard |
| `OWNER` | Can upload documents, grant/revoke permissions on their own documents |
| `VIEWER` | Default role for new registrations. Read access to documents shared with them |

### Document-Level Permissions (assigned per document per user)

| Level | Capabilities |
|---|---|
| `READ` | View metadata, download file |
| `EDIT` | View metadata, download file, edit metadata |

Ownership always implies full access (READ + EDIT + grant/revoke). Admins can view metadata for all documents but **cannot download** document files unless explicitly granted READ or EDIT permission (content isolation by design).

---

## Security Headers

The following HTTP response headers are set on all responses:

| Header | Value | Purpose |
|---|---|---|
| `X-Content-Type-Options` | `nosniff` | Prevents MIME-type sniffing |
| `X-Frame-Options` | `DENY` | Prevents clickjacking via iframes |
| `X-XSS-Protection` | `1; mode=block` | Legacy XSS filter for older browsers |
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'` | Restricts resource origins |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Controls referrer header leakage |

Headers are injected via a Flask `@app.after_request` hook so they apply uniformly to every route.

---

## Rate Limiting

> [!NOTE]
> Rate limiting is **not currently implemented** in TrustVault v1.0. This is a planned future enhancement.

**Recommended future implementation:**

- Use [Flask-Limiter](https://flask-limiter.readthedocs.io/) backed by Redis.
- Suggested limits:
  - `POST /auth/login` — 10 requests / minute per IP
  - `POST /auth/register` — 5 requests / hour per IP
  - `POST /documents/upload` — 20 requests / hour per user
  - All other authenticated endpoints — 300 requests / minute per user

---

## Error Responses

All error responses return standard HTML pages (Flask error handlers) except the `/health` endpoint which returns JSON.

| HTTP Status | Meaning | Common Causes |
|---|---|---|
| `400 Bad Request` | Invalid or missing input | Missing CSRF token, form validation failure, invalid file type |
| `401 Unauthorized` | Not logged in | Accessing a `@login_required` route without a session (redirects to `/auth/login`) |
| `403 Forbidden` | Insufficient role or permission | VIEWER trying to upload; user without READ trying to download |
| `404 Not Found` | Resource does not exist | Invalid document `<id>`, unknown user `<id>` |
| `500 Internal Server Error` | Unhandled server-side exception | Database error, disk I/O failure |
| `503 Service Unavailable` | Health check failure | Database unreachable |

---

## Endpoints — Auth Blueprint (`/auth`)

### 1. GET /auth/login

| Property | Value |
|---|---|
| **Method** | `GET` |
| **Path** | `/auth/login` |
| **Auth Required** | No |
| **Roles** | Public |
| **Request Params** | None |
| **Success Response** | `200 OK` — HTML login form |
| **Error Responses** | None |
| **Notes** | If the user is already authenticated, they are redirected to `/documents/dashboard`. |

---

### 2. POST /auth/login

| Property | Value |
|---|---|
| **Method** | `POST` |
| **Path** | `/auth/login` |
| **Auth Required** | No |
| **Roles** | Public |
| **Request Body** | `username`, `password`, `csrf_token` |
| **Success Response** | `302 Redirect` → `/documents/dashboard` |
| **Error Responses** | `400` — CSRF failure; `200` — re-renders form with flash error on bad credentials |
| **Notes** | Logs `LOGIN_SUCCESS` or `LOGIN_FAILURE` to the audit trail. Inactive accounts are rejected before password check. Failed attempts include a generic error message to prevent username enumeration. |

**Audit Events:**

| Event | When |
|---|---|
| `LOGIN_SUCCESS` | Credentials valid, account active |
| `LOGIN_FAILURE` | Wrong password, unknown user, or inactive account |

---

### 3. GET /auth/register

| Property | Value |
|---|---|
| **Method** | `GET` |
| **Path** | `/auth/register` |
| **Auth Required** | No |
| **Roles** | Public |
| **Request Params** | None |
| **Success Response** | `200 OK` — HTML registration form |
| **Error Responses** | None |
| **Notes** | Redirects authenticated users to dashboard. |

---

### 4. POST /auth/register

| Property | Value |
|---|---|
| **Method** | `POST` |
| **Path** | `/auth/register` |
| **Auth Required** | No |
| **Roles** | Public |
| **Request Body** | `username`, `email`, `password`, `confirm_password`, `csrf_token` |
| **Success Response** | `302 Redirect` → `/auth/login` with success flash |
| **Error Responses** | `400` — CSRF; `200` — re-render with validation errors (duplicate username/email, password mismatch, weak password) |
| **Notes** | New accounts are assigned the `VIEWER` role and set to active by default. Passwords are hashed with bcrypt before storage. Email uniqueness is enforced at DB level. |

**Validation Rules:**

| Field | Rule |
|---|---|
| `username` | 3–64 characters, alphanumeric + underscore, unique |
| `email` | Valid RFC format, unique, `check_deliverability=False` |
| `password` | Minimum 8 characters |
| `confirm_password` | Must match `password` |

---

### 5. POST /auth/logout

| Property | Value |
|---|---|
| **Method** | `POST` |
| **Path** | `/auth/logout` |
| **Auth Required** | Yes |
| **Roles** | Any authenticated user |
| **Request Body** | `csrf_token` |
| **Success Response** | `302 Redirect` → `/auth/login` |
| **Error Responses** | `400` — CSRF failure; `401` — not logged in |
| **Notes** | Uses `POST` (not `GET`) to prevent CSRF-triggered logout via image tags or links. Clears the Flask-Login session fully. |

---

### 6. GET /auth/settings

| Property | Value |
|---|---|
| **Method** | `GET` |
| **Path** | `/auth/settings` |
| **Auth Required** | Yes |
| **Roles** | Any authenticated user |
| **Request Params** | None |
| **Success Response** | `200 OK` — HTML settings page with change-password form |
| **Error Responses** | `401` — not logged in |
| **Notes** | Displays the current user's username and email (read-only). Only password change is supported in v1. |

---

### 7. POST /auth/settings

| Property | Value |
|---|---|
| **Method** | `POST` |
| **Path** | `/auth/settings` |
| **Auth Required** | Yes |
| **Roles** | Any authenticated user |
| **Request Body** | `current_password`, `new_password`, `confirm_password`, `csrf_token` |
| **Success Response** | `302 Redirect` → `/auth/settings` with success flash |
| **Error Responses** | `400` — CSRF or validation failure; `200` — re-render with error if `current_password` is wrong |
| **Notes** | Logs `PASSWORD_CHANGE` to audit trail. The current password is verified with bcrypt before updating. The new password must satisfy the same strength rules as registration. |

**Audit Events:**

| Event | When |
|---|---|
| `PASSWORD_CHANGE` | Password successfully updated |

---

## Endpoints — Documents Blueprint (`/documents`)

### 8. GET /documents/dashboard

| Property | Value |
|---|---|
| **Method** | `GET` |
| **Path** | `/documents/dashboard` |
| **Auth Required** | Yes |
| **Roles** | Any authenticated user |
| **Request Params** | None |
| **Success Response** | `200 OK` — HTML dashboard with KPI cards and recent activity |
| **Error Responses** | `401` — not logged in |
| **Notes** | KPI values (`total_docs`, `shared_docs`, `recent_activity_count`, `pending_events`) are computed from live DB queries scoped to the current user. Recent audit stream shows the last 10 events. |

**Dashboard KPIs:**

| KPI | Source |
|---|---|
| `total_docs` | Documents owned by or shared with current user |
| `shared_docs` | Documents with at least one non-owner permission grant |
| `recent_activity_count` | Audit events in last 7 days for this user |
| `pending_events` | Audit events with status `FAILURE` in last 24 hours |

---

### 9. GET /documents/

| Property | Value |
|---|---|
| **Method** | `GET` |
| **Path** | `/documents/` |
| **Auth Required** | Yes |
| **Roles** | Any authenticated user |
| **Query Params** | `tab` (all/my/shared), `category`, `sort` (name/date/size/category), `q` (search query) |
| **Success Response** | `200 OK` — HTML paginated document table |
| **Error Responses** | `401` — not logged in |
| **Notes** | `tab=all` shows all accessible documents; `tab=my` filters to owned documents; `tab=shared` filters to documents shared with the user. Search (`q`) applies to document name and category. |

**Query Parameters:**

| Param | Type | Default | Description |
|---|---|---|---|
| `tab` | string | `all` | Filter set: `all`, `my`, `shared` |
| `category` | string | — | Filter by exact category name |
| `sort` | string | `date` | Sort field: `name`, `date`, `size`, `category` |
| `q` | string | — | Full-text search on document name |

---

### 10. GET /documents/upload

| Property | Value |
|---|---|
| **Method** | `GET` |
| **Path** | `/documents/upload` |
| **Auth Required** | Yes |
| **Roles** | `OWNER`, `ADMIN` |
| **Request Params** | None |
| **Success Response** | `200 OK` — HTML upload form with drag-and-drop zone |
| **Error Responses** | `401` — not logged in; `403` — VIEWER role |
| **Notes** | The drag-and-drop zone is implemented in vanilla JavaScript. Supported file types are displayed to the user. |

---

### 11. POST /documents/upload

| Property | Value |
|---|---|
| **Method** | `POST` |
| **Path** | `/documents/upload` |
| **Auth Required** | Yes |
| **Roles** | `OWNER`, `ADMIN` |
| **Request Body** | `file` (multipart), `category` (string), `csrf_token` |
| **Success Response** | `302 Redirect` → `/documents/<new_id>/view` |
| **Error Responses** | `400` — invalid MIME type, CSRF failure; `403` — VIEWER role; `413` — file too large |
| **Notes** | File is stored in the private uploads directory with a UUID-based filename (not the original name) to prevent IDOR. Original filename is preserved in the DB record. MIME type is validated against a server-side whitelist — client-provided `Content-Type` is not trusted. Logs `DOCUMENT_UPLOAD`. |

**Allowed MIME Types:**

| Extension | MIME Type |
|---|---|
| `.pdf` | `application/pdf` |
| `.docx` | `application/vnd.openxmlformats-officedocument.wordprocessingml.document` |
| `.xlsx` | `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` |
| `.png` | `image/png` |
| `.jpg` / `.jpeg` | `image/jpeg` |
| `.txt` | `text/plain` |

**Audit Events:**

| Event | When |
|---|---|
| `DOCUMENT_UPLOAD` | File successfully stored and DB record created |

---

### 12. GET /documents/\<id\>/view

| Property | Value |
|---|---|
| **Method** | `GET` |
| **Path** | `/documents/<id>/view` |
| **Auth Required** | Yes |
| **Roles** | READ or EDIT permission, owner, or ADMIN |
| **Request Params** | None |
| **Success Response** | `200 OK` — HTML metadata page; includes permission list for owners/admins |
| **Error Responses** | `401` — not logged in; `403` — no permission; `404` — document not found |
| **Notes** | Logs `ACCESS_GRANTED` or `ACCESS_DENIED`. Admins see metadata but do **not** see the download button unless they hold an explicit READ/EDIT grant (content isolation). Audit trail for the document is shown on this page. |

**Audit Events:**

| Event | When |
|---|---|
| `ACCESS_GRANTED` | User has permission and metadata is served |
| `ACCESS_DENIED` | User is authenticated but lacks permission |

---

### 13. GET /documents/\<id\>/download

| Property | Value |
|---|---|
| **Method** | `GET` |
| **Path** | `/documents/<id>/download` |
| **Auth Required** | Yes |
| **Roles** | READ or EDIT permission, or owner |
| **Request Params** | None |
| **Success Response** | `200 OK` — Binary file stream as `attachment` with original filename |
| **Error Responses** | `401` — not logged in; `403` — no permission (includes ADMIN without explicit grant); `404` — document or file not found |
| **Notes** | File is streamed using `send_file()` from the private uploads directory. The URL is **not** a direct static file path; the server authorises each request. Logs `DOCUMENT_DOWNLOAD`. |

**Audit Events:**

| Event | When |
|---|---|
| `DOCUMENT_DOWNLOAD` | File successfully streamed to user |

---

### 14. GET /documents/\<id\>/edit

| Property | Value |
|---|---|
| **Method** | `GET` |
| **Path** | `/documents/<id>/edit` |
| **Auth Required** | Yes |
| **Roles** | EDIT permission or owner |
| **Request Params** | None |
| **Success Response** | `200 OK` — HTML edit form pre-populated with current metadata |
| **Error Responses** | `401` — not logged in; `403` — READ-only or no permission; `404` — not found |
| **Notes** | Editable fields are `filename` (display name) and `category`. File content cannot be changed via edit — a new upload is required. |

---

### 15. POST /documents/\<id\>/edit

| Property | Value |
|---|---|
| **Method** | `POST` |
| **Path** | `/documents/<id>/edit` |
| **Auth Required** | Yes |
| **Roles** | EDIT permission or owner |
| **Request Body** | `filename`, `category`, `csrf_token` |
| **Success Response** | `302 Redirect` → `/documents/<id>/view` with success flash |
| **Error Responses** | `400` — CSRF or validation failure; `403` — insufficient permission; `404` — not found |
| **Notes** | Logs `DOCUMENT_EDIT`. The stored UUID filename on disk is **not** changed; only the display name in the DB is updated. |

**Audit Events:**

| Event | When |
|---|---|
| `DOCUMENT_EDIT` | Metadata successfully updated |

---

### 16. POST /documents/\<id\>/delete

| Property | Value |
|---|---|
| **Method** | `POST` |
| **Path** | `/documents/<id>/delete` |
| **Auth Required** | Yes |
| **Roles** | Owner or `ADMIN` |
| **Request Body** | `csrf_token` |
| **Success Response** | `302 Redirect` → `/documents/` with success flash |
| **Error Responses** | `400` — CSRF failure; `403` — not owner or admin; `404` — not found |
| **Notes** | Deletes both the DB record and the file from disk atomically (DB first, then disk). All associated permission grants are cascade-deleted. Logs `DOCUMENT_DELETE`. This action is **irreversible**. |

**Audit Events:**

| Event | When |
|---|---|
| `DOCUMENT_DELETE` | Document record and file successfully removed |

---

### 17. GET /documents/\<id\>/permissions

| Property | Value |
|---|---|
| **Method** | `GET` |
| **Path** | `/documents/<id>/permissions` |
| **Auth Required** | Yes |
| **Roles** | Owner or `ADMIN` |
| **Request Params** | None |
| **Success Response** | `200 OK` — HTML permission management page with current grant list and grant form |
| **Error Responses** | `401` — not logged in; `403` — not owner or admin; `404` — not found |
| **Notes** | Lists all users who have been granted access (username, level, granted date). Shows the grant form to add new permissions. |

---

### 18. POST /documents/\<id\>/grant

| Property | Value |
|---|---|
| **Method** | `POST` |
| **Path** | `/documents/<id>/grant` |
| **Auth Required** | Yes |
| **Roles** | Owner or `ADMIN` |
| **Request Body** | `username`, `level` (READ or EDIT), `csrf_token` |
| **Success Response** | `302 Redirect` → `/documents/<id>/permissions` with success flash |
| **Error Responses** | `400` — CSRF failure, unknown username, invalid level; `403` — not owner or admin; `404` — document not found |
| **Notes** | Logs `PERMISSION_GRANTED`. If the user already has a grant for this document, the existing grant is updated to the new level (upsert). Owners cannot grant permissions to themselves. |

**Audit Events:**

| Event | When |
|---|---|
| `PERMISSION_GRANTED` | Grant successfully created or updated |

---

### 19. POST /documents/\<id\>/revoke/\<user_id\>

| Property | Value |
|---|---|
| **Method** | `POST` |
| **Path** | `/documents/<id>/revoke/<user_id>` |
| **Auth Required** | Yes |
| **Roles** | Owner or `ADMIN` |
| **Request Body** | `csrf_token` |
| **Success Response** | `302 Redirect` → `/documents/<id>/permissions` with success flash |
| **Error Responses** | `400` — CSRF failure; `403` — not owner or admin; `404` — document or grant not found |
| **Notes** | Logs `PERMISSION_REVOKED`. Revocation takes effect immediately — on the target user's **next** request, the server will deny access. Existing in-flight requests are not interrupted. |

**Audit Events:**

| Event | When |
|---|---|
| `PERMISSION_REVOKED` | Grant successfully removed |

---

### 20. GET /documents/permissions

| Property | Value |
|---|---|
| **Method** | `GET` |
| **Path** | `/documents/permissions` |
| **Auth Required** | Yes |
| **Roles** | Any authenticated user |
| **Request Params** | None |
| **Success Response** | `200 OK` — HTML permissions center page |
| **Error Responses** | `401` — not logged in |
| **Notes** | Shows two sections: (1) permissions the user has **granted** to others (as owner), (2) permissions the user has **received** from others. Provides quick links to revoke individual grants. |

---

### 21. GET /documents/activity

| Property | Value |
|---|---|
| **Method** | `GET` |
| **Path** | `/documents/activity` |
| **Auth Required** | Yes |
| **Roles** | Any authenticated user (ADMIN sees all events) |
| **Request Params** | None |
| **Success Response** | `200 OK` — HTML activity log table |
| **Error Responses** | `401` — not logged in |
| **Notes** | Non-admin users see only events where they are the actor or the document is owned by/shared with them. ADMINs see the full platform audit trail (same as `/admin/audit-logs` but via the user UI). Events are sorted descending by timestamp. |

---

## Endpoints — Admin Blueprint (`/admin`)

> [!IMPORTANT]
> All admin endpoints require the `ADMIN` platform role. Requests from `OWNER` or `VIEWER` accounts are rejected with HTTP 403. Admin routes also enforce session authentication — unauthenticated requests redirect to `/auth/login`.

---

### 22. GET /admin/

| Property | Value |
|---|---|
| **Method** | `GET` |
| **Path** | `/admin/` |
| **Auth Required** | Yes |
| **Roles** | `ADMIN` |
| **Request Params** | None |
| **Success Response** | `200 OK` — HTML admin dashboard |
| **Error Responses** | `401` — not logged in; `403` — non-admin |
| **Notes** | Shows platform-wide stats: total registered users, total documents, recent audit events (last 20), and permission change events. All values are live DB queries — no caching. |

**Dashboard Stats:**

| Stat | Source |
|---|---|
| Total users | `SELECT COUNT(*) FROM user` |
| Total documents | `SELECT COUNT(*) FROM document` |
| Recent events | Last 20 rows from `audit_log` |
| Permission changes | `PERMISSION_GRANTED` + `PERMISSION_REVOKED` events last 24h |

---

### 23. GET /admin/users

| Property | Value |
|---|---|
| **Method** | `GET` |
| **Path** | `/admin/users` |
| **Auth Required** | Yes |
| **Roles** | `ADMIN` |
| **Request Params** | None |
| **Success Response** | `200 OK` — HTML user management table |
| **Error Responses** | `401` — not logged in; `403` — non-admin |
| **Notes** | Lists every user with: username, email, role, active status, document count, registration date. Each row has action buttons to change role or toggle status. |

---

### 24. POST /admin/users/\<id\>/role

| Property | Value |
|---|---|
| **Method** | `POST` |
| **Path** | `/admin/users/<id>/role` |
| **Auth Required** | Yes |
| **Roles** | `ADMIN` |
| **Request Body** | `role` (ADMIN / OWNER / VIEWER), `csrf_token` |
| **Success Response** | `302 Redirect` → `/admin/users` with success flash |
| **Error Responses** | `400` — CSRF failure, invalid role value; `403` — non-admin; `404` — user not found |
| **Notes** | Logs `USER_ROLE_CHANGE`. Admins cannot demote their own account to prevent lockout. Role changes take effect on the target user's next request. |

**Audit Events:**

| Event | When |
|---|---|
| `USER_ROLE_CHANGE` | Role successfully updated |

---

### 25. POST /admin/users/\<id\>/toggle-status

| Property | Value |
|---|---|
| **Method** | `POST` |
| **Path** | `/admin/users/<id>/toggle-status` |
| **Auth Required** | Yes |
| **Roles** | `ADMIN` |
| **Request Body** | `csrf_token` |
| **Success Response** | `302 Redirect` → `/admin/users` with status flash |
| **Error Responses** | `400` — CSRF failure; `403` — non-admin; `404` — user not found |
| **Notes** | Toggles the `is_active` flag. Deactivated users cannot log in (rejected at login before password check). Deactivating an admin's own account is blocked. Logs `USER_STATUS_CHANGE`. |

**Audit Events:**

| Event | When |
|---|---|
| `USER_STATUS_CHANGE` | Active flag toggled |

---

### 26. GET /admin/audit-logs

| Property | Value |
|---|---|
| **Method** | `GET` |
| **Path** | `/admin/audit-logs` |
| **Auth Required** | Yes |
| **Roles** | `ADMIN` |
| **Request Params** | None |
| **Success Response** | `200 OK` — HTML full audit log table |
| **Error Responses** | `401` — not logged in; `403` — non-admin |
| **Notes** | Displays all audit events across the platform. Each row shows: actor username, event type, resource (document name or user), status (SUCCESS/FAILURE), timestamp, and hash verification status. Hash chain integrity is visually indicated (✓ or ✗). |

**Audit Log Columns:**

| Column | Description |
|---|---|
| Actor | Username of the user who triggered the event |
| Event | Event type constant (e.g. `DOCUMENT_UPLOAD`, `LOGIN_FAILURE`) |
| Resource | Human-readable target of the event |
| Status | `SUCCESS` or `FAILURE` |
| Timestamp | UTC datetime formatted as `YYYY-MM-DD HH:MM:SS` |
| Hash | SHA-256 hash chain node (truncated for display) |
| Chain OK | ✓ if this entry's hash is consistent with the previous entry |

---

### 27. POST /admin/audit-logs/verify

| Property | Value |
|---|---|
| **Method** | `POST` |
| **Path** | `/admin/audit-logs/verify` |
| **Auth Required** | Yes |
| **Roles** | `ADMIN` |
| **Request Body** | `csrf_token` |
| **Success Response** | `302 Redirect` → `/admin/audit-logs` with flash: "Audit chain verified ✓" or "Chain integrity failure detected ✗" |
| **Error Responses** | `400` — CSRF failure; `403` — non-admin |
| **Notes** | Re-runs `verify_audit_trail()` which walks every entry in insertion order, re-computes `SHA-256(prev_hash + event_data)`, and compares to stored hash. Any mismatch indicates tampering or corruption. This is a potentially slow operation on large audit tables. |

**Hash Chain Algorithm:**

The audit entry hash is computed as:

```
entry_hash = SHA-256(
    prev_entry_hash +
    actor_id +
    event_type +
    resource_id +
    status +
    timestamp.strftime("%Y-%m-%d %H:%M:%S")
)
```

The first entry uses a sentinel string as `prev_entry_hash` (e.g. `"GENESIS"`).

---

## Health Check

### 28. GET /health

| Property | Value |
|---|---|
| **Method** | `GET` |
| **Path** | `/health` |
| **Auth Required** | No |
| **Roles** | Public |
| **Request Params** | None |
| **Success Response** | `200 OK` — `{"status": "ok", "db": true}` |
| **Error Responses** | `503 Service Unavailable` — `{"status": "degraded", "db": false}` |
| **Notes** | Used by Render.com health checks and uptime monitors. Performs a lightweight `SELECT 1` against the database to confirm connectivity. Returns `503` if the DB probe fails. |

**Response Schema:**

```json
{
  "status": "ok",
  "db": true
}
```

| Field | Type | Values |
|---|---|---|
| `status` | string | `"ok"` or `"degraded"` |
| `db` | boolean | `true` if DB query succeeded, `false` otherwise |

---

## Complete Endpoint Summary

| # | Method | Path | Auth | Min Role |
|---|---|---|---|---|
| 1 | GET | `/auth/login` | No | Public |
| 2 | POST | `/auth/login` | No | Public |
| 3 | GET | `/auth/register` | No | Public |
| 4 | POST | `/auth/register` | No | Public |
| 5 | POST | `/auth/logout` | Yes | Any |
| 6 | GET | `/auth/settings` | Yes | Any |
| 7 | POST | `/auth/settings` | Yes | Any |
| 8 | GET | `/documents/dashboard` | Yes | Any |
| 9 | GET | `/documents/` | Yes | Any |
| 10 | GET | `/documents/upload` | Yes | OWNER / ADMIN |
| 11 | POST | `/documents/upload` | Yes | OWNER / ADMIN |
| 12 | GET | `/documents/<id>/view` | Yes | READ / EDIT / Owner / ADMIN |
| 13 | GET | `/documents/<id>/download` | Yes | READ / EDIT / Owner |
| 14 | GET | `/documents/<id>/edit` | Yes | EDIT / Owner |
| 15 | POST | `/documents/<id>/edit` | Yes | EDIT / Owner |
| 16 | POST | `/documents/<id>/delete` | Yes | Owner / ADMIN |
| 17 | GET | `/documents/<id>/permissions` | Yes | Owner / ADMIN |
| 18 | POST | `/documents/<id>/grant` | Yes | Owner / ADMIN |
| 19 | POST | `/documents/<id>/revoke/<user_id>` | Yes | Owner / ADMIN |
| 20 | GET | `/documents/permissions` | Yes | Any |
| 21 | GET | `/documents/activity` | Yes | Any (ADMIN sees all) |
| 22 | GET | `/admin/` | Yes | ADMIN |
| 23 | GET | `/admin/users` | Yes | ADMIN |
| 24 | POST | `/admin/users/<id>/role` | Yes | ADMIN |
| 25 | POST | `/admin/users/<id>/toggle-status` | Yes | ADMIN |
| 26 | GET | `/admin/audit-logs` | Yes | ADMIN |
| 27 | POST | `/admin/audit-logs/verify` | Yes | ADMIN |
| 28 | GET | `/health` | No | Public |

---

*API documentation generated for TrustVault v1.0.0 — 2026-10-23*
