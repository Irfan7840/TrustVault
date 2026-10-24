# TrustVault Demo Script

A structured five-minute walkthrough covering all three user roles and key security features. Run this after seeding demo data with `flask seed-demo`.

---

## Pre-Demo Setup

```bash
# Activate virtual environment
.venv\Scripts\activate          # Windows
source .venv/bin/activate       # Linux / macOS

# Apply migrations and seed demo data
flask db upgrade
flask seed-demo

# Start development server
flask run
```

Open **http://localhost:5000** in your browser.

---

## Demo Accounts

| Role    | Username | Password       | Purpose                              |
|---------|----------|----------------|--------------------------------------|
| Admin   | admin    | AdminVault2026! | Platform administration, audit logs  |
| Owner   | alice    | Demo@Alice1    | Upload, share, manage permissions    |
| Viewer  | bob      | Demo@Bob12     | Consume shared documents             |

---

## Step-by-Step Script

### Minute 1 — Registration and Login

1. Open `http://localhost:5000`. You are redirected to the login page.
2. Click **"Create an account"** and register a new account:
   - Username: `testuser`, Email: `test@example.com`, Password: `Test@Secure1`
   - Submit — you should see "Account created successfully."
3. Log in as **alice / Demo@Alice1**.
4. You land on the **Dashboard** — show the four KPI cards:
   - Total Documents (real count from DB)
   - Documents Shared (real count)
   - Recent Activity (last 24 h events)
   - Pending Events (unanswered DENIED events)
5. Point out the **sidebar navigation**: Dashboard, My Documents, Shared With Me, Upload, Permissions, Activity Logs, Settings.

---

### Minute 2 — Document Upload

1. Click **Upload** in the sidebar.
2. Drag and drop the provided `Q4_Financial_Report.pdf` (or any PDF) into the dropzone.
   - Observe the JS preview showing filename and size.
3. Set **Category** to Finance. Click **Upload Document**.
4. You are redirected to the **Document Detail** page showing:
   - Filename, category, upload date, file size, MIME type.
   - An audit entry: `DOCUMENT_UPLOAD — SUCCESS` by alice.
5. Try uploading a disallowed file type (e.g., `.exe`):
   - The server rejects it with: "File type not permitted."
   - An `UPLOAD_REJECTED` audit entry is created.

---

### Minute 3 — Permission Management

1. From the document detail page, click **Manage Permissions**.
2. Grant **bob** READ access:
   - Type username: `bob`, select Level: `READ`, click **Grant**.
   - A `PERMISSION_GRANTED` audit entry appears.
3. Open a new private/incognito window. Log in as **bob / Demo@Bob12**.
4. Navigate to **Shared With Me** — the Q4 report appears.
5. Click the document — bob can view metadata and click **Download** to download the file.
6. Bob cannot see the **Edit** or **Delete** buttons (server-side enforcement).
7. Back in alice's session, go to **Manage Permissions** and click **Revoke** for bob.
8. In bob's session, refresh the document page — immediately receives **403 Forbidden**.
   - **Key security point**: revocation is effective on the very next request, no cache.

---

### Minute 4 — Security Controls

1. **IDOR prevention** — In the browser address bar, change the document ID to one you don't own:
   - Navigate to `/documents/999/view` — receive 403 Forbidden.
   - The access-denied event appears in the audit log.
2. **Path traversal** — The file download endpoint uses UUID storage names; you cannot request `../../etc/passwd`.
3. **CSRF protection** — All forms include a hidden CSRF token. Attempting a cross-site POST fails with 400.
4. **Security headers** — Open browser DevTools → Network → click any response:
   - Observe: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy`.
5. **Audit trail** — Navigate to **Activity Logs**. All events are logged with actor, action, document, timestamp, and status badge (SUCCESS in green, DENIED in red).

---

### Minute 5 — Admin Dashboard

1. Open a new tab and log in as **admin / AdminVault2026!**.
2. Navigate to `/admin/` — the **Admin Dashboard** shows:
   - Platform totals: users, documents, permissions, recent audit events.
   - All values are real database counts.
3. Click **Users** — see alice, bob, testuser. Change testuser's role to OWNER. Change it back.
4. Click **Deactivate** on a non-admin user — they cannot log in while deactivated.
5. Navigate to **Admin → Audit Logs**:
   - Full audit trail visible: every upload, download, permission change, login.
   - Click **Verify Audit Chain** — the server re-computes SHA-256 hashes and confirms integrity.
6. **Admin content isolation** — As admin, navigate to a document detail page for alice's documents. Admin can see metadata (filename, category, permissions) but the **Download** button is absent unless alice has explicitly granted the admin permission.

---

## Key Security Points Summary

| Control | Demonstration |
|---------|--------------|
| Server-side authorization | Bob's DENIED access after revoke takes effect immediately |
| IDOR prevention | Direct URL manipulation returns 403, not another user's document |
| No public file URLs | Files served through authenticated `/download` endpoint only |
| Audit trail integrity | SHA-256 hash chain verified by admin; tamper detection works |
| CSRF protection | All state-changing forms include token; cross-site POST fails |
| Security headers | Visible in DevTools on every response |
| Admin isolation | Admin cannot download documents without explicit owner grant |

---

## Health Check

```
GET http://localhost:5000/health
→ {"status": "ok", "db": true}
```

---

## Troubleshooting

| Problem | Solution |
|---------|---------|
| `flask: command not found` | Activate the venv: `source .venv/bin/activate` |
| `No such table` error | Run `flask db upgrade` |
| Demo accounts not found | Run `flask seed-demo` |
| Port 5000 already in use | Use `flask run --port 5001` |
| Upload fails silently | Check `UPLOAD_FOLDER` is writable |
