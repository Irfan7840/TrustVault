# TrustVault — Production Deployment Guide

> **Target Platform:** Render.com (Preferred) or Railway.app  
> **Application Runtime:** Python 3.12 + Gunicorn WSGI Server  
> **Database:** Managed PostgreSQL 15+  
> **File Storage:** Private Persistent Volume (Disks)  

---

## 1. Architecture Overview in Production

```
 Internet (Clients)
         │
         ▼  HTTPS (Port 443 / TLS Termination)
   [Render / Railway Edge Router]
         │
         ▼  Reverse Proxy (Port $PORT)
   [Gunicorn WSGI: 2 Workers]
         │
         ├───▶ [TrustVault Flask Application]
         │          │
         │          ├───▶ PostgreSQL (DATABASE_URL over SSL)
         │          │
         │          └───▶ Persistent Disk (/storage/documents/ UUID files)
         │
         └───▶ Health Monitor (GET /health -> HTTP 200)
```

---

## 2. Production Environment Variables

Configure the following variables in the hosting provider dashboard:

| Variable Name | Required | Example / Format | Notes |
|---|---|---|---|
| `FLASK_ENV` | Yes | `production` | Enables production configuration class. |
| `SECRET_KEY` | Yes | `a6c1e948... (64 hex characters)` | Used to sign session cookies and CSRF tokens. |
| `DATABASE_URL` | Yes | `postgresql://user:pass@host:5432/trustvault` | Connection URI for PostgreSQL. Must use `postgresql://` (SQLAlchemy 2.0+ incompatible with legacy `postgres://`). |
| `UPLOAD_FOLDER` | Yes | `/var/data/trustvault/storage` or `/opt/render/project/src/storage/documents` | Absolute path mounted to persistent disk. |
| `ALLOWED_EXTENSIONS` | No | `pdf,docx,xlsx,png,jpg,jpeg,txt` | Defaults to safe whitelist if omitted. |
| `MAX_CONTENT_LENGTH` | No | `16777216` | 16 MB maximum upload payload limit. |

---

## 3. Deployment on Render.com (Recommended)

### Step 1: Push Code to GitHub / GitLab
Because `git` was not installed locally in the development sandbox, initialize git on your machine or upload the repository to GitHub:
```bash
git init
git add .
git commit -m "TrustVault production release"
git branch -M main
git remote add origin https://github.com/<your-username>/TrustVault.git
git push -u origin main
```

### Step 2: Create Managed PostgreSQL Database
1. In the [Render Dashboard](https://dashboard.render.com/), click **New +** → **PostgreSQL**.
2. **Name:** `trustvault-db`
3. **Database:** `trustvault`
4. **User:** `trustvault`
5. **Plan:** Free or Starter
6. Click **Create Database**. Copy the **Internal Database URL**.

### Step 3: Deploy Web Service via `render.yaml` (Blueprint)
The repository includes a ready-to-use `render.yaml` Blueprint:
1. In the Render Dashboard, click **New +** → **Blueprint**.
2. Connect your `TrustVault` GitHub repository.
3. Render automatically reads `render.yaml` and provisions:
   - Web Service `trustvault`
   - Database `trustvault-db`
4. Verify the build and start commands:
   - **Build Command:** `pip install -r requirements.txt && flask db upgrade`
   - **Start Command:** `gunicorn -w 2 -b 0.0.0.0:$PORT "trustvault:create_app('production')"`

### Step 4: Configure Persistent Disk for Private File Storage
> [!IMPORTANT]
> The Render free tier uses an ephemeral filesystem that clears uploaded files when instances restart. For persistent production document storage:
1. In your Web Service settings, navigate to **Disks**.
2. Click **Add Disk**:
   - **Name:** `trustvault-storage`
   - **Mount Path:** `/opt/render/project/src/storage/documents`
   - **Size:** 1 GB (or as required)
3. Save and redeploy.

### Step 5: Initialize Admin & Seed Demo Data
Open the **Shell** tab in your Render service dashboard:
```bash
# 1. Create your administrator account
flask create-admin admin admin@yourdomain.com StrongAdminPass2026!

# 2. (Optional) Seed demonstration users (alice & bob) and sample documents
flask seed-demo
```

---

## 4. Alternative Deployment: Railway.app

1. In [Railway.app](https://railway.app/), create a **New Project** → **Provision PostgreSQL**.
2. Click **New Service** → **GitHub Repo** → select `TrustVault`.
3. In **Settings** → **Deploy**, set:
   - **Start Command:** `gunicorn -w 2 -b 0.0.0.0:$PORT "trustvault:create_app('production')"`
4. In **Variables**, add:
   - `FLASK_ENV=production`
   - `DATABASE_URL=${{Postgres.DATABASE_URL}}`
   - `SECRET_KEY=<generate-random-secret>`
   - `UPLOAD_FOLDER=/app/storage/documents`
5. In **Volumes**, mount a persistent volume at `/app/storage/documents`.
6. Run migrations via Railway CLI or Deploy Command: `flask db upgrade`.

---

## 5. Health Monitoring & Verification

Once deployed, probe the health check endpoint:

```bash
curl -I https://<your-deployed-domain>/health
```

Expected response:
```http
HTTP/1.1 200 OK
Content-Type: application/json

{"db": true, "status": "ok"}
```

If the database is unreachable, the endpoint returns `503 Service Unavailable` with `{"db": false, "status": "degraded"}`.

---

## 6. Rollback Procedures

If an issue occurs after a new deployment:

1. **Application Code Rollback:**
   - In Render: Go to **Deploys** → select the previous successful build → click **Rollback**.
2. **Database Migration Rollback:**
   - Open the web service shell:
   ```bash
   flask db downgrade
   ```
3. **Data Recovery:**
   - Managed PostgreSQL backups are available in the **Backups** tab of your Render database.
