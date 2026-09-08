# API Reference

Base URL: `http://localhost:8000`

All authenticated endpoints require an HttpOnly JWT cookie (`devpilot_token`), set automatically by the browser after a successful login.

---

## Authentication

### POST /api/auth/register

Create a new user account.

**Request body**
```json
{
  "name": "Alice",
  "email": "alice@example.com",
  "password": "secret"
}
```

**Response 201**
```json
{
  "id": "<uuid>",
  "email": "alice@example.com",
  "name": "Alice"
}
```

Sets the `devpilot_token` cookie.

---

### POST /api/auth/login

Authenticate an existing user.

**Request body**
```json
{
  "email": "alice@example.com",
  "password": "secret"
}
```

**Response 200** — same shape as register. Sets the `devpilot_token` cookie.

---

### POST /api/auth/logout

Clear the authentication cookie.

**Response 200**
```json
{ "message": "Logged out" }
```

---

### GET /api/auth/me

Return the currently authenticated user.

**Response 200**
```json
{
  "id": "<uuid>",
  "email": "alice@example.com",
  "name": "Alice"
}
```

---

## Projects

### GET /api/projects

List all projects owned by the authenticated user.

**Response 200** — array of project objects.

---

### POST /api/projects

Create a new project.

**Request body**
```json
{ "name": "My Project" }
```

**Response 201**
```json
{
  "id": "<uuid>",
  "name": "My Project",
  "user_id": "<uuid>"
}
```

---

### GET /api/projects/{project_id}

Get a single project by ID. Returns 404 if not found or not owned by the caller.

---

## Repositories

### POST /api/repositories

Add a repository to a project.

The `url` field must be a valid GitHub HTTPS URL. It is validated and normalised to the canonical `.git` form before storage. Invalid URLs return 422.

**Request body**
```json
{
  "name": "My Repo",
  "url": "https://github.com/owner/repo",
  "project_id": "<uuid>"
}
```

**Response 201**
```json
{
  "id": "<uuid>",
  "name": "My Repo",
  "url": "https://github.com/owner/repo.git",
  "project_id": "<uuid>"
}
```

**Error 422** — URL is not a valid GitHub HTTPS URL.

Accepted URL forms:
- `https://github.com/<owner>/<repo>`
- `https://github.com/<owner>/<repo>.git`

Rejected URL forms (non-exhaustive):
- `http://`, `git://`, `ssh://`, `file://` schemes
- SSH shorthand `git@github.com:...`
- Any host other than `github.com`
- URLs with credentials, ports, query strings, or fragments
- Local or relative paths

---

### GET /api/repositories?project_id={id}

List repositories for a project. Returns 404 if the project is not owned by the caller.

---

### GET /api/repositories/{repository_id}

Get a single repository. Returns 404 if not found or not owned by the caller.

---

## Scans

### POST /api/scans

Trigger a new security scan.

The client sends only `repository_id`. The backend retrieves the stored GitHub URL, validates it, and clones the repository in a background task. The frontend never sends repository paths.

**Request body**
```json
{
  "repository_id": "<uuid>"
}
```

**Response 201** — scan is created immediately with `status = "pending"`.
```json
{
  "id": "<uuid>",
  "repository_id": "<uuid>",
  "status": "pending",
  "started_at": null,
  "completed_at": null
}
```

**Error 404** — repository not found or not owned by caller.
**Error 422** — stored URL failed validation (data integrity guard).

**Background workflow:**
```
pending → clone repository → running → scan engine → completed | failed
```

---

### GET /api/scans?repository_id={id}

List scans for a repository, ordered by newest first. Returns 404 for unowned repositories.

---

### GET /api/scans/{scan_id}

Get a single scan. Returns 404 for unowned scans.

---

### GET /api/scans/{scan_id}/summary

Get a finding count summary for a completed scan.

**Response 200**
```json
{
  "scan_id": "<uuid>",
  "status": "completed",
  "total_findings": 12,
  "high": 2,
  "medium": 3,
  "low": 4,
  "info": 3
}
```

---

### GET /api/scans/{scan_id}/findings

List all findings for a scan, ordered by newest first.

**Response 200** — array of finding objects.
```json
[
  {
    "id": "<uuid>",
    "scan_id": "<uuid>",
    "severity": "high",
    "title": "Possible hardcoded secret",
    "description": "A possible credential or secret appears to be hardcoded.",
    "file_path": "src/config.py",
    "line_number": 42
  }
]
```

Severity levels: `high`, `medium`, `low`, `info`

---

## Health

### GET /health

No authentication required.

**Response 200**
```json
{
  "status": "ok",
  "service": "devpilot-api",
  "version": "0.1.0"
}
```
