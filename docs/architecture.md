# Architecture

DevPilot follows a modular architecture designed to separate the frontend, API layer, database, authentication, repository integration, and scanning engine.

## High-Level Architecture

```text
┌──────────────────────┐
│      User            │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  Next.js Frontend    │
│  React + TypeScript  │
└──────────┬───────────┘
           │ HTTP / JSON
           ▼
┌──────────────────────┐
│    FastAPI Backend   │
├──────────────────────┤
│ Authentication       │
│ Projects             │
│ Repositories         │
│ Scans                │
└──────────┬───────────┘
           │
     ┌─────┴──────────────┐
     ▼                    ▼
┌──────────┐  ┌────────────────────────┐
│PostgreSQL│  │  GitHub Clone Service  │
│ Database │  │  + Scan Engine         │
└──────────┘  └───────────┬────────────┘
                          │
                          ▼
                   ┌──────────────┐
                   │   Findings   │
                   └──────────────┘
```

## Frontend

The frontend is responsible for:

- User interface
- Authentication screens
- Dashboard
- Project management
- Repository management
- Scan controls
- Findings visualization

Technology:

- Next.js 16
- React 19
- TypeScript
- Tailwind CSS

## Backend

The backend is built with FastAPI.

### Main API modules
```
backend/app/api/
├── auth.py
├── users.py
├── projects.py
├── repositories.py
└── scans.py
```

The API layer handles:

- HTTP requests
- Authentication
- Authorization
- Request validation
- Database operations
- Scan orchestration (clone → analyze → store findings)

### Services
```
backend/app/services/
├── github/
│   ├── __init__.py
│   └── repository.py      # URL validation + secure cloning
└── scan_engine/
    ├── engine.py           # ScanEngine orchestrator
    └── analyzers.py        # Static code analysis
```

## Authentication

DevPilot uses JWT-based authentication.

The authentication flow is:
```
Register/Login
      │
      ▼
Password verification
      │
      ▼
JWT access token
      │
      ▼
HttpOnly cookie
      │
      ▼
Authenticated API request
```

Protected resources verify both:

- The user is authenticated.
- The requested resource belongs to that user.

## Database

PostgreSQL stores the application's persistent data.

The ORM layer uses SQLAlchemy. Database schema changes are managed with Alembic migrations.

Core entities:
```
User
 └── Project
       └── Repository  (stores validated GitHub HTTPS URL)
             └── Scan
                   └── Finding
```

### Project Ownership

Every project belongs to a user. Repositories belong to projects. Scans belong to repositories. Access follows the ownership chain — an authenticated user cannot access another user's project, repository, scan, or finding.

## GitHub Repository Service

The `app/services/github/repository.py` module handles secure repository access.

### URL Validation (`validate_github_url`)

Accepts only GitHub HTTPS URLs of the form:
```
https://github.com/<owner>/<repo>
https://github.com/<owner>/<repo>.git
```

Explicitly rejects:
- HTTP (plain-text) URLs
- `git://`, `ssh://`, `file://` and other schemes
- SSH shorthand (`git@github.com:...`)
- All non-`github.com` hosts (GitLab, Bitbucket, localhost, private IPs)
- Embedded credentials (`user:pass@...`)
- Non-standard ports
- Query strings and fragments
- Local or relative paths

Returns the canonical `.git` form on success.
Raises `GitHubURLValidationError` on failure.

### Secure Cloning (`clone_repository`)

A context manager that:

1. Creates an isolated `tempfile.mkdtemp()` workspace.
2. Runs `git clone --depth 1 -- <url> <dest>` via `subprocess.run` with:
   - An argument array (never `shell=True`)
   - `GIT_TERMINAL_PROMPT=0` to prevent interactive prompts
   - Configurable timeout (default 120 seconds)
3. Yields the cloned path to the caller.
4. **Always** deletes the workspace on exit — including on exception and timeout.

```python
with clone_repository(url, timeout=120) as repo_path:
    # repo_path is a Path to the cloned tree
    run_analysis(repo_path)
# workspace is deleted here, even if an exception occurred
```

Raises `GitCloneTimeoutError` on timeout, `GitCloneError` on other clone failures. Error messages are user-safe and never leak internal paths.

## Scan Workflow

```
POST /api/scans  { repository_id }
        │
        ▼
  Verify ownership
        │
        ▼
  Validate stored URL (422 if invalid)
        │
        ▼
  Create Scan (status = pending)
        │
        ▼
  Return 201 immediately
        │
        ▼ (background task)
  clone_repository(url, timeout)
        │
        ▼
  status = running
        │
        ▼
  ScanEngine.run(cloned_path)
        │
        ├── completed → store findings
        └── failed    → mark scan failed
              │
              ▼ (always)
        Delete temp directory
```

The client sends only `repository_id`. The backend retrieves the stored (validated) URL. The frontend never sends or sees repository paths.

## Scan Engine

`ScanEngine` in `app/services/scan_engine/engine.py` is unchanged from Phase 2. It runs static code analysis via `analyzers.py`, which scans supported file extensions for:

- TODO/FIXME markers (info)
- Debug `print()` statements in Python (low)
- Broad `except Exception` handling (medium)
- Possible hardcoded secrets (`API_KEY`, `SECRET_KEY`, etc.) (high)

## Design Principles

**Separation of Concerns**
Authentication, API routes, database models, URL validation, cloning, and scanning logic remain separated.

**Secure by Default**
Protected resources require authentication and ownership validation. Only GitHub HTTPS URLs are accepted. Cloning uses argument arrays, never shell interpolation.

**No Local Paths from Clients**
The frontend never sends local paths. All repository access is via stored GitHub URLs resolved by the backend.

**Guaranteed Cleanup**
Temporary clone directories are always deleted, even on failure, using a context manager that runs in the `finally` block.

**Stateless Authentication**
JWT access tokens allow the API to authenticate requests without server-side sessions.

**Background Processing**
Repository scans are executed as background tasks so API requests are not blocked.

**Incremental Architecture**
New analysis engines, additional host providers, and integrations can be added without rewriting the core API.
