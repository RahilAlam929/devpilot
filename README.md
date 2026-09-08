# DevPilot

A static analysis platform for software repositories — detect code quality, security, and maintainability issues through a REST API and web dashboard.

---

## Overview

DevPilot is a full-stack code intelligence platform that runs static analysis against local code repositories and surfaces findings categorized by severity. You point it at a directory on disk, it walks the source files line by line, and stores every detected issue in a queryable PostgreSQL database.

**Problem it solves:** Manually auditing codebases for debug statements, broad error handling, hardcoded credentials, and unfinished work markers is tedious and error-prone. DevPilot automates that sweep and makes the results accessible via a REST API and a Next.js dashboard.

**Core workflow:**

```
Register / Login
      │
      ▼
Create a Project
      │
      ▼
Register a Repository  (name + URL stored; no cloning)
      │
      ▼
POST /api/scans  { repository_id, repository_path }
      │
      ▼
FastAPI BackgroundTask runs static analysis on the local path
      │
      ▼
Findings stored in PostgreSQL  (high / medium / low / info)
      │
      ▼
Query findings via API or view the dashboard summary
```

---

## Features

### Currently Implemented

- Email + password registration and login with Argon2 password hashing
- JWT access tokens stored in HttpOnly cookies
- User-scoped resources — cross-user access is rejected at every layer
- Project and repository management (create, list, retrieve)
- Asynchronous scan execution via FastAPI `BackgroundTasks`
- Scan lifecycle tracking: `pending → running → completed` / `failed`
- Regex-based static analysis across 14 file extensions
- Severity-bucketed findings: `high`, `medium`, `low`, `info`
- Scan summary endpoint returning per-severity counts
- Next.js dashboard (prototype): trigger scans, view status, and review finding summaries
- PostgreSQL 16 with Alembic-managed schema migrations
- Docker Compose service for the database

### Planned

- Automatic repository cloning from a remote URL
- GitHub OAuth and webhook integration
- Frontend authentication UI (login/register forms)
- Full frontend routing — projects, repositories, scans, findings explorer
- Redis + Celery background worker infrastructure
- AST-based analysis beyond regex
- AI-assisted finding explanations and fix suggestions
- RBAC, rate limiting, and team workspaces
- CI/CD pipelines and production deployment configuration
- Automated test suite

---

## Architecture

```mermaid
flowchart TD
    Browser["Browser\nNext.js (port 3000)"]

    subgraph Backend["FastAPI Backend (port 8000)"]
        direction TB
        Router["API Routers\n/api/*"]
        AuthMW["get_current_user\nJWT cookie → User"]
        ProjR["Projects Router"]
        RepoR["Repositories Router"]
        ScanR["Scans Router"]
        BG["FastAPI BackgroundTask"]
        Engine["ScanEngine.run()"]
        Analyzers["analyze_repository()\nRegex rules per file"]
    end

    DB[(PostgreSQL 16\nport 5433)]
    Docker["docker-compose\npostgres:16-alpine"]

    Browser -->|"HTTP/JSON + cookie"| Router
    Router --> AuthMW
    AuthMW --> ProjR
    AuthMW --> RepoR
    AuthMW --> ScanR
    ScanR -->|"add_task()"| BG
    BG --> Engine
    Engine --> Analyzers
    ProjR & RepoR & ScanR & Analyzers -->|SQLAlchemy 2.0| DB
    Docker -.->|provisions| DB
```

**Request path for a protected endpoint:**

1. Cookie `devpilot_token` is read from the request.
2. JWT is decoded; the `sub` claim resolves to a `User.id`.
3. The handler filters all queries by the authenticated user's ownership chain.
4. For scans: a `Scan` row is created with `status="pending"`, the HTTP response is returned immediately, and a `BackgroundTask` drives the engine in a separate database session.

---

## Tech Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| Frontend framework | Next.js 16.3.4 | React server/client rendering, routing |
| UI language | TypeScript 5 | Type-safe frontend development |
| Styling | Tailwind CSS 4 | Utility-first CSS |
| Backend framework | FastAPI 0.128.8 | Async HTTP API, dependency injection |
| Runtime | Python 3.9 / Uvicorn 0.39 | ASGI server |
| ORM | SQLAlchemy 2.0 | Database access and model definition |
| Migrations | Alembic 1.16.5 | Schema versioning |
| Database | PostgreSQL 16 | Persistent storage |
| DB driver | psycopg 3.2.13 (binary) | Async-capable PostgreSQL adapter |
| Validation | Pydantic 2.13 + pydantic-settings 2.11 | Request/response validation, settings |
| Password hashing | pwdlib 0.2.1 (Argon2 via argon2-cffi) | Secure credential storage |
| Authentication | PyJWT 2.13 (HS256) | Stateless JWT tokens |
| Infrastructure | Docker + Compose | Local PostgreSQL provisioning |

---

## Project Structure

```
devpilot/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── auth.py          # /api/auth — register, login, logout, me
│   │   │   ├── users.py         # /api/users — legacy unauthenticated user creation
│   │   │   ├── projects.py      # /api/projects — project CRUD
│   │   │   ├── repositories.py  # /api/repositories — repository CRUD
│   │   │   └── scans.py         # /api/scans — scan creation, status, findings
│   │   ├── models/
│   │   │   └── models.py        # SQLAlchemy ORM: User, Project, Repository, Scan, Finding
│   │   ├── services/
│   │   │   └── scan_engine/
│   │   │       ├── engine.py    # ScanEngine — orchestrates a single scan run
│   │   │       └── analyzers.py # analyze_repository() — regex rules per file
│   │   ├── auth.py              # JWT encode/decode, Argon2 password helpers
│   │   └── database.py          # SQLAlchemy engine, session factory, pydantic Settings
│   ├── migrations/
│   │   ├── env.py               # Alembic runtime config (reads sqlalchemy.url from alembic.ini)
│   │   └── versions/            # Migration scripts
│   ├── main.py                  # FastAPI app factory, CORS, router registration
│   └── alembic.ini              # Alembic configuration
│
├── frontend/
│   └── src/app/
│       ├── page.tsx             # Single-page dashboard (prototype)
│       ├── layout.tsx           # Root HTML layout
│       └── globals.css          # Tailwind base + custom component styles
│
├── docs/                        # Architecture notes and getting-started draft
├── workers/                     # Empty — planned background worker infrastructure
├── infrastructure/              # Empty — planned deployment configuration
├── tests/                       # Empty — planned test suite
├── docker-compose.yml           # PostgreSQL 16 service definition
└── README.md
```

---

## Getting Started

### Prerequisites

| Tool | Required version |
|------|-----------------|
| Python | 3.9 or later |
| Node.js | 18 or later |
| Docker | Any recent version with Compose v2 |
| Git | Any |

### 1. Clone the repository

```bash
git clone https://github.com/RahilAlam929/devpilot.git
cd devpilot
```

### 2. Start PostgreSQL

```bash
docker compose up -d postgres
```

PostgreSQL 16 will be reachable at `127.0.0.1:5433`. The container is named `devpilot-postgres` and uses a persistent named volume (`postgres_data`).

### 3. Backend — virtual environment and dependencies

```bash
cd backend

python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

pip install \
  fastapi \
  "uvicorn[standard]" \
  sqlalchemy \
  alembic \
  "psycopg[binary]" \
  pydantic \
  pydantic-settings \
  pyjwt \
  "pwdlib[argon2]" \
  email-validator \
  python-dotenv
```

### 4. Environment variables

Create `backend/.env` with the following keys. Do not commit this file.

```env
DATABASE_URL=postgresql+psycopg://devpilot:devpilot_dev_password@127.0.0.1:5433/devpilot
JWT_SECRET_KEY=replace-with-a-long-random-string
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=60
AUTH_COOKIE_NAME=devpilot_token
```

> `JWT_SECRET_KEY` must be a strong random value. Generate one with:
> ```bash
> python3 -c "import secrets; print(secrets.token_hex(32))"
> ```

> **Alembic note:** `alembic.ini` contains a hardcoded `sqlalchemy.url`. For local development the default value matches the Docker Compose credentials. Update it if your database connection differs.

### 5. Run database migrations

```bash
# from backend/ with the virtual environment active
alembic upgrade head
```

### 6. Start the backend

```bash
uvicorn main:app --reload --port 8000
```

- API: `http://127.0.0.1:8000`
- Interactive docs (Swagger UI): `http://127.0.0.1:8000/docs`
- Health check: `http://127.0.0.1:8000/health`

### 7. Frontend setup

```bash
cd ../frontend
npm install
npm run dev
```

Dashboard: `http://localhost:3000`

> **Prototype limitation:** `page.tsx` currently has hardcoded `userId` and `projectId` constants. The frontend does not participate in the authentication flow yet. Use the API directly (curl, Swagger UI, or Postman) until frontend auth forms are implemented.

---

## Environment Variables

All variables are read from `backend/.env` via pydantic-settings. The application will refuse to start if required variables are missing.

```env
# Required — PostgreSQL connection string
DATABASE_URL=

# Required — secret used to sign and verify JWT tokens
JWT_SECRET_KEY=

# Optional — defaults shown
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=60
AUTH_COOKIE_NAME=devpilot_token
```

---

## Authentication

DevPilot uses stateless JWT authentication delivered via HttpOnly cookies.

### Flow

```
POST /api/auth/register  or  POST /api/auth/login
             │
             ▼
    Argon2 password verification (pwdlib)
             │
             ▼
    JWT signed with JWT_SECRET_KEY (HS256)
    Payload: { sub: user_id, exp: now + JWT_ACCESS_TOKEN_EXPIRE_MINUTES }
             │
             ▼
    Set-Cookie: devpilot_token=<token>
    HttpOnly=true, SameSite=Lax, path=/
             │
             ▼
    Subsequent requests: cookie read → JWT decoded → User loaded from DB
```

### Registration

- Email must be a valid address and is normalised to lowercase.
- Password must be at least 8 characters.
- Duplicate email addresses return `409 Conflict`.
- On success, the auth cookie is set and the created user is returned.

### Login

- Accepts `email` + `password`.
- Returns `401 Unauthorized` for any mismatch, with the same error message for both unknown email and wrong password (no user enumeration).

### Logout

`POST /api/auth/logout` deletes the cookie. No server-side session is invalidated (stateless JWT).

### Protected routes

All Project, Repository, and Scan endpoints use a `get_current_user` FastAPI dependency. It:

1. Reads the `devpilot_token` cookie.
2. Decodes the JWT; raises `401` on expiry or invalid signature.
3. Loads the `User` row; raises `401` if the user no longer exists.

### Ownership checks

Every resource query additionally filters by the authenticated user's ownership chain (`user_id` on projects, project ownership on repositories, repository ownership on scans). A user cannot read, modify, or scan another user's resources.

---

## API Reference

All routes are prefixed with `/api`. Protected routes require the `devpilot_token` cookie.

### Health

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/health` | No | Returns service name and version |

### Authentication

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/auth/register` | No | Create account; sets auth cookie |
| `POST` | `/api/auth/login` | No | Authenticate; sets auth cookie |
| `POST` | `/api/auth/logout` | No | Clears auth cookie |
| `GET` | `/api/auth/me` | Yes | Returns the authenticated user |

**Register request body:**
```json
{ "email": "dev@example.com", "name": "Alice", "password": "min8chars" }
```

**Login request body:**
```json
{ "email": "dev@example.com", "password": "min8chars" }
```

**Response (register / login / me):**
```json
{ "id": "<uuid>", "email": "dev@example.com", "name": "Alice" }
```

### Users

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/users` | No | Legacy unauthenticated user creation (no password hashing) |

> This endpoint predates the auth system. Prefer `/api/auth/register` for all new user creation.

### Projects

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/projects` | Yes | Create a project for the current user |
| `GET` | `/api/projects` | Yes | List all projects owned by the current user |
| `GET` | `/api/projects/{project_id}` | Yes | Get a single owned project |

**Create request body:**
```json
{ "name": "my-project" }
```

### Repositories

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/repositories` | Yes | Register a repository under an owned project |
| `GET` | `/api/repositories?project_id=<id>` | Yes | List repositories in an owned project |
| `GET` | `/api/repositories/{repository_id}` | Yes | Get a single owned repository |

**Create request body:**
```json
{
  "name": "my-repo",
  "url": "https://github.com/example/my-repo",
  "project_id": "<project-uuid>"
}
```

> The `url` field is stored for reference only. DevPilot does not clone repositories.

### Scans

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/scans` | Yes | Start a scan; returns immediately while analysis runs in background |
| `GET` | `/api/scans?repository_id=<id>` | Yes | List scans for an owned repository |
| `GET` | `/api/scans/{scan_id}` | Yes | Get scan status and timestamps |
| `GET` | `/api/scans/{scan_id}/summary` | Yes | Per-severity finding counts |
| `GET` | `/api/scans/{scan_id}/findings` | Yes | Full finding list |

**Create request body:**
```json
{
  "repository_id": "<repository-uuid>",
  "repository_path": "/absolute/path/to/local/code"
}
```

> `repository_path` must be an absolute path to a directory that already exists on the machine running the backend.

**Scan status values:** `pending` · `running` · `completed` · `failed`

**Summary response:**
```json
{
  "scan_id": "<uuid>",
  "status": "completed",
  "total_findings": 12,
  "high": 1,
  "medium": 3,
  "low": 5,
  "info": 3
}
```

---

## Database

### Technology

PostgreSQL 16, accessed via SQLAlchemy 2.0 ORM with the psycopg 3 binary driver. Schema changes are managed with Alembic.

### Models and relationships

```
users
  id (PK, UUID string)
  email (unique, indexed)
  name
  password_hash
  created_at
   │
   └── projects  (ON DELETE CASCADE)
         id, name, user_id, created_at
          │
          └── repositories  (ON DELETE CASCADE)
                id, name, url, project_id, created_at
                 │
                 └── scans  (ON DELETE CASCADE)
                       id, repository_id, status
                       started_at, completed_at
                        │
                        └── findings  (ON DELETE CASCADE)
                              id, scan_id, severity
                              title, description
                              file_path, line_number
```

Cascade deletes propagate the full chain: deleting a user removes all their projects, repositories, scans, and findings.

### ER diagram

```mermaid
erDiagram
    users {
        string id PK
        string email
        string name
        string password_hash
        datetime created_at
    }
    projects {
        string id PK
        string name
        string user_id FK
        datetime created_at
    }
    repositories {
        string id PK
        string name
        string url
        string project_id FK
        datetime created_at
    }
    scans {
        string id PK
        string repository_id FK
        string status
        datetime started_at
        datetime completed_at
    }
    findings {
        string id PK
        string scan_id FK
        string severity
        string title
        text description
        string file_path
        int line_number
    }

    users ||--o{ projects : "owns"
    projects ||--o{ repositories : "contains"
    repositories ||--o{ scans : "has"
    scans ||--o{ findings : "produces"
```

### Migrations

Three migration scripts are applied in order:

| Revision | Description |
|----------|-------------|
| `4209f5ec67e9` | Create initial schema (users, projects, repositories, scans, findings) |
| `59e12d3fce6f` | Empty placeholder (no schema changes) |
| `02914dbc1623` | Add `password_hash` column to `users` |

> Alembic reads `sqlalchemy.url` directly from `alembic.ini`, not from `backend/.env`. Keep the two in sync when changing database credentials.

---

## Scan Engine

### How a scan works

1. `POST /api/scans` validates that the requested repository belongs to the current user.
2. A `Scan` row is created with `status="pending"` and committed.
3. The HTTP response (`201 Created`) is returned immediately.
4. FastAPI's `BackgroundTask` invokes `run_scan_background()` in a fresh database session.
5. `ScanEngine.run()` validates the path, sets `status="running"`, and calls `analyze_repository()`.
6. `analyze_repository()` calls `Path.rglob("*")` and passes each eligible file to `analyze_file()`.
7. Each `FindingResult` is persisted as a `Finding` row.
8. On success the scan transitions to `"completed"`; on any exception it transitions to `"failed"`.

### Static analysis rules

| Severity | Rule | Applies to |
|----------|------|------------|
| `high` | Possible hardcoded secret — variable named `API_KEY`, `SECRET_KEY`, `ACCESS_TOKEN`, or `PASSWORD` assigned a string literal | All supported extensions |
| `medium` | Broad exception handling — `except Exception:` | `.py` only |
| `low` | Debug print statement — `print(...)` | `.py` only |
| `info` | Unfinished work marker — `TODO` or `FIXME` in any comment or line | All supported extensions |

All rules are regex-based and operate line-by-line. There is no AST parsing or cross-file analysis.

### Supported file extensions

`.py` `.js` `.jsx` `.ts` `.tsx` `.java` `.go` `.rs` `.php` `.rb` `.cpp` `.c` `.h` `.hpp`

### Skipped directories

`.git` `.venv` `venv` `node_modules` `__pycache__` `.next` `dist` `build`

---

## Development

### Backend

```bash
# Start the API with hot reload
cd backend
source .venv/bin/activate
uvicorn main:app --reload --port 8000

# Apply all pending migrations
alembic upgrade head

# Generate a new migration after changing models
alembic revision --autogenerate -m "describe the change"

# Downgrade one revision
alembic downgrade -1
```

### Frontend

```bash
cd frontend

# Development server with hot reload
npm run dev

# Production build
npm run build

# Lint (ESLint with Next.js config)
npm run lint
```

> TypeScript type checking runs as part of `npm run build`. There is no separate `tsc` script in `package.json`.

### Testing

No automated test suite exists. The `tests/` directory is empty. Manual verification is currently done through the Swagger UI at `http://127.0.0.1:8000/docs` or with curl.

---

## API Examples

The examples below use `--cookie-jar` and `--cookie` to persist the session cookie across requests. Replace placeholder values (`<...>`) with actual UUIDs returned by the API.

**Register**
```bash
curl -s -c cookies.txt -X POST http://127.0.0.1:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "dev@example.com", "name": "Alice", "password": "securepassword"}'
```

**Login**
```bash
curl -s -c cookies.txt -X POST http://127.0.0.1:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "dev@example.com", "password": "securepassword"}'
```

**Get current user**
```bash
curl -s -b cookies.txt http://127.0.0.1:8000/api/auth/me
```

**Create a project**
```bash
curl -s -b cookies.txt -X POST http://127.0.0.1:8000/api/projects \
  -H "Content-Type: application/json" \
  -d '{"name": "my-project"}'
```

**Register a repository**
```bash
curl -s -b cookies.txt -X POST http://127.0.0.1:8000/api/repositories \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-repo",
    "url": "https://github.com/example/my-repo",
    "project_id": "<project-uuid>"
  }'
```

**Start a scan**
```bash
curl -s -b cookies.txt -X POST http://127.0.0.1:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "repository_id": "<repository-uuid>",
    "repository_path": "/absolute/path/to/local/code"
  }'
```

**Poll scan status**
```bash
curl -s -b cookies.txt http://127.0.0.1:8000/api/scans/<scan-uuid>
```

**Get scan summary**
```bash
curl -s -b cookies.txt http://127.0.0.1:8000/api/scans/<scan-uuid>/summary
```

**Get findings**
```bash
curl -s -b cookies.txt http://127.0.0.1:8000/api/scans/<scan-uuid>/findings
```

---

## Security

### What is implemented

| Practice | Detail |
|----------|--------|
| Password hashing | Argon2 via pwdlib — passwords are never stored in plaintext |
| JWT authentication | HS256-signed tokens with configurable expiry; secret loaded from environment |
| HttpOnly cookies | The `devpilot_token` cookie is inaccessible to JavaScript |
| Ownership enforcement | Every query filters by the authenticated user's ownership chain; no resource is returned unless it belongs to the requester |
| Input validation | Pydantic validates all request bodies; email addresses are validated with `email-validator` |
| Environment-based secrets | `JWT_SECRET_KEY` and `DATABASE_URL` are read from `.env`, not hardcoded |

### Known gaps

- `secure=False` on the auth cookie — appropriate for local HTTP development, must be set to `True` behind HTTPS in production.
- No rate limiting on authentication endpoints.
- `alembic.ini` contains a hardcoded database URL with development credentials. Do not use these credentials in production.
- The legacy `POST /api/users` endpoint creates users without password hashing and requires no authentication.

---

## Error Handling

| Status | When it occurs |
|--------|---------------|
| `400 Bad Request` | Password shorter than 8 characters |
| `401 Unauthorized` | Missing cookie, expired JWT, invalid signature, or user not found |
| `404 Not Found` | Requested resource does not exist or does not belong to the current user |
| `409 Conflict` | Registration with an email address that already exists |
| `422 Unprocessable Entity` | Pydantic validation failure (missing fields, wrong types, invalid email) |

---

## Testing

No automated tests are currently implemented. The `tests/` directory is present but empty.

Manual testing options:
- **Swagger UI** — `http://127.0.0.1:8000/docs` provides an interactive interface for all endpoints.
- **curl** — see the [API Examples](#api-examples) section above.
- **Redoc** — `http://127.0.0.1:8000/redoc` for read-only API documentation.

---

## Roadmap

**Phase 1 — Foundation** ✅ Complete
- FastAPI backend, PostgreSQL, SQLAlchemy 2.0, Alembic
- JWT authentication with HttpOnly cookies
- Projects, Repositories, Scans, Findings REST API
- Regex-based static analysis scan engine
- Next.js prototype dashboard

**Phase 2 — Repository Integration** ⬜ Planned
- Automatic repository cloning from URL
- Temporary workspace isolation per scan
- GitHub URL validation

**Phase 3 — Frontend** ⬜ Planned
- Authentication UI (register / login / logout)
- Full page routing — projects, repositories, scans, findings
- Finding detail view with file and line context
- Severity filtering and scan history

**Phase 4 — Analysis Depth** ⬜ Planned
- AST-based analysis
- Expanded rule sets (security, performance, maintainability)
- Cross-file dependency analysis

**Phase 5 — AI Integration** ⬜ Planned
- LLM-powered finding explanations
- Fix suggestions per finding

**Phase 6 — Production Hardiness** ⬜ Planned
- Redis + Celery background workers
- GitHub OAuth and webhooks
- RBAC and team workspaces
- Rate limiting
- Structured logging, metrics, tracing
- CI/CD pipelines

---

## Contributing

1. Fork the repository and create a feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes. For backend changes, ensure the app starts and basic flows work via Swagger UI. For frontend changes, verify `npm run build` and `npm run lint` pass without errors.

3. Keep commits focused. One logical change per commit with a clear message:
   ```
   feat: add severity filter query param to findings endpoint
   fix: return 404 instead of 500 when repository path is missing
   ```

4. If you add or change a database model, generate a migration:
   ```bash
   cd backend
   alembic revision --autogenerate -m "describe the change"
   ```

5. Open a pull request against `main`. Describe what changed, why, and how to test it.

---

## License

License information has not yet been added to this repository.

---

## Project Status

DevPilot is in active early development. The backend API is functional — authentication, resource management, and the scan engine all work end to end. The frontend is a working prototype with hardcoded identifiers; it demonstrates the scan workflow but is not yet connected to the authentication system. There are no automated tests and no production deployment configuration. The project is suitable for local development and learning, not production use.
