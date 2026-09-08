# Development Guide

## Prerequisites

- Python 3.9+
- Node.js 18+
- PostgreSQL (for production; tests use SQLite in-memory)
- `git` on PATH (required for cloning repositories)

---

## Backend Setup

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt   # or install from pyproject.toml
```

Create `backend/.env`:
```
DATABASE_URL=postgresql://user:password@localhost:5432/devpilot
JWT_SECRET_KEY=<a-long-random-secret>
GIT_CLONE_TIMEOUT_SECONDS=120
```

Run migrations:
```bash
alembic upgrade head
```

Start the server:
```bash
uvicorn main:app --reload
```

---

## Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

The frontend runs on `http://localhost:3000` and proxies API calls to `http://localhost:8000`.

---

## Running Backend Tests

```bash
cd backend
.venv/bin/pytest tests/ -v
```

Tests use an in-memory SQLite database and do not require a PostgreSQL instance or network access. All `git clone` calls are mocked.

### Test coverage

| File | What is tested |
|---|---|
| `test_github_url_validation.py` | `validate_github_url()` — all valid forms, all rejection categories |
| `test_clone_repository.py` | `_run_clone()` and `clone_repository()` context manager — subprocess args, shell=False, GIT_TERMINAL_PROMPT, timeout, cleanup |
| `test_scan_api.py` | POST/GET /api/scans — authorization, schema (no repository_path), background task wiring, 422 for invalid stored URLs |
| `test_repository_api.py` | POST/GET /api/repositories — URL validation at creation, 422 error messages, authorization |

---

## Frontend Lint and Build

```bash
cd frontend
npm run lint   # ESLint
npm run build  # TypeScript check + Next.js production build
```

---

## Project Structure

```
devpilot/
├── backend/
│   ├── app/
│   │   ├── api/           # Route handlers
│   │   ├── models/        # SQLAlchemy models
│   │   ├── services/
│   │   │   ├── github/    # URL validation + secure cloning
│   │   │   └── scan_engine/  # Static analysis
│   │   ├── auth.py        # JWT helpers
│   │   └── database.py    # Engine + settings
│   ├── tests/             # pytest test suite
│   ├── migrations/        # Alembic migrations
│   └── main.py            # FastAPI app entry point
├── frontend/
│   └── src/
│       ├── app/           # Next.js pages
│       ├── components/    # React components
│       └── lib/           # API client
└── docs/                  # Documentation
```

---

## Security Notes

- The GitHub clone service uses `subprocess.run` with an **argument array** and `shell=False` to prevent command injection.
- Only `github.com` HTTPS URLs are accepted. SSH, file, and other schemes are rejected at validation.
- Temporary clone directories are always cleaned up via a context manager `finally` block.
- The clone timeout defaults to 120 seconds (configurable via `GIT_CLONE_TIMEOUT_SECONDS`).
- The `backend/.env` file must never be committed. It is in `.gitignore`.
