# Getting Started

## Prerequisites

Make sure the following are installed:

- Git
- Python 3.9+
- Node.js 18+
- PostgreSQL

## Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/<your-org>/devpilot.git
   cd devpilot
   ```

2. **Set up the backend**
   ```bash
   cd backend
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Configure environment**

   Create `backend/.env`:
   ```
   DATABASE_URL=postgresql://user:password@localhost:5432/devpilot
   JWT_SECRET_KEY=your-secret-key
   GIT_CLONE_TIMEOUT_SECONDS=120
   ```

4. **Run database migrations**
   ```bash
   alembic upgrade head
   ```

5. **Start the API server**
   ```bash
   uvicorn main:app --reload
   ```

6. **Set up the frontend** (in a new terminal)
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

7. Open `http://localhost:3000` in your browser.

## Running Tests

```bash
cd backend
.venv/bin/pytest tests/ -v
```

See [development.md](development.md) for full details.
