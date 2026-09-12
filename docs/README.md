# DevAnalyzeX

DevAnalyzeX is an AI-powered developer platform for analyzing repositories, detecting code issues, and helping developers understand and improve their projects.

## What DevAnalyzeX Does

DevAnalyzeX is being built around a simple workflow:

1. Create an account
2. Create a project
3. Connect a repository
4. Run a repository scan
5. Analyze findings
6. Review security, quality, and code issues

## Current Status

### Completed

- User registration
- User login
- User logout
- Current authenticated user
- JWT-based authentication
- HTTP-only authentication cookie
- Protected project APIs
- Project ownership isolation
- Protected repository APIs
- Repository ownership isolation
- Protected scan APIs
- Scan ownership isolation
- PostgreSQL database
- SQLAlchemy ORM
- Alembic migrations
- FastAPI backend

### In Progress

- GitHub repository integration
- Repository cloning
- Temporary scan workspaces
- Real repository scanning
- Dashboard
- Scan results UI
- AI-powered code analysis

## Tech Stack

### Frontend

- Next.js
- React
- TypeScript
- Tailwind CSS

### Backend

- Python
- FastAPI
- SQLAlchemy
- Alembic
- PostgreSQL

### Infrastructure

- Docker
- GitHub

## Project Structure

```text
devpilot/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── models/
│   │   ├── services/
│   │   ├── auth.py
│   │   └── database.py
│   ├── migrations/
│   └── main.py
│
├── frontend/
│
├── docs/
│
└── docker-compose.yml
Documentation
Getting Started
Architecture
Authentication
API Reference
Development
