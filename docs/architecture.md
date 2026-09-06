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
     ┌─────┴─────┐
     ▼           ▼
┌──────────┐ ┌────────────────┐
│PostgreSQL│ │  Scan Engine   │
│ Database │ │ Code Analysis  │
└──────────┘ └───────┬────────┘
                     │
                     ▼
              ┌──────────────┐
              │   Findings   │
              └──────────────┘
Frontend

The frontend is responsible for:

User interface
Authentication screens
Dashboard
Project management
Repository management
Scan controls
Findings visualization
Technology:

Next.js
React
TypeScript
Tailwind CSS
Backend

The backend is built with FastAPI.

Main API modules
backend/app/api/
├── auth.py
├── users.py
├── projects.py
├── repositories.py
└── scans.py
The API layer handles:

HTTP requests
Authentication
Authorization
Request validation
Database operations
Scan orchestration
Authentication

DevPilot uses JWT-based authentication.

The authentication flow is:
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
Protected resources verify both:

The user is authenticated.
The requested resource belongs to that user.
Database

PostgreSQL stores the application's persistent data.

The ORM layer uses SQLAlchemy.

Database schema changes are managed with Alembic migrations.

Core entities include:
User
 │
 └── Project
       │
       └── Repository
             │
             └── Scan
                   │
                   └── Finding
Project Ownership

Every project belongs to a user.

Repositories belong to projects.

Scans belong to repositories.

Therefore access follows the ownership chain:
User
 ↓
Project
 ↓
Repository
 ↓
Scan
 ↓
Finding
An authenticated user cannot access another user's project, repository, or scan.

Scan Engine

The scan engine is responsible for analyzing repository contents.

Current architecture:
Repository
    │
    ▼
Scan Request
    │
    ▼
Background Task
    │
    ▼
Scan Engine
    │
    ├── Code Analysis
    ├── Issue Detection
    └── Finding Generation
             │
             ▼
          Database
Future GitHub Integration

The planned repository workflow is
GitHub URL
    │
    ▼
Validate Repository
    │
    ▼
Clone Repository
    │
    ▼
Temporary Workspace
    │
    ▼
Run Scan
    │
    ▼
Store Findings
    │
    ▼
Display Results
Temporary workspaces will isolate repository scanning from the main application environment.

Design Principles

DevPilot follows these principles:

Separation of Concerns

Authentication, API routes, database models, and scanning logic remain separated.

Secure by Default

Protected resources require authentication and ownership validation.

Stateless Authentication

JWT access tokens allow the API to authenticate requests without maintaining server-side sessions.
Background Processing

Repository scans are executed as background tasks so API requests are not blocked by long-running analysis.

Incremental Architecture

New analysis engines, GitHub providers, AI models, and integrations can be added without rewriting the core API.
