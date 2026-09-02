# 🚀 DevPilot

> **AI-native developer platform for understanding, analyzing, and improving software projects.**

DevPilot is a developer productivity and code intelligence platform designed to help engineers understand their codebases, detect potential issues, review code, and continuously improve software quality.

The platform combines **repository intelligence, static analysis, AI-assisted reasoning, and developer workflows** into a single system.

---

## ✨ Vision

Modern software projects are becoming increasingly complex.

Developers need to understand:

- What is happening inside a codebase?
- Where are the potential bugs?
- Which files introduce security or quality risks?
- What changed between scans?
- How can an issue be fixed?
- Can AI explain the problem in developer-friendly language?

**DevPilot aims to answer these questions automatically.**

---

# 🏗️ System Architecture

```text
                         ┌──────────────────────────┐
                         │        Developer         │
                         │   Web Dashboard / UI     │
                         └────────────┬─────────────┘
                                      │
                                      ▼
                         ┌──────────────────────────┐
                         │      Next.js Frontend    │
                         │      TypeScript + UI     │
                         └────────────┬─────────────┘
                                      │
                              REST / JSON API
                                      │
                                      ▼
                         ┌──────────────────────────┐
                         │       FastAPI Backend    │
                         │                          │
                         │  Auth / Projects / API  │
                         │  Repository Management   │
                         │  Scan Management        │
                         └───────┬─────────┬────────┘
                                 │         │
                    ┌────────────┘         └─────────────┐
                    ▼                                    ▼
          ┌──────────────────┐                 ┌──────────────────┐
          │   PostgreSQL     │                 │  Redis / Workers │
          │                  │                 │                  │
          │ Users            │                 │ Async Jobs       │
          │ Projects         │                 │ Repository Scan  │
          │ Repositories     │                 │ Code Analysis    │
          │ Scans            │                 │ AI Processing    │
          │ Findings         │                 └────────┬─────────┘
          └──────────────────┘                          │
                                                        ▼
                                             ┌────────────────────┐
                                             │  Analysis Engine   │
                                             │                    │
                                             │ Static Analysis    │
                                             │ Security Checks    │
                                             │ Code Quality       │
                                             │ AI Reasoning       │
                                             └─────────┬──────────┘
                                                       │
                                                       ▼
                                             ┌────────────────────┐
                                             │      Findings      │
                                             │                    │
                                             │ Severity           │
                                             │ File               │
                                             │ Line               │
                                             │ Description        │
                                             │ Suggested Fix      │
                                             └────────────────────┘
How DevPilot Works

The core workflow is:
GitHub Repository
       │
       ▼
Connect Repository
       │
       ▼
Create Scan
       │
       ▼
Repository Worker
       │
       ▼
Clone / Fetch Code
       │
       ▼
Code Analysis
       │
       ├── Bugs
       ├── Security Issues
       ├── Code Smells
       ├── Performance Issues
       └── Maintainability
       │
       ▼
AI Analysis
       │
       ▼
Findings
       │
       ▼
Developer Dashboard
Core Domain Model
User
 │
 └── Project
       │
       └── Repository
             │
             └── Scan
                   │
                   └── Finding
User

Represents a DevPilot account.

Project

Logical workspace containing repositories.

Repository

A Git repository connected to a project.

Scan

An analysis execution against a repository.

Finding

An issue discovered during a scan.

Examples:
CRITICAL
HIGH
MEDIUM
LOW
INFO
Project Structure
devpilot/
│
├── frontend/
│   ├── src/
│   │   └── app/
│   ├── public/
│   ├── package.json
│   └── tsconfig.json
│
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── users.py
│   │   │   ├── projects.py
│   │   │   ├── repositories.py
│   │   │   └── scans.py
│   │   │
│   │   ├── models/
│   │   │   └── models.py
│   │   │
│   │   └── database.py
│   │
│   ├── migrations/
│   ├── main.py
│   ├── alembic.ini
│   └── requirements.txt
│
├── workers/
│
├── infrastructure/
│
├── tests/
│
├── docs/
│
├── .github/
│   └── workflows/
│
├── docker-compose.yml
├── .gitignore
└── README.md
API Architecture

DevPilot exposes a REST API.

Health
GET /health
Returns API health information.
Users

Create a user:
POST /api/users
{
  "email": "developer@example.com",
  "name": "Developer"
}
Projects

Create project:
POST /api/projects
List projects:
GET /api/projects?user_id=<USER_ID>
Get project:
GET /api/projects/<PROJECT_ID>
Repositories

Connect repository:
POST /api/repositories
Example:
{
  "name": "my-project",
  "url": "https://github.com/example/my-project",
  "project_id": "<PROJECT_ID>"
}
List repositories:
GET /api/repositories?project_id=<PROJECT_ID>
Scans

Create scan
POST /api/scans
Example:
{
  "repository_id": "<REPOSITORY_ID>"
}
Get scan:
GET /api/scans/<SCAN_ID>
Database Design

DevPilot currently uses PostgreSQL with SQLAlchemy and Alembic.
┌──────────────┐
│    users     │
├──────────────┤
│ id           │
│ email        │
│ name         │
│ created_at   │
└──────┬───────┘
       │
       │ 1:N
       ▼
┌──────────────┐
│   projects   │
├──────────────┤
│ id           │
│ name         │
│ user_id      │
│ created_at   │
└──────┬───────┘
       │
       │ 1:N
       ▼
┌────────────────┐
│  repositories  │
├────────────────┤
│ id             │
│ name           │
│ url            │
│ project_id     │
│ created_at     │
└───────┬────────┘
        │
        │ 1:N
        ▼
┌──────────────┐
│    scans     │
├──────────────┤
│ id           │
│ repository_id│
│ status       │
│ started_at   │
│ completed_at │
└──────┬───────┘
       │
       │ 1:N
       ▼
┌──────────────┐
│   findings   │
├──────────────┤
│ id           │
│ scan_id      │
│ severity     │
│ title        │
│ description  │
│ file_path    │
│ line_number  │
└──────────────┘
Local Development
Prerequisites

Make sure you have:

Node.js
Python 3.9+
Docker
Git
Clone
git clone https://github.com/RahilAlam929/devpilot.git
cd devpilot
Start PostgreSQL
docker compose up -d postgres
Verify:
docker ps
PostgreSQL is exposed locally on:
127.0.0.1:5433
Backend Setup
cd backend
Create virtual environment:
python3 -m venv .venv
Activate:
source .venv/bin/activate
Install dependencies:
pip install -r requirements.txt
Configure environment:
DATABASE_URL=postgresql+psycopg://devpilot:devpilot_dev_password@127.0.0.1:5433/devpilot
Run migrations:
alembic upgrade head
Start API:
uvicorn main:app --reload --port 8000
API:
http://127.0.0.1:8000
Swagger documentation:
OpenAPI:
http://127.0.0.1:8000/openapi.json
Frontend Setup
cd frontend
npm install
npm run dev
Testing

Backend health check:
curl http://127.0.0.1:8000/health
Security Principles

DevPilot is being designed with production engineering practices in mind.

Planned security controls include:

Authentication
Role-Based Access Control
API rate limiting
Input validation
Repository access controls
Secret management
Audit logging
Secure worker isolation
Dependency scanning
Static Application Security Testing (SAST)
⚙️ Engineering Principles

DevPilot follows several engineering principles:

Separation of Concerns

Frontend, API, workers, analysis engine, and persistence remain independently maintainable.

API-First Design

Backend functionality is exposed through versionable APIs.

Asynchronous Processing

Long-running repository analysis should not block API requests.

Database Migrations

Schema changes are managed through Alembic migrations.

Containerized Infrastructure

Development infrastructure is reproducible through Docker.

Observability

Future versions will include:

Structured logging
Metrics
Distributed tracing
Scan execution metrics
Error tracking
🗺️ Roadmap
Phase 1 — Foundation
 Repository initialization
 Next.js frontend
 FastAPI backend
 PostgreSQL
 SQLAlchemy
 Alembic migrations
 User API
 Project API
 Repository API
 Scan API
Phase 2 — Code Intelligence
 Repository cloning
 File discovery
 AST parsing
 Static analysis
 Security rules
 Code quality analysis
 Finding generation
Phase 3 — AI Developer Copilot
 LLM integration
 Code explanations
 Root-cause analysis
 Fix suggestions
 Repository Q&A
 RAG pipeline
 Context-aware AI
Phase 4 — Developer Experience
 Dashboard
 Scan history
 Finding explorer
 Code viewer
 Severity filters
 Risk trends
 Pull request reviews
Phase 5 — Production
 Authentication
 RBAC
 Redis
 Background workers
 GitHub OAuth
 GitHub webhooks
 CI/CD
 Observability
 Rate limiting
 Production deployment
📊 Future Developer Workflow

Eventually, a developer will be able to:
Connect GitHub
      ↓
Select Repository
      ↓
Start Scan
      ↓
DevPilot analyzes code
      ↓
AI understands findings
      ↓
Developer receives:
      │
      ├── Risk Score
      ├── Security Issues
      ├── Bugs
      ├── Code Smells
      ├── Performance Issues
      └── AI Fix Suggestions
Long-Term Goal

DevPilot is being built toward an AI-native software engineering platform rather than a simple code scanner.

The long-term goal is to help developers move from:
Write Code
    ↓
Find Problems
    ↓
Understand Problems
    ↓
Fix Problems
    ↓
Ship Software
to:
Write → Analyze → Understand → Fix → Review → Ship
                         ↑
                    AI Copilot
Project Status

Status: 🚧 Active Development

DevPilot is currently in the foundational backend/API stage.

The architecture is intentionally designed to evolve from a simple CRUD-based backend into a distributed code intelligence platform with asynchronous analysis and AI-powered developer workflows.

👨‍💻 Author

MD Rahil

B.Tech Computer Science & Engineering

Building toward AI-powered developer tools and intelligent software engineering systems.

⭐ Why DevPilot?

DevPilot demonstrates practical engineering across:

Full-stack development
REST API design
Database architecture
PostgreSQL
SQLAlchemy
Database migrations
Docker
Distributed systems
Static code analysis
AI engineering
Developer tooling
Software architecture
Production engineering
📜 License

License will be added as the project matures.
