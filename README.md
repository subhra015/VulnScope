# VulnScope — Intelligent Application Security & Dependency Risk Analyzer

[![VulnScope CI](https://github.com/vulnscope/vulnscope/actions/workflows/ci.yml/badge.svg)](https://github.com/vulnscope/vulnscope/actions/workflows/ci.yml)
[![Phase](https://img.shields.io/badge/Phase-1%3A%20Foundation-emerald)](https://github.com/vulnscope/vulnscope)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI%20%7C%20Python%203.11%2B-009688)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/Frontend-React%2018%2B%20%7C%20Vite%20%7C%20TypeScript-61dafb)](https://react.dev)
[![Database](https://img.shields.io/badge/Database-SQLite%20%7C%20SQLAlchemy%202.x-003B57)](https://www.sqlalchemy.org)

---

## 1. Project Overview & Problem Statement

Modern software applications rely heavily on open-source dependencies, third-party libraries, and rapid development cycles. However, development teams often face major application security challenges:
- Insecure coding patterns and vulnerabilities (e.g., SQL injection, SSRF, broken access control).
- Accidental exposure of secrets, tokens, and cryptographic keys in source code.
- Known Common Vulnerabilities and Exposures (CVEs) in transitive dependencies.
- Alert fatigue caused by disjointed scanning tools that lack unified risk prioritization and scan-to-scan regression tracking.

**VulnScope** is an Intelligent Application Security and Dependency Risk Analyzer built to solve these problems by integrating static application security testing (SAST via Semgrep), secrets detection (via Gitleaks), and software composition analysis (SCA via the OSV API/OSV-Scanner) into a unified developer dashboard.

---

## 2. Current Implementation Status: Phase 1 Only

> [!IMPORTANT]
> **Phase 1 represents the architectural foundation of VulnScope.**
> In this phase:
> - **No automated security scanners are executed.**
> - **No repository cloning or ZIP archive file unpacking occurs.**
> - Creating a scan record creates a database record with honest initial status `created`.
> - The application security scanning engine, file intake workers, and finding aggregators will be introduced in subsequent phases.

---

## 3. Technology Stack

### Backend
- **Python 3.11+ / 3.13**
- **FastAPI 0.115+**: High-performance asynchronous REST API framework
- **Pydantic 2.x & pydantic-settings**: Strict request/response validation and environment configuration
- **SQLAlchemy 2.x**: Object-Relational Mapping (ORM) with type-annotated mapped columns and UTC-aware datetime handlers
- **Alembic**: Database migrations and schema version control
- **Uvicorn**: ASGI web server

### Frontend
- **React 18 / 19**
- **Vite 5+**: Fast modern frontend bundler
- **TypeScript 5+**: Type-safe development
- **Tailwind CSS v4**: Responsive, dark-themed security operations dashboard styling
- **Lucide React**: Clean iconography

### Database
- **SQLite**: Local relational database with configurable file path and automatic directory provisioning

### Testing & CI
- **Pytest 8+ & FastAPI TestClient**: Automated backend tests using isolated in-memory SQLite instances
- **TypeScript `tsc` & Vite Build**: Static type checking and production build verification
- **GitHub Actions**: Automated continuous integration workflow

---

## 4. Project Directory Structure

```text
VulnScope/
├── .github/
│   └── workflows/
│       └── ci.yml               # GitHub Actions CI workflow
├── backend/
│   ├── app/
│   │   ├── api/                 # API route handlers
│   │   │   ├── __init__.py      # Aggregated API router
│   │   │   ├── health.py        # Health-check & DB ping endpoint
│   │   │   └── scans.py         # Scan listing, creation, and inspection
│   │   ├── core/                # Core configuration & settings
│   │   │   ├── __init__.py
│   │   │   └── config.py        # Pydantic BaseSettings & path resolution
│   │   ├── db/                  # Database connectivity & session management
│   │   │   ├── __init__.py
│   │   │   └── session.py       # Engine, SessionLocal, get_db dependency
│   │   ├── models/              # SQLAlchemy 2.x ORM models
│   │   │   ├── __init__.py
│   │   │   ├── base.py          # Base declarative class & UTCDateTime decorator
│   │   │   ├── repository.py    # Repository database model
│   │   │   ├── scan.py          # Scan database model
│   │   │   └── finding.py       # Finding database model (Phase 3 schema)
│   │   ├── schemas/             # Pydantic request & response contracts
│   │   │   ├── __init__.py
│   │   │   ├── health.py        # Health response schema
│   │   │   ├── scan.py          # Scan creation & response schemas
│   │   │   └── finding.py       # Finding response schema
│   │   ├── main.py              # FastAPI application entry point & lifespan
│   │   └── config.py            # Backward-compatibility alias
│   ├── data/                    # SQLite database storage directory
│   │   └── vulnscope.db         # Persistent SQLite database file
│   ├── migrations/              # Alembic database migration scripts
│   │   ├── versions/            # Migration revisions (0001 initial schema)
│   │   └── env.py               # Alembic runner configuration
│   ├── tests/                   # Automated backend test suite
│   │   ├── __init__.py
│   │   ├── conftest.py          # Isolated in-memory SQLite fixtures & TestClient
│   │   ├── test_health.py       # Health check tests
│   │   ├── test_models.py       # ORM model relationship & cascade tests
│   │   └── test_scans.py        # Scan CRUD and validation rejection tests
│   ├── alembic.ini              # Alembic CLI configuration
│   ├── requirements.txt         # Backend Python dependencies
│   └── .env.example             # Backend environment template
├── frontend/
│   ├── public/                  # Static assets & SVG favicon
│   ├── src/
│   │   ├── components/          # Reusable dashboard UI components
│   │   │   ├── CreateScanForm.tsx   # Scan record creation form
│   │   │   ├── Header.tsx           # Dashboard top bar & connection badge
│   │   │   ├── ScanDetailsModal.tsx # Scan record inspector & raw JSON viewer
│   │   │   ├── ScansTable.tsx       # Scans audit table & empty state
│   │   │   ├── Sidebar.tsx          # Navigation sidebar & phase badges
│   │   │   ├── StatusBadge.tsx      # Color-coded status badge
│   │   │   └── SummaryCards.tsx     # Metrics cards (scans, findings)
│   │   ├── pages/
│   │   │   └── Dashboard.tsx    # Primary dashboard layout
│   │   ├── services/
│   │   │   └── api.ts           # Centralized API service & typed fetch client
│   │   ├── types/
│   │   │   └── index.ts         # TypeScript domain types & API interfaces
│   │   ├── App.tsx              # Root application component
│   │   ├── index.css            # Tailwind CSS v4 styling
│   │   ├── main.tsx             # React DOM entry point
│   │   └── vite-env.d.ts        # Vite environment type declarations
│   ├── package.json             # Frontend npm dependencies and scripts
│   ├── tsconfig.json            # TypeScript project references
│   ├── tsconfig.app.json        # Frontend application TS configuration
│   ├── vite.config.ts           # Vite build configuration
│   ├── .env.example             # Frontend environment template
│   └── .env                     # Local environment configuration
├── .gitignore                   # Multi-language Git ignore rules
├── .env.example                 # Root environment template
└── README.md                    # Project documentation
```

---

## 5. Prerequisites

Before running VulnScope, verify that the following tools are installed on your machine:
- **Python**: 3.11 or higher (`python --version`)
- **Node.js**: 18.x, 20.x, or higher (`node --version`)
- **npm**: 9.x or higher (`npm --version`)
- **Git**: 2.x or higher (`git --version`)

---

## 6. Setup Instructions (Windows PowerShell & VS Code)

### Step 1: Open Terminal in the Project Root
```powershell
cd d:\Projects\VulnScope
```

### Step 2: Configure Environment Variables
Copy `.env.example` templates to `.env` in both `backend` and `frontend`:
```powershell
# In backend
Copy-Item backend\.env.example backend\.env

# In frontend
Copy-Item frontend\.env.example frontend\.env
```

---

## 7. Python Virtual Environment Setup

To keep dependencies isolated:
```powershell
cd d:\Projects\VulnScope\backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

*(If PowerShell script execution is restricted, run: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`)*

---

## 8. Backend Dependency Installation and Launch Commands

### Install Dependencies
```powershell
cd d:\Projects\VulnScope\backend
pip install -r requirements.txt
```

### Run Database Migrations (Alembic)
```powershell
alembic upgrade head
```

### Start the Backend Server
```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

The backend will start at:
- **Base API URL**: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Interactive OpenAPI/Swagger Documentation**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc Documentation**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)
- **Health Check**: [http://127.0.0.1:8000/api/health](http://127.0.0.1:8000/api/health)

---

## 9. Frontend Dependency Installation and Launch Commands

In a separate terminal window:
```powershell
cd d:\Projects\VulnScope\frontend
npm install
npm run dev
```

The frontend dashboard will be available at:
- **Local Dashboard URL**: [http://localhost:5173](http://localhost:5173)

---

## 10. Configuration Details (`.env.example`)

### Backend Settings (`backend/.env`)
| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `DEBUG` | `false` | Enables verbose SQL logging and FastAPI debug mode. |
| `APP_NAME` | `"VulnScope API"` | Application title shown in OpenAPI documentation. |
| `APP_VERSION` | `"0.1.0"` | Current version string. |
| `FRONTEND_ORIGIN` | `"http://localhost:5173,http://127.0.0.1:5173"` | Comma-separated CORS allowed origins. |
| `DATABASE_URL` | `"sqlite:///./data/vulnscope.db"` | Path to the SQLite database. |

### Frontend Settings (`frontend/.env`)
| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `VITE_API_BASE_URL` | `http://localhost:8000` | Target URL for the FastAPI backend API. |

---

## 11. SQLite Database & Migrations

- **Database Location**: Resolved automatically to `backend/data/vulnscope.db` regardless of the directory from which the application is started.
- **Auto-provisioning**: If started without migrations, FastAPI's application lifespan automatically creates missing tables via SQLAlchemy metadata.
- **Alembic Commands**:
  - Run all pending migrations: `alembic upgrade head`
  - Revert last migration: `alembic downgrade -1`
  - Check current revision status: `alembic current`
  - Generate a new migration after schema changes: `alembic revision --autogenerate -m "description"`

---

## 12. API Endpoint Specifications

### `GET /api/health`
Verifies backend operational status and active SQLite database connectivity.
- **Response `200 OK`**:
```json
{
  "status": "healthy",
  "service": "vulnscope-api",
  "version": "0.1.0",
  "database": "connected"
}
```

### `GET /api/scans`
Lists all scan records, ordered by creation timestamp in descending order (newest first). Returns an empty array `[]` when no records exist.
- **Response `200 OK`**:
```json
[
  {
    "id": "5c9ce5be-5d19-4709-ba5c-206efe111fa6",
    "project_name": "auth-service",
    "source_type": "github",
    "source_reference": "https://github.com/my-org/auth-service",
    "status": "created",
    "created_at": "2026-10-22T07:25:44.684742Z",
    "started_at": null,
    "completed_at": null,
    "error_summary": null
  }
]
```

### `POST /api/scans`
Creates a new scan record in the database with initial status `created`.
- **Request Body**:
```json
{
  "project_name": "auth-service",
  "source_type": "github",
  "source_reference": "https://github.com/my-org/auth-service"
}
```
- **Validation**:
  - `project_name`: Required, non-empty string (1–255 characters).
  - `source_type`: Must be `"github"` or `"zip"`.
  - `source_reference`: Optional string (max 500 characters).
- **Response `201 Created`**:
```json
{
  "id": "5c9ce5be-5d19-4709-ba5c-206efe111fa6",
  "project_name": "auth-service",
  "source_type": "github",
  "source_reference": "https://github.com/my-org/auth-service",
  "status": "created",
  "created_at": "2026-10-22T07:25:44.684742Z",
  "started_at": null,
  "completed_at": null,
  "error_summary": null
}
```

### `GET /api/scans/{scan_id}`
Retrieves a specific scan record and its associated findings.
- **Response `200 OK`**:
```json
{
  "id": "5c9ce5be-5d19-4709-ba5c-206efe111fa6",
  "project_name": "auth-service",
  "source_type": "github",
  "source_reference": "https://github.com/my-org/auth-service",
  "status": "created",
  "created_at": "2026-10-22T07:25:44.684742Z",
  "started_at": null,
  "completed_at": null,
  "error_summary": null,
  "repository_id": "806ed2bc-4bd1-4144-ad24-943c242c6bf0",
  "findings": []
}
```
- **Response `404 Not Found`** (if `scan_id` does not exist):
```json
{
  "detail": "Scan record with ID 'unknown-id' not found"
}
```

---

## 13. Running Automated Tests & Verification

### Run Backend Tests
Backend tests run against an isolated in-memory SQLite database (`sqlite:///:memory:`) and do not touch your persistent database.
```powershell
cd d:\Projects\VulnScope\backend
python -m pytest -v
```

### Run Frontend Build Verification
Verifies TypeScript compilation and builds static assets:
```powershell
cd d:\Projects\VulnScope\frontend
npm run build
```

---

## 14. Known Limitations in Phase 1

1. **Scan Execution**: Scans remain in status `created`. No source code is acquired, cloned, or scanned yet.
2. **ZIP File Uploads**: The UI and API accept `zip` as a source type and record metadata, but file streaming/storage is deferred to Phase 2.
3. **GitHub Token Authentication**: Private GitHub repositories requiring OAuth or Personal Access Tokens are not yet handled.
4. **Findings**: The findings table schema is established and tested with cascading deletes, but no real scanner findings exist yet.

---

## 15. Roadmap: Future Implementation Phases

- **Phase 2: Secure Repository & ZIP Intake**
  - Implement isolated worker processes for secure git shallow cloning.
  - Implement secure ZIP decompression with strict zip-slip and bomb protection.
  - Ephemeral sandbox directory management with automatic cleanup.
- **Phase 3: Multi-Engine Security Scanning**
  - Integrate **Semgrep** rulesets for OWASP Top 10 SAST.
  - Integrate **Gitleaks** for high-entropy secrets and credential detection.
  - Integrate **OSV-Scanner / OSV API** for dependency vulnerability analysis.
  - Normalize scanner outputs into the unified `Finding` model with fingerprinting.
- **Phase 4: Risk Prioritization & Remediation**
  - Compute composite risk scores based on severity and exploitability.
  - Scan-to-scan regression tracking (new vs. fixed findings).
  - Automated remediation suggestions.
- **Phase 5: Reporting & CI/CD Integrations**
  - PDF/JSON/SARIF report generation.
  - GitHub Actions & GitLab CI integrations with threshold gating.
