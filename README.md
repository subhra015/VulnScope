# VulnScope — Intelligent Application Security & Dependency Risk Analyzer

[![VulnScope CI](https://github.com/vulnscope/vulnscope/actions/workflows/ci.yml/badge.svg)](https://github.com/vulnscope/vulnscope/actions/workflows/ci.yml)
[![Phase](https://img.shields.io/badge/Phase-2%3A%20Secure%20Intake-emerald)](https://github.com/vulnscope/vulnscope)
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

**VulnScope** is an Intelligent Application Security and Dependency Risk Analyzer designed to integrate static application security testing (SAST via Semgrep), secrets detection (via Gitleaks), and software composition analysis (SCA via the OSV API/OSV-Scanner) into a unified developer dashboard.

---

## 2. Implementation Status: Phase 2 — Secure Repository & ZIP Intake

> [!IMPORTANT]
> **Phase 2 delivers secure source acquisition, safe archive extraction, and isolated workspace management.**
> In this phase:
> - **Source code is strictly acquired and staged; NO SUBMITTED CODE IS EXECUTED.**
> - **No project dependencies, npm packages, pip requirements, or build scripts are invoked.**
> - ZIP archives are streamed directly to disk, inspected for malicious path traversal, zip bombs, and symlinks, and unpacked into isolated workspaces.
> - Public GitHub repository snapshots are acquired via a constrained HTTP client protected by pre-flight DNS SSRF validation and redirect filtering.
> - A distinct intake lifecycle (`created` → `ingesting` → `ready` or `failed`) tracks source acquisition independently from the eventual security scan status.
> - Multi-engine security scanners (Semgrep, Gitleaks, OSV) and vulnerability scoring will be executed in Phase 3.

---

## 3. Threat Model & Security Controls

VulnScope treats all ingested source code and archive files as untrusted. The following defense-in-depth protections are enforced:

| Threat Category | Attack Vector | VulnScope Mitigation |
| :--- | :--- | :--- |
| **Zip Slip** | Archive entries with `../`, `..\`, absolute paths (`/etc/passwd`, `C:\`), or null bytes. | Sanitizes and normalizes path separators, rejects traversal tokens (`..`, `.`), validates that every resolved entry path strictly remains within the designated workspace, and rejects null bytes. |
| **Zip Bomb** | Small compressed payloads expanding into hundreds of gigabytes (e.g. 42.zip). | Enforces strict maximum expanded size (`150 MB`), maximum file count (`2000`), maximum single file size (`25 MB`), max directory nesting depth (`10`), and rejects excessive compression ratios (> 100:1). Decompression bytes are tracked dynamically during streaming. |
| **Symlink Attacks** | Symbolic links, FIFOs, sockets, or device nodes targeting host system files. | Inspects Unix file mode attributes in ZIP headers (`external_attr`). Rejects symlinks (`S_IFLNK`), FIFOs (`S_IFIFO`), character/block devices, and sockets. |
| **Duplicate / Conflicting Paths** | Archive entries conflicting in type or attempting case-insensitive collision. | Normalizes paths and tracks seen entries case-insensitively; rejects duplicate paths or attempts to write files into paths registered as directories (and vice-versa). |
| **Server-Side Request Forgery (SSRF)** | User requests targeting localhost, 127.0.0.1, AWS metadata `169.254.169.254`, or internal RFC1918 networks (`10.0.0.0/8`, `192.168.0.0/16`). | Rejects non-HTTPS schemes; restricts entry hosts to `github.com` and `www.github.com`; restricts download hosts to approved GitHub domains; performs pre-flight DNS address resolution ensuring all resolved IPs are public/global internet addresses. |
| **Unrestricted Redirects** | Initial GitHub URL redirecting to an attacker-controlled external host or internal endpoint. | Manually follows redirects (max 3 hops) and enforces full SSRF and approved-host verification on every redirect target before connecting. |
| **Resource Exhaustion** | Unlimited file uploads or runaway download streams exhausting disk or memory. | Streams multipart uploads and HTTP downloads in 64 KB chunks, rejecting requests immediately when size thresholds are exceeded. Enforces connect (10s) and read (30s) timeouts. |
| **Cross-Job Contamination** | Intake jobs overwriting or accessing files from other scans. | Allocates cryptographically secure UUIDv4 workspace subdirectories. Validates UUIDs strictly to prevent path manipulation. Restricts filesystem permissions (`0o700` where supported). |

---

## 4. Source Intake Lifecycle

The intake lifecycle remains distinct from the eventual security scan status:

```text
[Source Submission]
        │
        ▼
   status: "created"
   intake_status: "ingesting"  ──(On Error)──► status: "failed"
        │                                      intake_status: "failed"
        ▼                                      error_summary: "<sanitized error>"
   (Validation & Extraction)
        │
        ▼
   status: "created"          (Scan has NOT yet run; will be queued in Phase 3)
   intake_status: "ready"     (Source is safely extracted and verified in workspace)
   error_summary: null
```

---

## 5. Technology Stack

### Backend
- **Python 3.11+ / 3.13**
- **FastAPI 0.115+**: High-performance asynchronous REST API framework
- **Pydantic 2.x & pydantic-settings**: Strict request/response validation and environment configuration
- **SQLAlchemy 2.x**: Object-Relational Mapping (ORM) with type-annotated mapped columns and UTC-aware datetime handlers
- **Alembic**: Database migrations and schema version control
- **HTTPX**: Constrained asynchronous/synchronous HTTP client with bounded streaming
- **Uvicorn**: ASGI web server

### Frontend
- **React 18 / 19**
- **Vite 5 / 6**: Fast modern frontend bundler
- **TypeScript 5+**: Type-safe development
- **Tailwind CSS v4**: Responsive, dark-themed security operations dashboard styling
- **Lucide React**: Clean iconography

### Database & Storage
- **SQLite**: Local relational database with configurable file path and automatic directory provisioning
- **Workspace Storage**: Dedicated local directory (`backend/data/workspaces/<uuid>/source`)

---

## 6. Project Directory Structure

```text
VulnScope/
├── backend/
│   ├── app/
│   │   ├── api/                 # API route handlers
│   │   │   ├── __init__.py      # Aggregated API router
│   │   │   ├── health.py        # Health-check & DB ping endpoint
│   │   │   ├── intake.py        # Phase 2: Secure ZIP & GitHub intake endpoints
│   │   │   └── scans.py         # Scan listing, creation, and inspection
│   │   ├── core/                # Core configuration & settings
│   │   │   ├── __init__.py
│   │   │   └── config.py        # Pydantic BaseSettings & configurable limits
│   │   ├── db/                  # Database connectivity & session management
│   │   │   ├── __init__.py
│   │   │   └── session.py       # Engine, SessionLocal, get_db dependency
│   │   ├── models/              # SQLAlchemy 2.x ORM models
│   │   │   ├── __init__.py
│   │   │   ├── base.py          # Base declarative class & UTCDateTime decorator
│   │   │   ├── repository.py    # Repository database model
│   │   │   ├── scan.py          # Scan model with intake_status & workspace_id
│   │   │   └── finding.py       # Finding database model (Phase 3 schema)
│   │   ├── schemas/             # Pydantic request & response contracts
│   │   │   ├── __init__.py
│   │   │   ├── health.py        # Health response schema
│   │   │   ├── intake.py        # GitHub intake request schema
│   │   │   ├── scan.py          # Scan creation & response schemas
│   │   │   └── finding.py       # Finding response schema
│   │   ├── services/            # Core business logic & security services
│   │   │   ├── __init__.py
│   │   │   ├── archive.py       # SafeArchiveValidator (traversal, bomb, symlink checks)
│   │   │   ├── github.py        # GithubIntakeService (SSRF defense, streaming download)
│   │   │   └── workspace.py     # WorkspaceManager (UUID sandboxes, cleanup)
│   │   └── main.py              # FastAPI application entry point & lifespan
│   ├── data/                    # SQLite database storage & workspace sandboxes
│   │   ├── vulnscope.db         # Persistent SQLite database file
│   │   └── workspaces/          # Isolated source code intake sandboxes (UUID folders)
│   ├── migrations/              # Alembic database migration scripts
│   │   ├── versions/            # Migration revisions (0001 initial, 0002 intake fields)
│   │   └── env.py               # Alembic runner configuration
│   ├── tests/                   # Automated backend test suite
│   │   ├── __init__.py
│   │   ├── conftest.py          # Isolated in-memory SQLite fixtures & TestClient
│   │   ├── test_archive.py      # 14 ZIP security and archive edge case tests
│   │   ├── test_github_intake.py# 13 GitHub intake, SSRF, and redirect security tests
│   │   ├── test_health.py       # Health check tests
│   │   ├── test_models.py       # ORM model relationship & cascade tests
│   │   └── test_scans.py        # Scan CRUD and validation rejection tests
│   ├── alembic.ini              # Alembic CLI configuration
│   ├── requirements.txt         # Backend Python dependencies
│   └── .env.example             # Backend environment template
├── frontend/
│   ├── src/
│   │   ├── components/          # Reusable dashboard UI components
│   │   │   ├── CreateScanForm.tsx   # Dual GitHub / ZIP intake submission form
│   │   │   ├── Header.tsx           # Dashboard top bar & connection badge
│   │   │   ├── ScanDetailsModal.tsx # Record inspector with intake & workspace state
│   │   │   ├── ScansTable.tsx       # Scans audit table showing dual statuses
│   │   │   ├── Sidebar.tsx          # Navigation sidebar & phase badges
│   │   │   ├── StatusBadge.tsx      # Dual intake and scan status badges
│   │   │   └── SummaryCards.tsx     # Metrics cards
│   │   ├── services/
│   │   │   └── api.ts           # Centralized API service (multipart & JSON intake)
│   │   ├── types/
│   │   │   └── index.ts         # TypeScript domain types & API interfaces
│   │   ├── App.tsx              # Root application component
│   │   └── main.tsx             # React DOM entry point
│   └── package.json             # Frontend npm dependencies and scripts
└── README.md                    # Project documentation
```

---

## 7. Configurable Security Limits (`backend/.env`)

All limits are configurable via environment variables in `backend/.env`:

| Setting | Environment Variable | Default Value | Description |
| :--- | :--- | :--- | :--- |
| **Workspace Storage** | `WORKSPACES_DIR` | `./data/workspaces` | Directory where isolated intake sandboxes are created. |
| **Max Compressed Upload** | `MAX_UPLOAD_SIZE_BYTES` | `52428800` (50 MB) | Maximum size of an uploaded ZIP archive file. |
| **Max Expanded Size** | `MAX_EXPANDED_SIZE_BYTES` | `157286400` (150 MB) | Maximum cumulative uncompressed size of extracted files. |
| **Max File Count** | `MAX_FILE_COUNT` | `2000` | Maximum number of files and directories permitted in an archive. |
| **Max Single File Size** | `MAX_FILE_SIZE_BYTES` | `26214400` (25 MB) | Maximum uncompressed size for any individual file. |
| **Max Directory Depth** | `MAX_DIRECTORY_DEPTH` | `10` | Maximum permitted subfolder nesting depth. |
| **Max Compression Ratio** | `MAX_COMPRESSION_RATIO` | `100.0` | Zip bomb protection: uncompressed-to-compressed ratio ceiling. |
| **GitHub Connect Timeout** | `GITHUB_CONNECT_TIMEOUT_SECONDS`| `10.0` | Timeout in seconds for establishing connection to GitHub. |
| **GitHub Read Timeout** | `GITHUB_READ_TIMEOUT_SECONDS` | `30.0` | Timeout in seconds for reading chunks from GitHub. |
| **Max GitHub Download** | `MAX_GITHUB_DOWNLOAD_SIZE_BYTES`| `52428800` (50 MB) | Maximum snapshot download size allowed from GitHub. |
| **Workspace Retention** | `WORKSPACE_RETENTION_HOURS` | `24` | Automated cleanup threshold for stale completed workspaces. |

---

## 8. API Endpoint Specifications

### `POST /api/intake/zip`
Uploads and validates a source code ZIP archive via multipart form-data.

- **Request Headers**: `Content-Type: multipart/form-data`
- **Form Parameters**:
  - `file`: Required. The ZIP file to upload.
  - `project_name`: Optional string (1–255 characters). Defaults to archive stem.
- **Response `201 Created`**:
```json
{
  "id": "e2f494a8-6b19-4f76-857c-cbef4428df95",
  "project_name": "my-service",
  "source_type": "zip",
  "source_reference": "my-service.zip",
  "status": "created",
  "intake_status": "ready",
  "created_at": "2026-10-22T15:20:00Z",
  "started_at": null,
  "completed_at": null,
  "error_summary": null
}
```

#### Example: Windows PowerShell
```powershell
$filePath = ".\sample-project.zip"
$boundary = [System.Guid]::NewGuid().ToString()
$fileBytes = [System.IO.File]::ReadAllBytes($filePath)
$fileContent = [System.Text.Encoding]::GetEncoding("iso-8859-1").GetString($fileBytes)

$body = @"
--$boundary
Content-Disposition: form-data; name="project_name"

my-service
--$boundary
Content-Disposition: form-data; name="file"; filename="sample-project.zip"
Content-Type: application/zip

$fileContent
--$boundary--
"@

Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/intake/zip" `
  -Method Post `
  -ContentType "multipart/form-data; boundary=$boundary" `
  -Body $body
```

#### Example: cURL
```bash
curl -X POST http://127.0.0.1:8000/api/intake/zip \
  -F "project_name=my-service" \
  -F "file=@sample-project.zip"
```

---

### `POST /api/intake/github`
Acquires a public GitHub repository snapshot using constrained HTTP streaming.

- **Request Headers**: `Content-Type: application/json`
- **Request Body**:
```json
{
  "repo_url": "https://github.com/owner/repository",
  "project_name": "custom-name",
  "ref": "main"
}
```
- **Validation**:
  - `repo_url`: Required. Must begin with `https://github.com/owner/repo`. No credentials, non-standard ports, or private addresses.
  - `project_name`: Optional. Defaults to repository name.
  - `ref`: Optional git branch, tag, or commit SHA.
- **Response `201 Created`**:
```json
{
  "id": "93b2184a-7bc9-4b69-8d76-b6ae4949b271",
  "project_name": "custom-name",
  "source_type": "github",
  "source_reference": "https://github.com/owner/repository@main",
  "status": "created",
  "intake_status": "ready",
  "created_at": "2026-10-22T15:21:00Z",
  "started_at": null,
  "completed_at": null,
  "error_summary": null
}
```

#### Example: Windows PowerShell
```powershell
$payload = @{
    repo_url = "https://github.com/pallets/flask"
    project_name = "flask-core"
    ref = "main"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/intake/github" `
  -Method Post `
  -ContentType "application/json" `
  -Body $payload
```

#### Example: cURL
```bash
curl -X POST http://127.0.0.1:8000/api/intake/github \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/pallets/flask", "project_name": "flask-core", "ref": "main"}'
```

---

### `GET /api/scans`
Lists all scan records, showing both `status` (security scan status) and `intake_status` (source intake status).

- **Response `200 OK`**:
```json
[
  {
    "id": "93b2184a-7bc9-4b69-8d76-b6ae4949b271",
    "project_name": "flask-core",
    "source_type": "github",
    "source_reference": "https://github.com/pallets/flask@main",
    "status": "created",
    "intake_status": "ready",
    "created_at": "2026-10-22T15:21:00Z",
    "started_at": null,
    "completed_at": null,
    "error_summary": null
  }
]
```

---

### `GET /api/scans/{scan_id}`
Retrieves details for a specific scan, including associated `workspace_id` (UUID only; internal filesystem paths are omitted).

---

## 9. Windows PowerShell Setup & Execution Guide

### Prerequisites
- Python 3.11+
- Node.js 18+ & npm
- Git

### Step 1: Open Terminal in Project Root
```powershell
cd d:\Projects\VulnScope
```

### Step 2: Configure Environment
```powershell
Copy-Item backend\.env.example backend\.env
Copy-Item frontend\.env.example frontend\.env
```

### Step 3: Backend Setup & Migrations
```powershell
cd d:\Projects\VulnScope\backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
alembic upgrade head
```

### Step 4: Run Automated Tests
```powershell
cd d:\Projects\VulnScope\backend
python -m pytest -v
```

### Step 5: Start Backend Server
```powershell
cd d:\Projects\VulnScope\backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### Step 6: Start Frontend (In a New PowerShell Window)
```powershell
cd d:\Projects\VulnScope\frontend
npm install
npm run dev
```

The frontend dashboard is available at: [http://localhost:5173](http://localhost:5173)

---

## 10. Workspace Storage & Cleanup Policy

1. **Storage Location**: Workspaces are staged in `backend/data/workspaces/<workspace_id>/source`, strictly isolated from web-accessible directories.
2. **On-Failure Cleanup**: Any intake job that fails (archive traversal, bomb, oversized download, network timeout, corrupt zip) automatically deletes the entire workspace directory immediately.
3. **Audit Integrity**: The SQLite database record is updated to `intake_status="failed"` and `status="failed"` with a sanitized error summary; the failed workspace directory is removed.
4. **Housekeeping Policy**: The `cleanup_stale_workspaces` utility cleans up completed workspaces older than `WORKSPACE_RETENTION_HOURS` (default: 24h) while never deleting database files or configuration directories.

---

## 11. Known Limitations in Phase 2

1. **Private GitHub Repositories**: Only public repositories are supported in this phase. GitHub Personal Access Tokens and OAuth flows are not yet supported.
2. **Tarballs / Git Clone**: Only ZIP snapshots are unpacked; raw `.tar.gz` and `.git` shallow clones are not accepted.
3. **Security Scanners**: Semgrep SAST, Gitleaks, and OSV SCA scanner workers will be introduced in Phase 3.
