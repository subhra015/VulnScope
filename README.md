# VulnScope — Intelligent Application Security & Dependency Risk Analyzer

[![VulnScope CI](https://github.com/vulnscope/vulnscope/actions/workflows/ci.yml/badge.svg)](https://github.com/vulnscope/vulnscope/actions/workflows/ci.yml)
[![Phase](https://img.shields.io/badge/Phase-5%3A%20AI%20Remediation%20%26%20Reports-purple)](https://github.com/vulnscope/vulnscope)
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

## 11. Phase 3 — Real Security Scanner Engine

### Overview
Phase 3 integrates three production security analysis engines into a unified background pipeline:
1. **Semgrep** (Static Application Security Testing - SAST): Analyzes code for security flaws (e.g., SQL injection, insecure deserialization, command execution, broken crypto).
2. **Gitleaks** (Secret Detection): Scans snapshot files for exposed API tokens, private keys, access credentials, and webhooks.
3. **OSV-Scanner** (Software Composition Analysis - SCA): Identifies known CVEs and vulnerabilities in project lockfiles and dependency manifests (`requirements.txt`, `package-lock.json`, etc.).

---

### Security Safeguards & Threat Controls

| Threat | Safeguard Implemented |
| :--- | :--- |
| **Command Injection** | Subprocess commands are executed with `shell=False` as strict argument lists. No user input or file names are evaluated in shell contexts. |
| **Untrusted Code Execution** | **Zero untrusted repository code is executed.** No build scripts, test suites, `npm install`, `pip install`, or OSV call analysis (`--call-analysis`) are permitted. |
| **Credential & Secret Leakage** | Gitleaks matches, sensitive line contents, and raw secret values are **strictly scrubbed** and never saved to the database, logs, or API responses. Secret findings are represented as `"Potential exposed credential detected"`. |
| **Out-of-Tree Report Security** | Gitleaks output reports are generated **outside** the scanned source tree (in temporary directories or workspace root) and guaranteed to be deleted immediately after parsing. |
| **Resource Exhaustion** | Strict per-scanner execution timeouts (Semgrep: 120s, Gitleaks: 60s, OSV: 90s) and bounded process output capture (max 20 MB). Timed-out processes are automatically killed. |
| **Cross-Scan Contamination** | Concurrency semaphore enforces a maximum of concurrent scans (`MAX_CONCURRENT_SCANS=2`). Duplicate starts for an already active scan are rejected with HTTP 409 Conflict. |
| **Environment Variable Scrubbing** | Subprocesses run in a sanitized environment that excludes application secrets, API keys, database credentials, and internal paths. |

---

### Scanner CLI Installation & Verification

#### 1. Semgrep (SAST)
Installed via pip in Python 3.11+:
```powershell
pip install semgrep
semgrep --version
# Expected: 1.x (e.g. 1.182.1)
```

#### 2. Gitleaks (Secrets)
Download the Windows x64 binary from [Gitleaks GitHub Releases](https://github.com/gitleaks/gitleaks/releases):
```powershell
# Place in backend\tools\bin\gitleaks.exe
.\backend\tools\bin\gitleaks.exe version
# Expected: 8.x (e.g. 8.30.1)
```

#### 3. OSV-Scanner (SCA Dependencies)
Download the standalone binary from [OSV-Scanner GitHub Releases](https://github.com/google/osv-scanner/releases):
```powershell
# Place in backend\tools\bin\osv-scanner.exe
.\backend\tools\bin\osv-scanner.exe --version
# Expected: 2.x (e.g. 2.7.0)
```

Automatic discovery order:
1. `SEMGREP_BINARY_PATH`, `GITLEAKS_BINARY_PATH`, `OSV_SCANNER_BINARY_PATH` from `.env`
2. System `PATH`
3. Local `backend/tools/bin/<tool>.exe`
4. Python environment `Scripts/<tool>.exe`

If any scanner binary is missing, it is reported as `unavailable` with zero hardcoded findings fabricated.

---

### Scan Lifecycle States

```text
[Repository / ZIP Intake: ready]
              │
              ▼ (POST /api/scans/{id}/run)
       status: "running"
              │
    ┌─────────┴─────────┐
    ▼                   ▼
(All Scanners OK)   (At least 1 Succeeded,
    │                others Failed/Unavailable)
    ▼                   │
status: "completed"     ▼
                  status: "partial"
```

- **`completed`**: All configured scanners ran and succeeded (even if zero vulnerabilities were found).
- **`partial`**: At least one scanner succeeded, but one or more failed, timed out, or was unavailable.
- **`failed`**: All scanners failed or were unavailable, or an unrecoverable orchestration error occurred.

---

### Supported & Tested Ecosystems

- **Languages Tested (Semgrep)**: Python, JavaScript, TypeScript, Multi-language.
- **Dependency Formats (OSV-Scanner)**: `requirements.txt` (Python/PyPI), `package-lock.json` (npm/Node.js).
- **Secret Rules (Gitleaks)**: Slack Webhooks, GitHub Personal Access Tokens, AWS keys, generic credentials.

---

### Known Limitations

1. **Subprocess vs OS Containerization**: Subprocesses use `shell=False` and environment sanitization, but full operating system containerization (e.g. Docker / Linux namespaces) is outside Phase 3.
2. **Git History in Snapshot Archives**: Ingested ZIP archives and GitHub snapshot downloads do not contain full `.git` commit histories. Gitleaks therefore inspects the staged snapshot files rather than past historical commits.
3. **No Automatic Remediation**: Fixing code or upgrading dependencies in-place is deferred to future phases.

---

## 13. Phase 4 — Explainable Risk Prioritization, Remediation Guidance, and Finding Lifecycle

Phase 4 introduces an explainable, deterministic finding-risk prioritization engine, grounded remediation recommendations, finding lifecycle tracking across scans, and an interactive risk-centric inspection interface.

### 13.1 Deterministic Risk-Priority Engine

VulnScope computes an explainable, bounded risk priority score between `0` and `100` for every finding. The score is computed using deterministic Python logic without ungrounded heuristics or LLM hallucinations.

#### Scoring Formula & Weight Distribution

The final score aggregates four weighted dimensions:

$$\text{Risk Score} = \min\left(100, \max\left(0, \sum (\text{Component Raw Score} \times \text{Weight})\right)\right)$$

| Dimension | Weight | Raw Score Range | Description & Signals |
| :--- | :---: | :---: | :--- |
| **1. Base Severity / CVSS** | **50%** (0.50) | 0–100 | **Authoritative CVSS v3 base score** scaled directly ($score = \text{CVSS} \times 10$) when available for dependency findings to avoid double-counting. Otherwise maps scanner severity: Critical (95), High (80), Medium (50), Low (25), Info (10). Unspecified severity applies a conservative Medium baseline (50) with documented uncertainty. |
| **2. Detection Confidence** | **20%** (0.20) | 0–100 | Scanner-reported confidence level: High (95), Medium (70), Low (40). Absent confidence defaults to conservative 65.0 with missing evidence noted. |
| **3. Category & Exploitability Signal** | **20%** (0.20) | 0–100 | **Secret finding** (95: direct credential abuse risk / immediate blast radius). **Code finding** (85: high-impact patterns such as SQLi, RCE, command injection, SSRF, auth bypass, deserialization; 65: XSS/CORS/crypto; 45: standard rule). **Dependency** (75: unpatched / no fixed version known; 60: fixed version available; 55: general). |
| **4. Context & Actionability** | **10%** (0.10) | 0–100 | **Precision bonus**: pinpointed file & line (+20) or verified package coordinates (+15). Explicit asset context (e.g. verified public repository or flagged production asset) applies up to +10 modifier only when explicitly provided and persisted. |

#### Priority Tiers

- **`Critical`** (Score 85–100): Immediate danger or credential exposure; requires prompt mitigation.
- **`High`** (Score 70–84): Severe flaw or high-CVSS dependency with proven attack vector.
- **`Medium`** (Score 40–69): Moderate impact vulnerability, defensive flaw, or unverified confidence.
- **`Low`** (Score 0–39): Minor code quality notice, low severity finding, or informational item.

#### Explainability & Uncertainty Retention

Every score includes an explanation payload containing:
- `score`: integer 0–100
- `priority`: tier identifier
- `factors`: itemized breakdown of weights, raw scores, and point contributions
- `evidence`: raw input values used
- `reason`: concise human-readable summary
- `missing_evidence`: explicit caveats (e.g. missing CVSS, absent confidence, unknown asset context)

> [!NOTE]
> Scanner severity is kept separate from VulnScope's risk priority. Scanner severity is preserved intact and never overwritten. Risk priority scores reflect prioritization ranking based on available evidence and do not guarantee production exploitability.

---

### 13.2 Actionable Remediation Guidance

Remediation recommendations are category-specific, non-destructive, and strictly grounded in normalized finding data. VulnScope does **not** execute automated fixes or modify scanned code in this phase.

#### 1. SAST Code Findings (Semgrep)
- Leverages scanner rule metadata, CWE, and OWASP references.
- Contrasts unsafe implementation patterns with safer alternatives (e.g., parameterized queries vs string concatenation; `shell=False` argument lists vs shell invocation).
- Links exclusively to trusted security documentation (`owasp.org`, `cwe.mitre.org`, `nvd.nist.gov`, `semgrep.dev`).

#### 2. Secret Leak Findings (Gitleaks)
- Recommends immediate credential revocation and rotation at the issuing service.
- Guides migration to environment variables or enterprise secrets managers (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault).
- **Critical caveat**: explicitly explains that removing the secret from source code or rewriting Git history does **not** invalidate an exposed credential.
- **Data safety**: raw secret values are never revealed, persisted, or echoed in API responses.

#### 3. Dependency Findings (OSV-Scanner)
- Recommends upgrade to the specific fixed version **only** when verified advisory data exists.
- Warns developers to inspect changelogs for breaking changes and run regression tests before upgrading.
- When no fixed version is recorded, clearly states that no verified fix could be established and recommends compensating controls.

---

### 13.3 Finding Lifecycle & Scan Comparison

VulnScope compares findings between successive eligible scans of the same repository lineage without breaking historical records.

```text
[Target Scan Findings] ◄──────── Compare ────────► [Baseline Scan Findings]
          │                                                   │
          ├─ Matched unchanged ─────────────► "recurring"     │
          ├─ Matched with modified attrs ──► "changed"       │
          ├─ Not present in baseline ───────► "new"           │
          │                                                   │
          └─ Present in baseline, absent in target:           │
               ├─ Scanner completed successfully ─────────────┴─► "resolved"
               └─ Scanner failed / unavailable / omitted ──────┴─► "unconfirmed" (NO false resolution)
```

#### Lifecycle State Definitions
- **`new`**: Detected in target scan, not present in the eligible baseline scan.
- **`recurring`**: Finding persists across scans with identical core attributes.
- **`changed`**: Finding persists, but relevant evidence or attributes shifted (e.g. line number shift, severity change, package version upgrade, or fixed version update).
- **`resolved`**: Present in baseline, but absent from a complete, successful target scan where the relevant scanner ran and succeeded.
- **`unconfirmed`**: Baseline finding absent in target scan, but the relevant scanner failed or was unavailable; cannot confirm resolution.

#### Comparability Prerequisites & Prohibitions
1. **Unrelated Repositories**: Scans from different repositories or projects are **never** compared (rejected with HTTP 400).
2. **Ineligible States**: Scans still queued, running, or failed cannot serve as valid baselines.
3. **No False Resolution**: If a scanner fails or is unavailable in the target scan, associated baseline findings are flagged as `unconfirmed` rather than `resolved`. A missing finding does not prove a fix if scanner coverage was partial.

---

### 13.4 Phase 4 API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/scans/{id}/findings` | List findings with priority sorting (`sort_by=priority`), filters (priority, scanner, category, severity), pagination, and lifecycle annotation. |
| `GET` | `/api/scans/{id}/findings/{finding_id}` | Retrieve single finding with full deterministic score explanation, factor breakdown, and structured remediation guidance. |
| `GET` | `/api/scans/{id}/risk-summary` | Retrieve scan risk distribution (Critical, High, Medium, Low), mean/max scores, category averages, and scanner coverage notes. |
| `GET` | `/api/scans/{id}/comparison/{baseline_id}` | Compare target scan against an eligible baseline scan of the same repository lineage. |

---

### 13.5 Database Migrations

Apply the database migrations including Phase 4 risk scoring and Phase 5 remediation proposals:
```powershell
python -m alembic -c backend/alembic.ini upgrade head
```

Verify migration status:
```powershell
python -m alembic -c backend/alembic.ini current
# Expected: e5f6a7b8c9d0 (head)
```

---

## 14. Phase 5 — AI-Assisted Remediation, Safe Fix Previews, and Reports

Phase 5 introduces security-conscious, AI-assisted explanations, proposed unified diff fix patches, explicit human review workflows, and publication-ready multi-format security audit reports (PDF, HTML, JSON).

### 14.1 Architectural Principles & Safeguards

```text
[Deterministic Security Engine (Phases 1-4)]
        │ (Authoritative Findings, Risk Scores, Severities)
        ▼
[Context Sanitizer & Redaction Layer]
        ├─ Defense-in-depth Secret Redaction (AWS, GitHub, Slack, Private Keys)
        ├─ Sensitive File Exclusion (.env, .pem, id_rsa, credentials)
        └─ Bounded Snippet Sizing (20 lines / 4 KB max)
        │
        ▼
[AI Provider Abstraction Layer] (backend/app/services/ai/)
        ├─ "disabled" (Zero external calls)
        ├─ "ollama"   (Local loopback only: 127.0.0.1 / localhost)
        └─ "openai"   (HTTPS only; server-side credentials; SSRF protected)
        │
        ▼ (Structured JSON validation via Pydantic)
[Candidate Remediation Proposal]
        │
        ├─ [Structured Explanation] (Root cause, impact, steps, secure pattern, caveats)
        │
        └─ [Safe Fix Proposal] (Unified Diff for single-file code findings)
                 │
                 ▼ [Patch Validator Engine]
                 ├─ Path traversal & absolute path rejection
                 ├─ Manifest/lockfile edit rejection
                 ├─ Bounded lines (<= 100) & patch size (<= 30 KB)
                 └─ Unified diff syntax verification
                 │
                 ▼ [Lifecycle & Human In The Loop]
                 ├─ States: proposed -> reviewed -> downloaded -> verification_pending
                 ├─ Downloadable .patch file for manual developer application
                 └─ Rescan Verification: ONLY an eligible rescan can confirm "verified_by_rescan"
```

### 14.2 AI Provider Configuration & Privacy

VulnScope supports modular AI providers configured entirely through environment variables. Server credentials and base URLs are never accepted from clients.

| Setting | Default | Description |
| :--- | :--- | :--- |
| `AI_PROVIDER` | `"disabled"` | Active provider: `"disabled"`, `"ollama"`, or `"openai"`. |
| `AI_BASE_URL` | `"http://localhost:11434"` | Base endpoint. Must be loopback (`127.0.0.1`) for Ollama; must use `https://` for OpenAI. |
| `AI_MODEL` | `"llama3"` | Model identifier (e.g. `llama3`, `codellama`, `gpt-4o-mini`). |
| `AI_API_KEY` | `""` | Secret API key for remote providers. Never committed, logged, or exposed in API. |
| `AI_TIMEOUT_SECONDS` | `30.0` | Timeout threshold in seconds. |
| `AI_MAX_OUTPUT_TOKENS` | `2000` | Maximum token limit per response. |
| `AI_MAX_RETRIES` | `1` | Bounded retries for schema validation recovery. |
| `AI_REMOTE_OPT_IN_REQUIRED`| `true` | Enforces explicit user consent before sending finding context to remote providers. |
| `AI_MAX_SNIPPET_LINES` | `20` | Maximum lines extracted around a finding (before + after). |
| `AI_MAX_SNIPPET_BYTES` | `4096` | Maximum byte limit for source code snippet. |

#### Privacy & Prompt-Injection Controls
1. **Never Dispatches Raw Secrets**: Gitleaks secret values and synthetic secret patterns are stripped before any AI prompt is constructed.
2. **Excludes Sensitive Files**: Configuration files (`.env*`, `wp-config.php`), private keys (`.pem`, `.key`, `id_rsa`), and keystores are completely blocked from snippet extraction.
3. **Prompt Injection Containment**: All analyzed repository content and scanner messages are isolated inside `--- UNTRUSTED FINDING DATA ---`. Trusted system instructions explicitly command the model that instructions in code are data to analyze, not instructions to execute.
4. **Non-destructive & Isolated**: The model has no shell access, no repository write access, and no tool execution capability. Proposed patches are never applied automatically to workspace files.
5. **Deterministic Fallback**: If AI is disabled, unconfigured, or encounters network errors/rate limits, the application transparently falls back to deterministic Phase 4 guidance without fabricating data.

### 14.3 Proposal Lifecycle & Verification States

VulnScope strictly enforces that an AI suggestion is an **unverified proposal** until proven otherwise by a subsequent scan:

- **`proposed`**: Initial candidate explanation or patch generated.
- **`reviewed`**: Human developer explicitly reviewed the proposal.
- **`rejected`**: Proposal rejected by the developer.
- **`downloaded`**: Sanitized `.patch` file downloaded for local developer testing.
- **`validation_failed`**: Proposed diff failed structural or path safety checks.
- **`verification_pending`**: User indicates patch was applied externally and awaits rescan.
- **`verified_by_rescan`**: An eligible, successful rescan of the same repository lineage confirms the finding is no longer detected.
- **`unconfirmed`**: Rescan was partial, failed, or the relevant scanner did not run.

### 14.4 Professional Security Audit Reports

VulnScope provides publication-ready security audit reports in three formats:

1. **PDF (`/api/scans/{id}/report?format=pdf`)**: Built with ReportLab, featuring dynamic `Page X of Y` headers/footers (`NumberedCanvas`), executive risk distribution tables, scanner execution outcome metrics, detailed findings catalog, and audit coverage limitations.
2. **HTML (`/api/scans/{id}/report?format=html`)**: Fully self-contained, standalone printable HTML report with strict `html.escape` protection against XSS payloads and defense-in-depth secret redaction.
3. **JSON (`/api/scans/{id}/report?format=json`)**: Comprehensive machine-readable audit report conforming to a stable, documented JSON schema.

### 14.5 Phase 5 API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/scans/{id}/findings/{finding_id}/ai-remediation` | Generate or retrieve AI-assisted explanation and remediation proposal (supports `allow_remote` opt-in). |
| `GET` | `/api/scans/{id}/findings/{finding_id}/ai-remediation` | Retrieve existing AI remediation proposal for finding. |
| `POST` | `/api/scans/{id}/findings/{finding_id}/fix-proposals` | Generate candidate unified diff fix patch (prohibited for secrets/dependencies). |
| `GET` | `/api/scans/{id}/findings/{finding_id}/fix-proposals` | List all fix proposals for finding. |
| `PATCH`| `/api/scans/{id}/fix-proposals/{proposal_id}/status` | Update proposal lifecycle state (`reviewed`, `rejected`, `verification_pending`). |
| `GET` | `/api/scans/{id}/fix-proposals/{proposal_id}/download` | Download sanitized `.patch` file (`Content-Disposition: attachment`). |
| `GET` | `/api/scans/{id}/report?format=pdf\|html\|json` | Export security audit report in PDF, HTML, or JSON format. |

---

## 15. Verification and Automated Testing

Run the complete backend test suite (135 automated tests covering Phases 1–5):
```powershell
cd d:\Projects\VulnScope
python -m pytest backend/tests -v
```

Run the frontend TypeScript checks and production bundle build:
```powershell
cd d:\Projects\VulnScope\frontend
npm run build
```
