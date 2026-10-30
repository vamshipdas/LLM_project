# SOC Chatbot — RAG-powered Incident Response Assistant

A FastAPI + React application that lets SOC analysts chat with an AI assistant grounded in your organization's **SOP (Standard Operating Procedure) knowledge base** via Retrieval-Augmented Generation (RAG). Incoming simulated SOC tickets appear in a right-hand panel, while the left sidebar manages recent chats (new, archive, delete, settings).

## Features

| Area | Capability |
|------|------------|
| **Chat** | Ask natural-language questions about incidents and SOPs; answers are grounded in retrieved SOP excerpts with citations |
| **RAG** | Sentence Transformers embeddings (`all-MiniLM-L6-v2`) + FAISS vector store (`IndexFlatIP`, cosine similarity) |
| **SOPs** | Upload PDF / DOCX / TXT / MD documents; auto-chunked and indexed; admin-only upload/delete |
| **Tickets** | Simulated SOC ticket stream (phishing, ransomware, brute-force, malware, data exfiltration, unauthorized access) |
| **Auth** | JWT Bearer authentication; `analyst` and `admin` roles; admin required for SOP management |
| **Chat lifecycle** | New chat, recent-chats sidebar, archive/unarchive, delete |

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Python | 3.11+ | Used for the backend |
| [uv](https://github.com/astral-sh/uv) | latest | Python package manager (project is uv-managed) |
| Node.js | 18+ | Used for the frontend (Vite) |
| npm / yarn / pnpm | — | Frontend package manager |

> **No Docker is required.** The backend defaults to a local SQLite database, so the project runs with zero external services.

## Project Structure

```
Major-Project/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── auth_routes.py      # Login / me (JWT)
│   │   │   ├── chat_routes.py      # Chat sessions, messages, archive, delete
│   │   │   ├── sop_routes.py       # SOP list, chunks, upload, delete
│   │   │   └── ticket_routes.py    # Simulated SOC tickets
│   │   ├── models/
│   │   │   ├── db_models.py        # SQLAlchemy 2.x ORM models
│   │   │   └── schemas.py          # Pydantic request/response schemas
│   │   ├── services/
│   │   │   ├── auth_service.py     # bcrypt, JWT, seed users
│   │   │   ├── embedding_service.py# Sentence Transformers wrapper
│   │   │   ├── rag_engine.py       # LangChain chain + local synthesis fallback
│   │   │   ├── sop_manager.py      # SOP parsing, chunking, vector indexing
│   │   │   ├── ticket_service.py   # Simulated ticket generator
│   │   │   └── vector_store.py     # FAISS IndexFlatIP persistence
│   │   ├── config.py               # Pydantic settings (.env)
│   │   ├── db.py                   # SQLAlchemy engine + session
│   │   ├── main.py                 # FastAPI app, lifespan seeding, CORS
│   │   └── __init__.py
│   ├── data/                       # SQLite DB, FAISS index, uploaded SOPs (gitignored)
│   ├── .env.example                # Copy to .env and edit
│   ├── docker-compose.yml          # Optional PostgreSQL
│   ├── pyproject.toml              # uv project metadata
│   └── requirements.txt            # Pinned dependencies
├── frontend/
│   ├── src/
│   │   ├── api.js                  # Fetch wrapper + auth token handling
│   │   ├── App.jsx                 # Auth gate + 3-column layout
│   │   ├── components/
│   │   │   ├── ChatWindow.jsx      # Chat UI + SOP citations
│   │   │   ├── Header.jsx          # Branding + signed-in user + logout
│   │   │   ├── LoginPage.jsx       # Sign-in form
│   │   │   ├── Sidebar.jsx         # Recent chats, archive/delete, settings
│   │   │   └── TicketsPanel.jsx    # Simulated incoming tickets
│   │   ├── App.css
│   │   ├── index.css
│   │   └── main.jsx
│   ├── index.html
│   ├── package.json
│   └── vite.config.js
├── graphify-out/                   # Code knowledge graph (auto-generated)
├── .gitignore
└── README.md
```

## Quick Start

### 1. Clone / open the project

```powershell
cd C:\Users\HP\Desktop\Office\Major-Project
```

### 2. Backend

Open PowerShell in the `backend` folder:

```powershell
cd backend
```

#### Install Python dependencies

```powershell
uv sync
```

> If `uv sync` fails because the venv already exists, use:
> ```powershell
> uv pip install --python .\.venv\Scripts\python.exe -r requirements.txt
> ```

#### Configure environment

Copy the example file and edit as needed:

```powershell
copy .env.example .env
```

Edit `backend/.env`. The only values you *might* want to change for a local run:

```ini
# JWT signing key — set a fixed value so tokens survive restarts
SECRET_KEY=change-me-in-production

# Frontend origin (Vite dev server)
CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173

# LLM provider: auto | openai | nim | none
# "none" (default) uses deterministic local synthesis — works offline with no API key.
LLM_PROVIDER=none

# Optional: PostgreSQL DSN. Leave empty for zero-config SQLite.
DATABASE_URL=

# Seed demo account passwords (change before any shared deployment)
SEED_ADMIN_PASSWORD=adminpassword123
SEED_ANALYST_PASSWORD=socpassword123

# Critical alert email notifications (SMTP)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=vamshipdas@gmail.com
SMTP_PASSWORD=<GMAIL_APP_PASSWORD>
ALERT_EMAIL_FROM=vamshipdas@gmail.com
ALERT_EMAIL_TO=dasvamshi8@gmail.com
ALERT_EMAIL_ENABLED=true
ALERT_MIN_SEVERITY=critical
ALERT_COOLDOWN_SECONDS=300
DASHBOARD_BASE_URL=http://localhost:5173
```

> **Setting up Gmail SMTP App Password:**
> 1. In your Google Account (`vamshipdas@gmail.com`), enable **2-Step Verification**.
> 2. Go to **Security > App passwords** (or search "App passwords").
> 3. Generate a password for "Mail" / "Windows Computer" (16 characters).
> 4. Paste it into `backend/.env` under `SMTP_PASSWORD=...`.
> 5. If `SMTP_PASSWORD` is omitted, email sending is safely disabled with a log warning and the app runs normally.


#### Start the backend

```powershell
\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8123
```

Wait for:

```
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8123 (Press CTRL+C to quit)
Database engine   : sqlite:///...
Vector index      : 24 SOP chunks in FAISS
LLM provider      : none configured -> deterministic local synthesis
```

First boot downloads the `all-MiniLM-L6-v2` embedding model (~90 MB) — this takes ~30–60 seconds.

Verify:

```powershell
Invoke-WebRequest http://127.0.0.1:8123/health
```

Expected: `{"status":"ok","version":"1.0.0","vector_chunks":24,...}`

Interactive API docs: `http://127.0.0.1:8123/docs`

### 3. Frontend

Open a **second** PowerShell window in the `frontend` folder:

```powershell
cd C:\Users\HP\Desktop\Office\Major-Project\frontend
npm install
npm run dev
```

Vite will start on `http://localhost:5173`.

> If you want the frontend to point at a different backend URL, create `frontend/.env`:
> ```
> VITE_API_BASE=http://127.0.0.1:8123/api/v1
> ```

### 4. Use the app

1. Open `http://localhost:5173`
2. Sign in with one of the seeded accounts:
   - **analyst** / `socpassword123` — chat, view tickets, view SOPs
   - **admin** / `adminpassword123` — everything analyst + upload/delete SOPs
3. The UI has three columns:
   - **Left** — Sidebar: recent chats, New chat, Archive/Delete per chat, Settings, Sign out
   - **Center** — Chat window: type a question about an incident/SOP; answers include SOP citations
   - **Right** — Incoming Tickets panel: simulated SOC tickets (phishing, ransomware, malware, data exfiltration, etc.)

## Backend Architecture

### Database (SQLAlchemy 2.x)
- **Zero-config:** SQLite at `backend/data/soc.db` (created automatically on first boot)
- **Optional PostgreSQL:** set `DATABASE_URL=postgresql+psycopg://user:pass@localhost:5432/soc_assistant` and run `docker compose -f backend/docker-compose.yml up -d`

### RAG Pipeline
1. SOPs are parsed (PDF via `pypdf`, DOCX via `python-docx`, TXT/MD via plain read)
2. Text is chunked with LangChain `RecursiveCharacterTextSplitter` (900 chars, 120 overlap)
3. Chunks are embedded with `sentence-transformers/all-MiniLM-L6-v2` and stored in FAISS `IndexFlatIP` (cosine similarity on L2-normalized vectors)
4. On chat, the user query is embedded and the top-K SOP chunks are retrieved
5. A LangChain `ChatOpenAI` chain (OpenAI or NVIDIA NIM LLaMA) generates the answer; if no provider is configured, a deterministic local synthesiser runs offline

### Authentication
- `POST /api/v1/auth/login` → JWT access token (HS256)
- `GET /api/v1/auth/me` → current user
- All chat/ticket/SOP endpoints require a valid Bearer token
- `admin` role required for SOP upload/delete

### Seed Data
On first boot the backend seeds:
- 2 users: `admin` / `analyst`
- 6 default SOPs (phishing, ransomware, privilege escalation, brute-force, malware, data exfiltration) → 24 vector chunks
- 12 simulated SOC tickets

## API Reference

Base URL: `http://127.0.0.1:8123/api/v1`

### Auth
| Method | Endpoint | Body | Auth | Description |
|--------|----------|------|------|-------------|
| POST | `/auth/login` | `{username, password}` | — | Get JWT access token |
| GET | `/auth/me` | — | Bearer | Current user profile |

### Chat
| Method | Endpoint | Body | Auth | Description |
|--------|----------|------|------|-------------|
| POST | `/chat` | — | Bearer | Create a new chat session |
| GET | `/chat/sessions` | `?include_archived=1` | Bearer | List sessions (archived hidden by default) |
| GET | `/chat/sessions/{id}/messages` | — | Bearer | Get message history |
| POST | `/chat/sessions/{id}/message` | `{message}` | Bearer | Send message; get RAG answer + SOP citations |
| PATCH | `/chat/sessions/{id}/archive` | `{archived: bool}` | Bearer | Archive or unarchive a session |
| DELETE | `/chat/sessions/{id}` | — | Bearer | Delete a session |

### Tickets
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/tickets` | Bearer | All simulated tickets |
| GET | `/tickets/open` | Bearer | Open tickets only |

### SOPs
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/sops` | Bearer | List indexed SOPs |
| GET | `/sops/{id}/chunks` | Bearer | Get SOP chunks |
| POST | `/sops/upload` | Bearer (admin) | Upload PDF/DOCX/TXT/MD SOP |
| DELETE | `/sops/{id}` | Bearer (admin) | Delete an SOP |

## Environment Variables (`backend/.env`)

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | *(ephemeral per boot)* | JWT signing key. Set a fixed value for production. |
| `ALGORITHM` | `HS256` | JWT algorithm |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `1440` | Token lifetime |
| `CORS_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | Comma-separated frontend origins |
| `LLM_PROVIDER` | `auto` | `auto` \| `openai` \| `nim` \| `none` |
| `OPENAI_API_KEY` | `""` | OpenAI key (used if `LLM_PROVIDER=openai` or auto) |
| `OPENAI_MODEL` | `gpt-4o-mini` | OpenAI model |
| `NIM_API_KEY` | `""` | NVIDIA NIM key |
| `NIM_BASE_URL` | `https://integrate.api.nvidia.com/v1` | NIM endpoint |
| `NIM_MODEL` | `meta/llama-4-scout-17b-16e-instruct` | NIM model |
| `LLM_TIMEOUT_SECONDS` | `25` | LLM request timeout |
| `EMBEDDING_MODEL` | `sentence-transformers/all-MiniLM-L6-v2` | Embedding model |
| `RETRIEVAL_TOP_K` | `4` | SOP chunks retrieved per query |
| `DATABASE_URL` | `""` | Empty = SQLite; set PostgreSQL DSN for production |
| `SEED_ADMIN_PASSWORD` | `adminpassword123` | Admin seed password |
| `SEED_ANALYST_PASSWORD` | `socpassword123` | Analyst seed password |

## Running with PostgreSQL (optional)

```powershell
cd backend
docker compose -f docker-compose.yml up -d
# Then set in .env:
# DATABASE_URL=postgresql+psycopg://soc:soc@localhost:5432/soc_assistant
```

Restart the backend after changing `DATABASE_URL`.

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `ModuleNotFoundError: No module named 'jose'` | Run `uv pip install --python .\.venv\Scripts\python.exe python-jose[cryptography]` |
| Port 8123 already in use | The sibling dhruva project owns port 8000; use 8123 (already configured) or change `--port` |
| First boot hangs ~60s | The embedding model (~90 MB) is downloading on first startup |
| Frontend shows `ERR_CONNECTION_REFUSED` | Backend isn't running. Start uvicorn on `127.0.0.1:8123` first |
| Login returns 401 with correct credentials | Ensure the backend is running and `SECRET_KEY` isn't changing between restarts (tokens are invalidated on restart if `SECRET_KEY` is unset) |
| Archived chats don't appear | Use the "Show archived" toggle in the sidebar |
| DOCX upload fails | Ensure the file is a valid `.docx` and under 20 MB; `sop_id` must be 3–64 chars (letters, digits, `_`, `-`) |
| Security log access denied | Windows requires Administrator privileges to read the Security event log. Launch your terminal/IDE as Administrator or the collector automatically falls back to System and Application logs. |

## Log Analysis Module

The application includes a comprehensive **Log Analysis & Threat Correlation** engine with two modes:

### 1. Real-Time Logs (Live Host Telemetry)
- Collects live operating system logs via Server-Sent Events (`/api/v1/logs/stream`).
- **Cross-Platform:**
  - **Windows:** PowerShell `Get-WinEvent` polling across `System`, `Application`, and `Security` logs.
    > **Note:** To stream the **Windows Security log** (logon failures, account changes, privilege escalation), run your terminal or IDE as **Administrator**. Without Administrator rights, the system automatically falls back to `System` and `Application` logs with a warning banner.
  - **Linux:** `journalctl -f -o json`
  - **macOS:** `log stream --style ndjson`
- Real-time normalization into standard `{timestamp, level, source, event_id, message, host}` schema.
- Live counters: throughput (events/s), buffered count, errors, warnings, and findings.
- Auto-scroll with pause/resume and a 500-event DOM rendering cap.

### 2. Upload Logs (Forensic File Ingestion)
- Supported formats: `.log`, `.txt`, `.csv`, `.json`, `.jsonl`, `.evtx` (Windows Event Log binary via `python-evtx`), and Syslog (RFC 3164 & RFC 5424).
- Max file size: 20 MB.
- Provides summary overview (total events, level breakdown chart, top sources, time window) and paginated/filterable event listing.

### 3. Rule-Based Detection & SOP Correlation (RAG)
Configurable rules located in `backend/app/rules.yaml`:
- **Brute Force (T1110):** 5+ failed logons within 60s
- **Account Compromise (T1078):** Successful logon following repeated failures
- **Persistence (T1543):** Service installation (7045) or scheduled task (4698)
- **Defense Evasion (T1070):** Audit/System log cleared (1102 / 104)
- **Privilege Escalation (T1098):** Account creation / addition to Administrators (4720, 4732)
- **Malware Detection (T1204):** Antivirus/Defender detection events (1116, 1117)
- **Suspicious Execution (T1059.001):** Encoded PowerShell commands (`-enc`, `DownloadString`)
- **Network Reconnaissance (T1046):** Port scan / connection refused bursts

Clicking **"Analyze with CyberLLM (RAG)"**:
1. Correlates identified findings against the organizational SOP FAISS vector index.
2. Synthesizes recommended containment steps with exact SOP citations.
3. Auto-creates incident tickets in the system for high/critical findings.
4. Includes **"Ask CyberLLM about this"** button to jump directly into chat with a pre-filled investigative prompt.

### 4. Deterministic Severity Mapping (services/severity.py)
Every log event in both Real-Time and Upload modes is deterministically classified:
- **Base Level Mapping:**
  - Verbose / Debug / Info / Information / Notice -> `LOW` (score 20)
  - Warning / Warn -> `MEDIUM` (score 50)
  - Error / Err -> `HIGH` (score 75)
  - Critical / Fatal / Alert / Emergency -> `CRITICAL` (score 95)
- **Configurable Overrides (`severity_rules.yaml`):**
  - Failed Logons (`4625`, `Failed password`): `MEDIUM` -> Escalates to `HIGH` if 5+ in 60s from same IP/user -> Escalates to `CRITICAL` if followed by successful logon (`4624`).
  - Log Cleared (`1102`, `104`): `CRITICAL`
  - Persistence (`7045`, `4698`): `HIGH`
  - Privilege Escalation (`4720`, `4732`, `4728`): `HIGH`
  - Antivirus / Defender (`1116`, `1117`, `5001` real-time protection disabled): `HIGH` / `CRITICAL`
  - Suspicious PowerShell (`-enc`, `DownloadString`, `IEX`): `HIGH`
  - Routine System Noise (service started/stopped, DHCP, DCOM): `LOW`
- **Rule Constraints:** Overrides only escalate severity (never lower).
- **Audit & Tooltips:** Returns human-readable reasons array explaining the classification.
- **Legend Endpoint:** `GET /api/logs/severity-rules` returns active rules for UI inspection.

### 5. Log Explainer Chatbot (services/log_explainer.py)
A plain-language AI assistant built into the Log Analysis module:
- **Endpoint:** `POST /api/logs/chat` (JWT authenticated).
- **Persistent DB Sessions:** Stored in `log_chat_messages` table with audit logging.
- **Built-in Offline Knowledge Base (`event_knowledge.yaml`):** Covers ~40 common Windows Event IDs and Linux Syslog patterns with plain-English descriptions, MITRE techniques, and indicators of normal vs. malicious activity. Works offline with zero API keys.
- **SOP RAG Retrieval:** Retrieves the top 4 matching organizational SOP excerpts from FAISS.
- **Strict 5-Part Plain-Language Template:**
  1. **What happened:** 1-2 simple sentences, no jargon (technical terms in brackets).
  2. **Why it matters:** Real-world risk in simple words.
  3. **Severity:** Exact calculated severity badge and score from `classify_severity`.
  4. **What to do next:** Numbered steps derived from SOP text with citations (`[SOP-SEC-04 §1.0]`).
  5. **Is it normal?:** Likely false positive vs. likely malicious with confidence level.
- **Simple / Technical Toggle:** Toggle between conversational ELI5 explanation and detailed technical breakdown (MITRE techniques, event IDs, raw fields).
- **Anti-Prompt-Injection Defense:** Untrusted log data is strictly enclosed in `<LOG_DATA>...</LOG_DATA>` tags. Instructions inside log entries (such as "ignore previous instructions") are safely neutralized.
- **Multi-Modal Context:** Supports single-event explanation, multi-select rows (`Explain Selected`), and HTML5 Drag-and-Drop of log rows or finding cards into the chat drawer.

### Running Tests
To run the full backend unit test suite:
```powershell
cd backend
.\.venv\Scripts\python.exe -m pytest tests/
```
All 40 unit tests cover:
- Embedding service & FAISS RAG
- Log parser & format detection
- Security rule analyzer
- Deterministic severity classification & escalation
- Secret redaction, offline knowledge lookup, 5-part template adherence & prompt-injection defense

## Tech Stack

**Backend:** FastAPI, SQLAlchemy 2.x, SQLite, Pydantic v2, python-jose, bcrypt, sentence-transformers, faiss-cpu, langchain, langchain-core, uvicorn

**Frontend:** React 18, Vite, Lucide React, React Markdown, Remark GFM

## License

Internal project — Department of CS (IoT & Cybersecurity).
