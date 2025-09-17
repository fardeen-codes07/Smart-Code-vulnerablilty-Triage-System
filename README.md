# Smart-Code-vulnerablilty-Triage-System

# SecureScan — Cyber Threat Analysis (Frontend + FastAPI backend)

SecureScan is a browser-based vulnerability scanner UI paired with a FastAPI backend for server-side scanning. The frontend performs client-side heuristics (regex + JavaScript AST via Esprima) and the backend accepts uploaded source files and returns structured findings that the UI renders.

## Repo layout
- `index.html` (or `frontend/`) — SecureScan UI (drag & drop, AI console, scanner).
- `app.py` — FastAPI backend that accepts file uploads at `POST /scan` and returns findings.
- `.github/workflows/ci.yml` — lightweight CI (optional).
- `vulnerable_test.js` — (optional) a test file that triggers scanner rules.

---

## Quick start (local)

### Prerequisites
- Python 3.9+  
- `pip`  
- `git` (optional, for cloning)

### 1) Clone & install
```bash
git clone <your-repo-url>
cd <repo-folder>
python -m venv .venv
# Activate virtualenv:
# Linux / macOS:
source .venv/bin/activate
# Windows (PowerShell):
.venv\Scripts\Activate.ps1

pip install fastapi uvicorn python-multipart aiofiles
