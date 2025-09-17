# Smart-Code-vulnerablilty-Triage-System

# SecureScan — Demo Cyber Threat Analysis (Client + FastAPI backend)

**SecureScan** is a single-file front-end demo for client-side vulnerability detection (regex + JS AST via Esprima) with a small FastAPI backend for server-side scanning. This repo contains:

- `frontend/` — (or single `index.html`) the SecureScan UI (drag & drop, AI console, scanner).
- `app.py` — FastAPI backend that accepts file uploads at `POST /scan` and returns findings.
- `docker-compose.yml` — local demo with backend and static frontend serving.
- `.github/workflows/ci.yml` — lightweight CI that checks Python lint and endpoint availability.

> ⚠️ **This project is a demo / proof-of-concept** — not production-ready. Do not upload real secrets. The backend uses simple heuristics; replace with real SAST tools (Semgrep, Bandit, CodeQL) for production.

---

## Quick demo (local, minimal)

### Prerequisites
- Python 3.9+ (recommended)
- pip
- git
- (optional) Docker & docker-compose

### 1) Clone & install
```bash
git clone <your-repo-url>
cd <repo-folder>
python -m venv .venv
source .venv/bin/activate        # Linux / macOS
.venv\Scripts\activate           # Windows (PowerShell)
pip install -r requirements.txt  # or: pip install fastapi uvicorn python-multipart
