# app.py
import os
import re
import uuid
import json
import shutil
import asyncio
from typing import List, Dict, Any
from fastapi import FastAPI, UploadFile, File, BackgroundTasks, HTTPException
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware

# -----------------------------
# CONFIG
# -----------------------------
# Set FRONTEND_FOLDER to where your index.html / frontend is located (optional)
FRONTEND_FOLDER = r"C:\Users\prath\Desktop\Dataquest 2.0\AIScanner.html"

# Temporary upload dir
TMP_DIR = "tmp_uploads"
os.makedirs(TMP_DIR, exist_ok=True)

# -----------------------------
# FastAPI app
# -----------------------------
app = FastAPI(title="SecureScan Backend")

# Allow CORS for dev. Restrict origins in production.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve index if frontend exists (optional)
if os.path.isdir(FRONTEND_FOLDER):
    from fastapi.staticfiles import StaticFiles
    app.mount("/static", StaticFiles(directory=FRONTEND_FOLDER), name="static")

    @app.get("/", include_in_schema=False)
    async def root():
        index_file = os.path.join(FRONTEND_FOLDER, "index.html")
        if os.path.exists(index_file):
            return FileResponse(index_file)
        return JSONResponse({"detail": "Frontend index.html not found"}, status_code=404)


# -----------------------------
# Detection heuristics (mirror front-end)
# -----------------------------
# Tuple: (compiled_regex, name, severity, description, remediation)
PATTERNS = [
    (re.compile(r"\b(api[_-]?key|client[_-]?secret|secret[_-]?key)\s*[:=]\s*['\"][A-Za-z0-9\-\._\/\+]{8,}['\"]", re.I),
     "Hardcoded API Key", "critical",
     "Possible hardcoded API key or secret detected.",
     "Move secrets to environment variables or a secret store."),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
     "AWS Access Key", "critical",
     "Possible AWS access key pattern found.",
     "Rotate key and use IAM roles or environment variables."),
    (re.compile(r"-----BEGIN (RSA|OPENSSL|PRIVATE) KEY-----", re.I),
     "Private Key PEM", "critical",
     "Private key material detected.",
     "Remove private keys from source and store securely."),
    (re.compile(r"\b(password|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]", re.I),
     "Hardcoded Password", "critical",
     "Hardcoded password detected.",
     "Use environment variables or a secrets vault."),
    # SQL-like concatenation (simple heuristic)
    (re.compile(r"(['\"`].*SELECT.*FROM.*['\"`]\s*\+|\bexecute\([^)]*['\"].*(\+|%|\{).*['\"]\)|\bfstring:.*SELECT.*FROM)", re.I),
     "Concatenated SQL", "high",
     "Possible SQL built by concatenation or template with variables.",
     "Use parameterized queries or prepared statements."),
    # XSS-like DOM writes
    (re.compile(r"\b(document\.write|innerHTML\s*=\s*|outerHTML\s*=\s*|insertAdjacentHTML\s*\()", re.I),
     "DOM write (dangerous)", "high",
     "Possible unsafe DOM write detected.",
     "Sanitize input and prefer textContent or safe templating."),
    # Eval/exec generic
    (re.compile(r"\b(eval|exec|execfile)\s*\(", re.I),
     "Eval or Exec (generic)", "high",
     "Use of eval/exec detected.",
     "Avoid eval/exec; use safer alternatives."),
    # Inline HTML event handlers in HTML
    (re.compile(r"\son\w+\s*=", re.I),
     "Inline event handler", "medium",
     "Inline on* event handler detected (possible JS execution).",
     "Prefer unobtrusive event binding and sanitize content."),
]

# -----------------------------
# Job store for SSE streaming (demo in-memory)
# -----------------------------
# jobs: scanId -> { queue: asyncio.Queue, task: asyncio.Task, status: str, results: List[...] }
jobs: Dict[str, Dict[str, Any]] = {}


# -----------------------------
# Utilities
# -----------------------------
def detect_in_text(filename: str, text: str) -> List[Dict[str, Any]]:
    """
    Run regex-based heuristics on text, return list of findings.
    Mirrors front-end analyzeContent() heuristics.
    """
    findings = []
    for (regex, name, severity, desc, rem) in PATTERNS:
        m = regex.search(text)
        if m:
            # crude line number
            line = text[:m.start()].count("\n") + 1
            findings.append({
                "type": name,
                "severity": severity,
                "file": filename,
                "line": line,
                "description": desc,
                "remediation": rem
            })
    return findings


async def cleanup_temp(files: List[str]):
    for p in files:
        try:
            os.remove(p)
        except Exception:
            pass


# -----------------------------
# Synchronous scan endpoint (simple)
# -----------------------------
@app.post("/scan")
async def scan(files: List[UploadFile] = File(...)):
    """
    Simple blocking scan endpoint.
    Accepts multipart/form-data with one or more 'files' entries.
    Returns an array of findings: [{type,severity,file,line,description,remediation}, ...]
    This endpoint is suitable for quick demos where client waits for the final JSON result.
    """
    saved = []
    all_findings = []
    try:
        for upload in files:
            tmp_path = os.path.join(TMP_DIR, f"{uuid.uuid4().hex}_{upload.filename}")
            saved.append(tmp_path)
            contents = await upload.read()
            with open(tmp_path, "wb") as f:
                f.write(contents)
            text = contents.decode("utf-8", errors="ignore")
            # Run detections (regex-based)
            findings = detect_in_text(upload.filename, text)
            # For JavaScript, returns the same heuristics. (Optional: integrate real AST parser later)
            all_findings.extend(findings)
        return all_findings
    finally:
        # cleanup temp files
        await cleanup_temp(saved)


# -----------------------------
# Async job API + SSE streaming
# -----------------------------
async def run_scan_job(scan_id: str, saved_files: List[Dict[str, str]]):
    """
    Background task that runs analysis and pushes progress messages into the job queue.
    When finished, pushes a final 'done' message with results.
    """
    job = jobs.get(scan_id)
    if job is None:
        return

    q: asyncio.Queue = job["queue"]

    try:
        await q.put({"type": "progress", "text": "Received files, starting analysis..."})
        # simulate some staged progress messages (you can replace these with real steps)
        await asyncio.sleep(0.7)
        await q.put({"type": "progress", "text": f"Enumerating {len(saved_files)} file(s)..."})
        await asyncio.sleep(0.6)
        await q.put({"type": "progress", "text": "Running regex heuristics..."})
        results = []
        for idx, fmeta in enumerate(saved_files):
            path = fmeta["path"]
            name = fmeta["name"]
            # read file
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
            except Exception:
                text = ""
            # add a small delay to emulate processing
            await asyncio.sleep(0.2)
            findings = detect_in_text(name, text)
            # attach file-level note if none found
            results.extend(findings)
            await q.put({"type": "progress", "text": f"Analyzed {name} ({idx+1}/{len(saved_files)}) — {len(findings)} findings"})
        await asyncio.sleep(0.5)
        await q.put({"type": "progress", "text": "Prioritizing potential vulnerabilities by severity..."})
        # final push
        await asyncio.sleep(0.4)
        await q.put({"type": "done", "results": results})
        # store result in job for retrieval if needed
        job["results"] = results
        job["status"] = "done"
    except Exception as e:
        await q.put({"type": "error", "text": f"Scan failed: {str(e)}"})
        job["status"] = "error"
    finally:
        # cleanup files
        try:
            for fmeta in saved_files:
                try:
                    os.remove(fmeta["path"])
                except Exception:
                    pass
        except Exception:
            pass


@app.post("/scan/start")
async def scan_start(files: List[UploadFile] = File(...)):
    """
    Start an asynchronous scan job. Returns { scanId } immediately.
    The client should then open an SSE stream at /scan/stream/{scanId} to receive progress and final results.
    """
    saved = []
    saved_files = []
    try:
        # Persist uploaded files temporarily
        for upload in files:
            tmp_path = os.path.join(TMP_DIR, f"{uuid.uuid4().hex}_{upload.filename}")
            contents = await upload.read()
            with open(tmp_path, "wb") as f:
                f.write(contents)
            saved.append(tmp_path)
            saved_files.append({"path": tmp_path, "name": upload.filename})

        scan_id = uuid.uuid4().hex
        q: asyncio.Queue = asyncio.Queue()
        jobs[scan_id] = {"queue": q, "task": None, "status": "queued", "results": None}

        # schedule background task
        loop = asyncio.get_event_loop()
        task = loop.create_task(run_scan_job(scan_id, saved_files))
        jobs[scan_id]["task"] = task
        jobs[scan_id]["status"] = "running"

        return {"scanId": scan_id}
    except Exception as e:
        # cleanup saved files on error
        for p in saved:
            try:
                os.remove(p)
            except Exception:
                pass
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/scan/stream/{scan_id}")
async def scan_stream(scan_id: str):
    """
    SSE endpoint streaming progress messages for a given scanId.
    The server sends JSON messages as text/event-stream lines.
    Example JSON payloads:
      { type: "progress", text: "..." }
      { type: "done", results: [...] }
      { type: "error", text: "..." }
    """
    job = jobs.get(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="scanId not found")

    q: asyncio.Queue = job["queue"]

    async def event_generator():
        # keep reading from queue until done or error
        while True:
            try:
                msg = await q.get()
            except asyncio.CancelledError:
                break

            # format as SSE data: "data: <json>\n\n"
            payload = json.dumps(msg)
            yield f"data: {payload}\n\n"

            if msg.get("type") in ("done", "error"):
                # stop streaming after final message
                break

    return StreamingResponse(event_generator(), media_type="text/event-stream")


# -----------------------------
# Health / utility endpoints
# -----------------------------
@app.get("/healthz", include_in_schema=False)
async def healthz():
    return {"status": "ok", "jobs_active": len(jobs)}


# -----------------------------
# Cleanup on shutdown (best-effort)
# -----------------------------
@app.on_event("shutdown")
async def shutdown_event():
    # cancel running tasks
    for sid, job in list(jobs.items()):
        t = job.get("task")
        if t and not t.done():
            t.cancel()
    # remove temp dir files (optional)
    try:
        for fname in os.listdir(TMP_DIR):
            fpath = os.path.join(TMP_DIR, fname)
            os.remove(fpath)
    except Exception:
        pass
