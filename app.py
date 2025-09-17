from fastapi import FastAPI, UploadFile, File
from fastapi.staticfiles import StaticFiles
import os
import shutil

# -----------------------------
# CONFIG
# -----------------------------
FRONTEND_FOLDER = FRONTEND_FOLDER = r"C:\Users\aizah\code-scanner-backend\frontend"
 # Local folder name for your cloned frontend
GITHUB_FRONTEND = "https://github.com/leomonu/Vulnerability_Triage_System_AI_Sentinal"

# -----------------------------
# FastAPI app
# -----------------------------
app = FastAPI()

# -----------------------------
# Clone frontend if not present
# -----------------------------
if not os.path.exists(FRONTEND_FOLDER):
    print("Cloning frontend from GitHub...")
    os.system(f"git clone {GITHUB_FRONTEND} {FRONTEND_FOLDER}")

# Serve frontend static files
app.mount("/", StaticFiles(directory=FRONTEND_FOLDER, html=True), name="frontend")

# -----------------------------
# Scan endpoint
# -----------------------------
@app.post("/scan")
async def scan_file(file: UploadFile = File(...)):
    # Save uploaded file temporarily
    contents = await file.read()
    filepath = f"temp_{file.filename}"
    with open(filepath, "wb") as f:
        f.write(contents)

    # --- TODO: your scanning logic goes here ---
    # For now, return dummy counts
    result = {"high": 2, "medium": 1, "low": 3}

    # Delete temp file
    os.remove(filepath)

    return result

# -----------------------------
# Run locally
# -----------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
