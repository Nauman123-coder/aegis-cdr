"""
api/main.py — Project Aegis-CDR FastAPI Backend (Groq Edition)

Serves the React-style frontend as a static HTML file.
No npm, no node_modules — just open http://localhost:8000

Endpoints:
  GET  /                       -> Aegis frontend (drag-drop UI)
  POST /api/sanitize           -> Upload + sanitize -> threat report
  GET  /api/download/{token}   -> Download sanitized file
  GET  /api/health             -> Server + Groq status
"""

import os
import sys
import shutil
import tempfile
import time
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Ensure project root on path
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from core.pdf.sanitizer import PDFSanitizer
from core.docx.sanitizer import DocxSanitizer
from core.ai.sentry import AegisSentry
from utils.validator import SafeTypeValidator

app = FastAPI(
    title="Project Aegis-CDR",
    description="AI-Driven Content Disarm & Reconstruction — Groq Edition",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SUPPORTED_TYPES = {
    "application/pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}

_file_store: dict[str, str] = {}

# ── Serve static frontend ─────────────────────────────────────────
STATIC_DIR = ROOT / "static"

@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    html_path = STATIC_DIR / "index.html"
    if html_path.exists():
        return HTMLResponse(content=html_path.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>Aegis CDR API running. Place index.html in /static/</h1>")


# ── Response models ────────────────────────────────────────────────
class SanitizeResponse(BaseModel):
    status: str
    original_filename: str
    sanitized_filename: str
    true_mime_type: str
    file_size_original: int
    file_size_sanitized: int
    processing_time_ms: int
    page_count_original: int
    page_count_sanitized: int
    items_removed_count: int
    threat_categories: list[dict]
    risk: dict
    ai_summary: str
    groq_powered: bool
    fallback_used: bool
    download_token: str


# ── Main sanitize endpoint ─────────────────────────────────────────
@app.post("/api/sanitize", response_model=SanitizeResponse)
async def sanitize_file(file: UploadFile = File(...)):
    t_start = time.time()
    raw_bytes = await file.read()
    file_size_original = len(raw_bytes)

    # Layer 1: Fingerprint
    validator = SafeTypeValidator()
    try:
        true_mime = validator.detect_true_type(raw_bytes)
    except ValueError as e:
        raise HTTPException(status_code=415, detail={
            "error": "FILE_BLOCKED", "message": str(e), "filename": file.filename,
        })

    if true_mime not in SUPPORTED_TYPES:
        raise HTTPException(status_code=415, detail={
            "error": "UNSUPPORTED_TYPE",
            "message": f"Unsupported file type: {true_mime}. Only PDF and DOCX are accepted.",
        })

    # Write to temp
    tmp_dir = Path(tempfile.mkdtemp())
    input_path = tmp_dir / (file.filename or "upload")
    input_path.write_bytes(raw_bytes)
    safe_name = f"SAFE_{file.filename or 'document'}"
    output_path = tmp_dir / safe_name

    # Layers 2-4: Decompose → Disarm → Reconstruct
    try:
        if true_mime == "application/pdf":
            sanitizer = PDFSanitizer(str(input_path), str(output_path), pixel_fallback=True)
        else:
            sanitizer = DocxSanitizer(str(input_path), str(output_path))
        result = sanitizer.sanitize()
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": "SANITIZATION_FAILED", "message": str(e)})

    items_removed = result.get("items_removed", [])
    page_orig = result.get("page_count_original", 0)
    page_safe = result.get("page_count_sanitized", 0)
    fallback_used = result.get("fallback_used", False)
    file_size_sanitized = output_path.stat().st_size if output_path.exists() else 0

    # AI Sentry
    sentry = AegisSentry()
    ai_summary = sentry.summarize(items_removed, page_orig, page_safe, file.filename or "document")
    risk = sentry.risk_score(items_removed)
    categories_raw = sentry.categorize_threats(items_removed)

    icon_map = {
        "Scripts & JavaScript": "⚡",
        "Macros & VBA":         "🦠",
        "External Links":       "🔗",
        "Embedded Objects":     "📦",
        "Auto-Execute Actions": "🚀",
        "Custom XML":           "🗂️",
        "Other":                "⚠️",
    }
    threat_categories = [
        {"name": k, "items": v, "icon": icon_map.get(k, "⚠️")}
        for k, v in categories_raw.items()
    ]

    # Store for download
    token = f"aegis_{int(time.time())}_{safe_name}"
    stable_path = Path(tempfile.gettempdir()) / token
    shutil.copy(str(output_path), str(stable_path))
    _file_store[token] = str(stable_path)

    return SanitizeResponse(
        status="sanitized",
        original_filename=file.filename or "unknown",
        sanitized_filename=safe_name,
        true_mime_type=true_mime,
        file_size_original=file_size_original,
        file_size_sanitized=file_size_sanitized,
        processing_time_ms=int((time.time() - t_start) * 1000),
        page_count_original=page_orig,
        page_count_sanitized=page_safe,
        items_removed_count=len(items_removed),
        threat_categories=threat_categories,
        risk=risk,
        ai_summary=ai_summary,
        groq_powered=sentry._groq_available,
        fallback_used=fallback_used,
        download_token=token,
    )


@app.get("/api/download/{token}")
async def download_file(token: str):
    if not token.startswith("aegis_"):
        raise HTTPException(status_code=400, detail="Invalid token.")
    file_path = _file_store.get(token)
    if not file_path or not Path(file_path).exists():
        raise HTTPException(status_code=404, detail="File not found or expired.")
    filename = "_".join(token.split("_")[2:])
    return FileResponse(file_path, filename=filename, media_type="application/octet-stream")


@app.get("/api/health")
async def health():
    return {
        "status": "operational",
        "version": "2.0.0",
        "groq": {
            "configured": bool(os.getenv("GROQ_API_KEY")),
            "model": os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
        },
        "ui": "http://localhost:8000",
        "supported_formats": ["PDF", "DOCX"],
    }


@app.get("/ping")
async def ping():
    """
    Lightweight keep-alive endpoint.
    Ping this every 14 minutes with UptimeRobot (free) to prevent
    Render free tier from sleeping after 15 minutes of inactivity.
    URL to monitor: https://your-app.onrender.com/ping
    """
    return {"pong": True}