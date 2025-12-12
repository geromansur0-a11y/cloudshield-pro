import os
import re
import tempfile
import hashlib
import time
import asyncio
from fastapi import FastAPI, File, UploadFile, Request, Form, HTTPException
from fastapi.responses import HTMLResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import PyPDF2
from openpyxl import load_workbook
import httpx
from telegram import Bot

# --- Konfigurasi ---
IOC_DIR = "iocs"
RATE_LIMIT = "10/minute"
TELEGRAM_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

# --- Load IOCs ---
def load_iocs():
    def read_lines(filename):
        path = os.path.join(IOC_DIR, filename)
        if not os.path.exists(path):
            return set()
        with open(path, "r") as f:
            return {line.strip().lower() for line in f if line.strip()}
    return {
        "hashes": read_lines("hashes.txt"),
        "bad_strings": read_lines("bad_strings.txt"),
        "bad_extensions": read_lines("bad_extensions.txt")
    }

IOCS = load_iocs()

# --- Telegram Alert ---
async def send_telegram_alert(message: str):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        bot = Bot(token=TELEGRAM_TOKEN)
        await bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=message)
    except Exception:
        pass

# --- Inisialisasi FastAPI ---
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="CloudShield Pro")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

def compute_hash(file_path: str) -> str:
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def has_bad_extension(filename: str) -> bool:
    ext = os.path.splitext(filename)[1].lower()
    return ext in IOCS["bad_extensions"]

def check_bad_strings(file_path: str, max_size_mb=5) -> list:
    file_size = os.path.getsize(file_path)
    if file_size > max_size_mb * 1024 * 1024:
        return []
    bad_found = []
    try:
        with open(file_path, "rb") as f:
            content = f.read()
            text = content.decode("utf-8", errors="ignore").lower()
            for bad_str in IOCS["bad_strings"]:
                if bad_str in text:
                    bad_found.append(bad_str)
    except Exception:
        pass
    return bad_found

def extract_metadata(file_path: str, filename: str):
    metadata = {}
    ext = os.path.splitext(filename)[1].lower()
    try:
        if ext == ".pdf":
            with open(file_path, "rb") as f:
                reader = PyPDF2.PdfReader(f)
                if reader.metadata:
                    metadata = {
                        "author": str(reader.metadata.get("/Author", "")),
                        "creator": str(reader.metadata.get("/Creator", "")),
                        "producer": str(reader.metadata.get("/Producer", "")),
                        "title": str(reader.metadata.get("/Title", "")),
                    }
        # elif ext == ".docx":  # Sementara dinonaktifkan di Termux
#     metadata = {"info": "DOCX metadata disabled in mobile version"}
        elif ext == ".xlsx":
            wb = load_workbook(file_path, read_only=True)
            props = wb.properties
            metadata = {
                "creator": props.creator or "",
                "last_modified_by": props.lastModifiedBy or "",
            }
    except Exception as e:
        metadata["error"] = f"Ekstraksi gagal: {str(e)}"
    return metadata

async def analyze_file(file_path: str, filename: str):
    findings = []
    risk = "low"

    if has_bad_extension(filename):
        findings.append(f"Ekstensi berbahaya: {os.path.splitext(filename)[1]}")
        risk = "high"

    file_hash = compute_hash(file_path)
    if file_hash in IOCS["hashes"]:
        findings.append("Hash cocok dengan malware dikenal")
        risk = "critical"

    if risk != "critical":
        bad_strings = check_bad_strings(file_path)
        for s in bad_strings:
            findings.append(f"String mencurigakan: '{s}'")
        if bad_strings:
            risk = "medium" if risk == "low" else risk

    metadata = {}
    if filename.lower().endswith(('.pdf', '.xlsx')):
        metadata = extract_metadata(file_path, filename)

    return {
        "filename": filename,
        "hash": file_hash,
        "malicious": len(findings) > 0,
        "findings": findings,
        "risk": risk,
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "file_size": os.path.getsize(file_path),
        "metadata": metadata
    }

@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    with open("../static/index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())

@app.post("/scan")
@limiter.limit(RATE_LIMIT)
async def scan_file(request: Request, file: UploadFile = File(...)):
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    try:
        result = await analyze_file(tmp_path, file.filename)
        if result["malicious"]:
            alert_msg = f"⚠️ ANCAMAN TERDETEKSI!\nFile: {file.filename}\nRisiko: {result['risk']}\nWaktu: {result['scan_time']}"
            asyncio.create_task(send_telegram_alert(alert_msg))
        return result
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

@app.post("/scan-url")
@limiter.limit(RATE_LIMIT)
async def scan_url(request: Request, url: str = Form(...)):
    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="URL harus dimulai dengan http:// atau https://")
    
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=30.0) as client:
            async with client.stream("GET", url) as response:
                response.raise_for_status()
                content_length = int(response.headers.get("content-length", 0))
                if content_length > 10 * 1024 * 1024:
                    raise HTTPException(status_code=413, detail="File terlalu besar (>10 MB)")
                
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    async for chunk in response.aiter_bytes(4096):
                        tmp.write(chunk)
                    tmp_path = tmp.name
                    filename = url.split("/")[-1] or "unknown_file"

        result = await analyze_file(tmp_path, filename)
        if result["malicious"]:
            alert_msg = f"⚠️ ANCAMAN DARI URL!\nURL: {url}\nFile: {filename}\nRisiko: {result['risk']}"
            asyncio.create_task(send_telegram_alert(alert_msg))
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Gagal mengunduh: {str(e)}")
    finally:
        if 'tmp_path' in locals() and os.path.exists(tmp_path):
            os.unlink(tmp_path)
