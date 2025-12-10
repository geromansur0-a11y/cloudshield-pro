from fastapi import APIRouter, File, UploadFile, HTTPException
from fastapi.responses import JSONResponse
import os
import uuid
import shutil
from app.core.ai_detector import scan_file_ai

router = APIRouter(prefix="/api")

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@router.post("/scan")
async def scan_file(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file uploaded")
    
    safe_filename = f"{uuid.uuid4()}_{file.filename.replace(' ', '_')}"
    filepath = os.path.join(UPLOAD_DIR, safe_filename)
    
    try:
        with open(filepath, "wb") as f:
            shutil.copyfileobj(file.file, f)
        
        result = scan_file_ai(filepath)
        return JSONResponse(content=result)
    
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)
