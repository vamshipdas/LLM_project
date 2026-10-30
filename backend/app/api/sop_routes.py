import os
import re
import tempfile
from typing import List

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.api.deps import require_admin, require_any_user
from app.config import settings
from app.db import get_db
from app.models.db_models import SOPDocument, User
from app.models.schemas import SOPDocumentOut, SOPChunkOut
from app.services.sop_manager import (
    is_supported_file,
    parse_file,
    sanitize_filename,
    sop_manager,
)
from app.services.vector_store import vector_store

router = APIRouter(prefix="/sops", tags=["SOP Knowledge Base"])

_SOP_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{2,63}$")
_MAX_UPLOAD_BYTES = 20 * 1024 * 1024  # 20 MB


@router.get("", response_model=List[dict])
def list_sops(
    db: Session = Depends(get_db),
    _: User = Depends(require_any_user),
) -> List[dict]:
    return sop_manager.get_all_sops(db)


@router.get("/{sop_id}/chunks", response_model=List[SOPChunkOut])
def get_sop_chunks(
    sop_id: str,
    db: Session = Depends(get_db),
    _: User = Depends(require_any_user),
) -> List[SOPChunkOut]:
    chunks = sop_manager.get_sop_chunks(db, sop_id)
    if not chunks:
        raise HTTPException(status_code=404, detail="SOP not found or has no chunks")
    return chunks


@router.post("/upload", response_model=SOPDocumentOut, status_code=201)
async def upload_sop(
    file: UploadFile = File(..., description="PDF, DOCX, TXT, or Markdown SOP"),
    sop_id: str = Form(...),
    title: str = Form(...),
    category: str = Form("general"),
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
) -> SOPDocumentOut:
    if not _SOP_ID_RE.match(sop_id or ""):
        raise HTTPException(
            status_code=400,
            detail="sop_id must be 3-64 characters of letters, digits, '_' or '-'.",
        )
    if not is_supported_file(file.filename or ""):
        raise HTTPException(
            status_code=400,
            detail="Unsupported file type. Accepted: .pdf, .docx, .txt, .md",
        )

    payload = await file.read()
    if not payload:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    if len(payload) > _MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File exceeds the 20 MB limit.")

    extension = os.path.splitext(file.filename or "")[1].lower()

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            suffix=extension, delete=False, dir=settings.DATA_DIR, mode="wb"
        ) as handle:
            handle.write(payload)
            tmp_path = handle.name
        content = parse_file(tmp_path)
    except Exception as exc:
        raise HTTPException(
            status_code=422, detail=f"Could not extract text from the file: {exc}"
        ) from exc
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass

    if not content.strip():
        raise HTTPException(status_code=422, detail="No text could be extracted.")

    return sop_manager.register_sop(
        db=db,
        sop_id=sop_id,
        title=title.strip() or sop_id,
        filename=file.filename or f"{sop_id}{extension}",
        category=(category or "general").strip().lower(),
        content=content,
    )


@router.delete("/{sop_id}", status_code=204)
def delete_sop(
    sop_id: str,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
) -> None:
    row = db.get(SOPDocument, sop_id)
    if row is None:
        raise HTTPException(status_code=404, detail="SOP not found")

    stored_name = sanitize_filename(row.filename)
    stored_path = os.path.join(settings.SOPS_DIR, stored_name)
    common_root = os.path.abspath(settings.SOPS_DIR)

    db.delete(row)
    db.commit()

    vector_store.remove_by_sop_id(sop_id)

    if os.path.abspath(stored_path).startswith(common_root + os.sep):
        try:
            os.remove(stored_path)
        except OSError:
            pass
