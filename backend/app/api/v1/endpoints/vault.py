from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.db.session import get_db
from backend.app.schemas.api_schemas import AcquireEvidenceInput
from backend.app.engines.vault_engine import vault_engine
from backend.app.engines.readiness_engine import readiness_engine
from backend.app.core.events import manager

router = APIRouter()

@router.get("/vault/items")
async def get_vault_items(
    case_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    items = await vault_engine.get_all_vault_items(db, case_id=case_id)
    return items

@router.post("/vault/acquire")
async def acquire_evidence(
    payload: AcquireEvidenceInput,
    db: AsyncSession = Depends(get_db)
):
    """
    Acquires evidence from normalized security events, preserves raw records as an immutable file,
    computes SHA-256, generates a tamper-evident manifest, and registers the evidence in the vault.
    Also updates evidence source status in the readiness engine to 'collected'.
    """
    vault_item = await vault_engine.acquire_evidence_from_events(
        db=db,
        case_id=payload.case_id,
        source_key=payload.source_key,
        source_title=payload.source_title,
        event_ids=payload.event_ids,
        original_source_path=payload.original_source_path
    )

    # Mark source as collected
    await readiness_engine.update_source_status(
        db=db,
        source_key=payload.source_key,
        new_status="collected",
        details=f"Acquired into vault as {vault_item.evidence_id}. SHA-256: {vault_item.sha256_hash[:16]}..."
    )

    # Broadcast evidence preserved event
    await manager.broadcast({
        "type": "EVIDENCE_PRESERVED",
        "evidence_id": vault_item.evidence_id,
        "case_id": vault_item.case_id,
        "source_title": vault_item.source_title,
        "sha256": vault_item.sha256_hash,
        "record_count": vault_item.record_count
    })

    return vault_item

@router.post("/vault/verify/{evidence_id}")
async def verify_evidence_integrity(
    evidence_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Runs cryptographic SHA-256 integrity check against the preserved file on disk.
    Updates the custody chain manifest.
    """
    result = await vault_engine.verify_evidence_integrity(db, evidence_id)
    if result.get("status") == "ERROR":
        raise HTTPException(status_code=404, detail=result.get("message"))
    
    # If verified, we can also advance source status to 'validated' in readiness engine!
    if result.get("verified"):
        # Fetch item to get source_key
        items = await vault_engine.get_all_vault_items(db)
        match = next((i for i in items if i.evidence_id == evidence_id), None)
        if match:
            await readiness_engine.update_source_status(
                db=db,
                source_key=match.source_key,
                new_status="validated",
                details=f"Cryptographically verified SHA-256 hash {result['calculated_sha256'][:16]}..."
            )

    return result
