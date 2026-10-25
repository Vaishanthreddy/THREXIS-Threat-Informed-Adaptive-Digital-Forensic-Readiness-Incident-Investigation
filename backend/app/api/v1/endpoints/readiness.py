from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from backend.app.db.session import get_db
from backend.app.db.models import ReadinessAssessmentHistory
from backend.app.schemas.api_schemas import UpdateSourceStatusInput
from backend.app.engines.readiness_engine import readiness_engine
from backend.app.core.events import manager

router = APIRouter()

@router.get("/readiness")
async def get_readiness_assessment(
    threat_context: Optional[str] = Query(None, description="Active threat technique (e.g., T1110)"),
    db: AsyncSession = Depends(get_db)
):
    """
    Computes weighted forensic readiness score:
    Readiness (%) = 100 * Σ(w_i * s_i) / Σ(w_i)
    Returns source details, gaps, and remediation actions.
    """
    assessment = await readiness_engine.calculate_readiness(db, threat_context=threat_context)
    return assessment

@router.post("/readiness/source")
async def update_evidence_source_status(
    payload: UpdateSourceStatusInput,
    db: AsyncSession = Depends(get_db)
):
    """
    Updates status of an evidence source (e.g. marking audit logs as 'collected' or 'validated').
    """
    updated = await readiness_engine.update_source_status(
        db=db,
        source_key=payload.source_key,
        new_status=payload.status,
        details=payload.details
    )
    if not updated:
        raise HTTPException(status_code=404, detail=f"Source {payload.source_key} not found")

    new_assessment = await readiness_engine.calculate_readiness(db)
    await readiness_engine.record_snapshot(db, new_assessment)

    # Broadcast updated readiness to all connected dashboards
    await manager.broadcast({
        "type": "READINESS_UPDATED",
        "score": new_assessment["score"],
        "category": new_assessment["category"],
        "coverage_percentage": new_assessment["coverage_percentage"],
        "gaps_count": new_assessment["gaps_count"]
    })

    return {
        "status": "success",
        "source": {
            "source_key": updated.source_key,
            "status": updated.status,
            "readiness_factor": updated.readiness_factor
        },
        "new_readiness": new_assessment
    }

@router.get("/readiness/history")
async def get_readiness_history(
    limit: int = Query(20, le=100),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(ReadinessAssessmentHistory).order_by(desc(ReadinessAssessmentHistory.assessed_at)).limit(limit))
    records = result.scalars().all()
    return records
