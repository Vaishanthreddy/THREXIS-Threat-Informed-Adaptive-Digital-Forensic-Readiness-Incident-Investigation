from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from backend.app.db.session import get_db
from backend.app.db.models import PrioritizationRecord
from backend.app.schemas.api_schemas import PrioritizeRequest
from backend.app.engines.prioritization_engine import prioritization_engine

router = APIRouter()

@router.post("/prioritization/run")
async def run_evidence_prioritization(
    payload: PrioritizeRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Executes an evidence prioritization run with the specified strategy (adaptive, static, random, threat_agnostic, frozen_context),
    budget limit, and observed threat context.
    """
    result = await prioritization_engine.prioritize(
        db=db,
        strategy=payload.strategy,
        budget=payload.budget,
        threat_context=payload.threat_context,
        initial_threat_context="BASELINE"
    )
    return result

@router.get("/prioritization/compare")
async def compare_prioritization_strategies(
    budget: float = Query(50.0, ge=10.0, le=200.0),
    threat_context: str = Query("T1110", description="Observed threat context"),
    db: AsyncSession = Depends(get_db)
):
    """
    Runs a benchmark comparison across all 5 strategies under the same collection budget.
    """
    comparisons = await prioritization_engine.compare_all_strategies(
        db=db,
        budget=budget,
        threat_context=threat_context
    )
    return comparisons

@router.get("/prioritization/history")
async def get_prioritization_history(
    limit: int = Query(20, le=100),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(PrioritizationRecord).order_by(desc(PrioritizationRecord.timestamp)).limit(limit))
    return result.scalars().all()
