from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from backend.app.db.session import get_db
from backend.app.db.models import DetectionAlert
from backend.app.engines.detection_engine import detection_engine

router = APIRouter()

@router.get("/detection/alerts")
async def get_alerts(
    status: Optional[str] = None,
    limit: int = Query(50, le=100),
    db: AsyncSession = Depends(get_db)
):
    query = select(DetectionAlert).order_by(desc(DetectionAlert.created_at)).limit(limit)
    if status:
        query = query.where(DetectionAlert.status == status)
    result = await db.execute(query)
    alerts = result.scalars().all()
    return alerts

@router.get("/detection/rules")
async def get_detection_rules():
    return detection_engine.rules
