from fastapi import APIRouter, HTTPException
from backend.app.engines.mitre_engine import mitre_engine

router = APIRouter()

@router.get("/intelligence/techniques")
async def get_mitre_techniques():
    """
    Returns all configured MITRE ATT&CK Enterprise techniques with tactics,
    subtechniques, detection methods, and evidence sources.
    """
    return mitre_engine.get_all_techniques()

@router.get("/intelligence/technique/{technique_id}")
async def get_technique_details(technique_id: str):
    tech = mitre_engine.get_technique(technique_id)
    if not tech:
        raise HTTPException(status_code=404, detail=f"MITRE technique {technique_id} not found")
    return tech
