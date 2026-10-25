from typing import Optional, List
from fastapi import APIRouter, Query
from backend.app.engines.evaluation_engine import evaluation_engine

router = APIRouter()

@router.get("/evaluation/experiments")
async def run_offline_experiments(
    budgets: Optional[str] = Query("20,40,60,80", description="Comma-separated budget limits")
):
    """
    Executes academically defensible offline evaluation comparing 5 prioritization strategies
    across multiple budget levels using reproducible controlled ground-truth workloads.
    """
    try:
        budget_list = [float(b.strip()) for b in budgets.split(",") if b.strip()]
    except Exception:
        budget_list = [20.0, 40.0, 60.0, 80.0]

    return evaluation_engine.run_budget_experiments(budget_levels=budget_list)

@router.get("/evaluation/context-shift")
async def run_context_shift_experiment():
    """
    Simulates dynamic adversary threat-context shift (T1110 SSH Brute Force -> T1548 Sudo Privilege Escalation)
    to measure strategy adaptation speed, recall degradation, and recovery penalty.
    """
    return evaluation_engine.run_context_shift_experiment()
