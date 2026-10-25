import os
from pathlib import Path
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent.parent.parent

class Settings(BaseModel):
    PROJECT_NAME: str = "THREXIS: Threat-Informed Adaptive Digital Forensic Readiness & Incident Investigation System"
    API_V1_PREFIX: str = "/api/v1"
    SECRET_COLLECTOR_KEY: str = os.getenv("THREXIS_COLLECTOR_KEY", "threxis-collector-secret-2026")
    DATABASE_URL: str = os.getenv("THREXIS_DB_URL", f"sqlite+aiosqlite:///{BASE_DIR}/threxis.db")
    VAULT_DIR: Path = BASE_DIR / "vault_storage"
    DATA_DIR: Path = BASE_DIR / "app" / "data"
    REPORTS_DIR: Path = BASE_DIR / "reports"
    
    # Detection thresholds
    SSH_FAILURE_THRESHOLD: int = 3
    SSH_FAILURE_WINDOW_SECONDS: int = 60
    
    # Default Evidence Budget
    DEFAULT_EVIDENCE_BUDGET: float = 100.0

settings = Settings()

# Ensure directories exist
settings.VAULT_DIR.mkdir(parents=True, exist_ok=True)
settings.DATA_DIR.mkdir(parents=True, exist_ok=True)
settings.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
