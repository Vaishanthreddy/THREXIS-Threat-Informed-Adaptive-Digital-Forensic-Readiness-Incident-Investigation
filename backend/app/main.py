from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from backend.app.core.config import settings
from backend.app.core.events import manager
from backend.app.api.v1.router import api_router
from backend.app.db.session import engine, Base, AsyncSessionLocal
from backend.app.engines.readiness_engine import readiness_engine

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables on startup
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        
    # Initialize default evidence sources in database
    async with AsyncSessionLocal() as session:
        await readiness_engine.initialize_sources_if_empty(session)
        
    yield
    
    # Clean shutdown
    await engine.dispose()

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Threat-Informed Adaptive Digital Forensic Readiness & Incident Investigation System Backend API",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware for local frontend and host communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix=settings.API_V1_PREFIX)

@app.get("/health")
@app.get("/api/v1/health")
async def health():
    return {
        "status": "healthy",
        "system": "THREXIS",
        "mode": "Forensic Telemetry Engine Active",
        "api_version": "v1"
    }

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)
