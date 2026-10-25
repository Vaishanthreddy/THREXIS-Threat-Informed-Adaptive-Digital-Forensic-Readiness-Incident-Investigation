@echo off
echo Starting THREXIS Full System (Backend + Frontend)...
start "THREXIS Backend (Port 8000)" cmd /k ".\venv\Scripts\python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload"
start "THREXIS Frontend (Port 5173)" cmd /k "cd frontend && npm run dev"
echo Both servers launched in separate windows.
echo Frontend: http://localhost:5173
echo Backend:  http://localhost:8000
