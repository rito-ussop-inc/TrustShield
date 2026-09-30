@echo off
echo Starting TrustShield backend on http://localhost:8000
cd /d "%~dp0"
python ml\training\train_message.py
uvicorn app.main:app --host 0.0.0.0 --port 8000 --app-dir backend
