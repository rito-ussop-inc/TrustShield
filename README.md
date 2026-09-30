# TrustShield — Verify Before You Trust

Web-based digital trust assessment: URLs, messages, QR codes, document integrity → explainable risk assessment.

## Quick start (local)

### 1. Backend (FastAPI)
```powershell
cd C:\Users\RITOYASH\OneDrive\Desktop\TrustShiled
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r backend\requirements.txt
python ml\training\train_message.py
uvicorn app.main:app --reload --port 8000 --app-dir backend
```
Health: http://localhost:8000/health

### 2. Frontend (React + Vite)
```powershell
cd frontend
npm install
npm run dev   # http://localhost:5173 (proxies /api → :8000)
```

### 3. Docker
```powershell
docker compose -f docker\docker-compose.yml up --build
```

## API
- POST /api/v1/analyze/url {url}
- POST /api/v1/analyze/message {text}
- POST /api/v1/analyze/qr (multipart file)
- POST /api/v1/analyze/document (multipart file + optional reference_sha256)
- GET /api/v1/analyses / GET /api/v1/analyses/{id}
- GET /health, GET /api/v1/providers/status

## Primary demo (PRD §14)
1. Paste: “Your account will be blocked within 24 hours. Verify immediately at http://secure-login-verify.tk/login”
2. System extracts URL, flags urgency/credential signals, analyzes URL lexicals, queries threat intel, combines in Trust Engine.
3. UI shows risk + evidence + recommendation (verify independently, don't enter credentials).

## Notes
- Unknown inputs are NEVER labeled safe — LOW only on low observed risk, else MEDIUM/HIGH/CRITICAL/UNKNOWN.
- Document hash match = integrity only, not authenticity.
- Providers degrade to `unavailable`/`not_configured`; local analysis continues.
- Secrets only via env (.env — see .env.example). Never in frontend.
