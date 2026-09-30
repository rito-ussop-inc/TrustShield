@echo off
echo Starting TrustShield frontend on http://localhost:5173
cd /d "%~dp0frontend"
npm install
npm run dev
