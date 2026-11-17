@echo off
title CloudShield - SIEM Server
echo ========================================================
echo   Starting CloudShield Cyber Security Platform...
echo ========================================================
echo.
cd /d "%~dp0"
echo Starting FastAPI & Uvicorn on http://127.0.0.1:8000 ...
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
pause
