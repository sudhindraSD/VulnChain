@echo off
REM VulnChain web demo launcher — starts the backend on http://127.0.0.1:8000
REM (serves both the API and the built frontend). First time only:
REM   1. pip install -r webapp\requirements.txt
REM   2. cd webapp\frontend && npm install && npm run build
cd /d "%~dp0..\webapp"
python server.py
