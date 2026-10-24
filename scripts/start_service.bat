@echo off
REM Start the CodeGuard service on port 8000 (bind to all interfaces so a tunnel or a phone on the same Wi-Fi can reach it).
REM Then, in a second window, expose it:   cloudflared tunnel --url http://127.0.0.1:8000     (or: ngrok http 8000)
REM Check it the way the judge will:        python scripts\endpoint_check.py http://127.0.0.1:8000
cd /d "%~dp0.."
python -W ignore -m codeguard serve --port 8000
