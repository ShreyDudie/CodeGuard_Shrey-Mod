#!/usr/bin/env bash
# Start the CodeGuard service on port 8000.  Expose it with: cloudflared tunnel --url http://127.0.0.1:8000   (or: ngrok http 8000)
cd "$(dirname "$0")/.."
exec python -W ignore -m codeguard serve --port 8000
