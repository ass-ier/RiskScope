#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export RISKSCOPE_DATABASE_URL="${RISKSCOPE_DATABASE_URL:-sqlite:///$(pwd)/.local/riskscope.db}"
export RISKSCOPE_FRONTEND_DIR="$(pwd)/frontend/dist"
mkdir -p .local
PORT="${PORT:-$(.venv/bin/python -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')}"
cd backend
../.venv/bin/alembic upgrade head
printf 'RiskScope local workstation: http://127.0.0.1:%s\n' "$PORT"
exec ../.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port "$PORT"
