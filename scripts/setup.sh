#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHON="${PYTHON:-python3.12}"
"$PYTHON" -c 'import sys; assert sys.version_info >= (3, 12), "Python 3.12+ required"'
"$PYTHON" -m venv .venv
.venv/bin/pip install -q -r backend/requirements.lock -e 'backend[dev]'
npm --prefix frontend ci --no-audit --no-fund
npm --prefix frontend run build
mkdir -p .local
export RISKSCOPE_DATABASE_URL="sqlite:///$(pwd)/.local/riskscope.db"
cd backend
../.venv/bin/alembic upgrade head
printf '\nReady. Run: bash scripts/run.sh (from the repository root)\n'
