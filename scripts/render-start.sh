#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export RISKSCOPE_MODE=hosted
# Guest capabilities and temporary workspaces intentionally belong to one process.
exec python -m uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port "${PORT:-10000}" --workers 1 --no-access-log
