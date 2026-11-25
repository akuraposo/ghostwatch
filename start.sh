#!/usr/bin/env bash
set -euo pipefail
export PORT="${PORT:-8080}"
echo "Starting GhostWatch v2.1 on port ${PORT}..."
exec python3 ghostwatch.py --host 0.0.0.0 --port "${PORT}"
