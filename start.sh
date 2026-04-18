#!/bin/bash
# Backend start script — used by Railpack auto-detect and local runs.
# Railway injects $PORT automatically; defaults to 8000 locally.
set -e
exec uvicorn vuln_mesh.dashboard.server:app \
    --host 0.0.0.0 \
    --port "${PORT:-8000}" \
    --workers 1
