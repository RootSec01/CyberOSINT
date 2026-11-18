#!/bin/sh
set -e
python -m raqeeb.prepare_production_schema --new-tables
exec uvicorn raqeeb.main:app --host 0.0.0.0 --port 8000 --workers 1 \
     --proxy-headers --forwarded-allow-ips '*' --no-server-header
