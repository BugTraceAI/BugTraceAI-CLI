#!/bin/bash
set -e

# Create directories for persistent data (volume mounts may override)
mkdir -p /app/reports /app/logs /app/data

# Pass all arguments to bugtrace CLI
# Default CMD is: serve --host 0.0.0.0 --port 8000
exec python -m bugtrace "$@"
