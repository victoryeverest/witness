#!/usr/bin/env bash
# Start the WITNESS backend on Linux / macOS, then print how to start the console.
#
#   bash scripts/start.sh            # http://127.0.0.1:8000
#   WITNESS_PORT=8010 bash scripts/start.sh
set -euo pipefail

PROJ_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BACKEND="$PROJ_ROOT/backend"
PORT="${WITNESS_PORT:-8000}"
LOG="${TMPDIR:-/tmp}/witness-backend.log"
PIDFILE="${TMPDIR:-/tmp}/witness-backend.pid"

PYTHON="$(command -v python3 || command -v python || true)"
if [ -z "$PYTHON" ]; then
    echo "Error: python3 not found in PATH. Install Python 3.11+ from https://python.org" >&2
    exit 1
fi
echo "Using $("$PYTHON" --version 2>&1)"

# Install from requirements.txt (the single source of truth) if anything is missing.
if ! "$PYTHON" -c "import fastapi, sqlalchemy, greenlet, aiosqlite, pydantic_settings" 2>/dev/null; then
    echo "Installing Python dependencies from backend/requirements.txt ..."
    "$PYTHON" -m pip install --quiet -r "$BACKEND/requirements.txt"
fi

mkdir -p "$PROJ_ROOT/data"

# Stop a previous instance started by this script.
if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "Stopping previous backend (PID $(cat "$PIDFILE"))"
    kill "$(cat "$PIDFILE")" 2>/dev/null || true
    sleep 1
fi

if curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$PORT/"; then
    echo "Error: port $PORT is already in use by another program. Set WITNESS_PORT to a free port." >&2
    exit 1
fi

echo "Starting WITNESS backend on http://127.0.0.1:$PORT ..."
cd "$BACKEND"
nohup "$PYTHON" -m uvicorn witness.api.app:app --host 0.0.0.0 --port "$PORT" --log-level warning \
    > "$LOG" 2>&1 < /dev/null &
echo $! > "$PIDFILE"

for _ in $(seq 1 40); do
    if curl -fsS "http://127.0.0.1:$PORT/health" > /dev/null 2>&1; then
        echo "Backend is up (PID $(cat "$PIDFILE"))."
        curl -fsS "http://127.0.0.1:$PORT/health"; echo
        echo
        echo "Console (separate terminal):  cd $PROJ_ROOT && bun install && bun run dev   # or npm"
        echo "API docs:                     http://127.0.0.1:$PORT/docs"
        echo "Flagship demo:                curl -X POST http://127.0.0.1:$PORT/demo/flagship -H 'Content-Type: application/json' -d '{\"max_iterations\": 5}'"
        echo "Benchmark (CLI):              cd $BACKEND && $PYTHON -m witness.benchmark"
        echo "Log:                          $LOG"
        echo "Stop:                         kill \$(cat $PIDFILE)"
        exit 0
    fi
    sleep 0.5
done

echo "Backend did not come up within 20 s. Last log lines:" >&2
tail -20 "$LOG" >&2
exit 1
