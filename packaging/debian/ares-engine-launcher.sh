#!/bin/bash
# Ares Engine Launcher — starts the server if not running and opens the browser

SERVER_URL="http://127.0.0.1:8080"
PID_FILE="/tmp/ares-engine.pid"

# Check if server is already running
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        # Server is running, just open browser
        xdg-open "$SERVER_URL" 2>/dev/null || true
        exit 0
    fi
    rm -f "$PID_FILE"
fi

# Start the server
/usr/share/ares-engine/ares &
ARES_PID=$!
echo "$ARES_PID" > "$PID_FILE"

# Wait for server to be ready
for i in $(seq 1 30); do
    if curl -s "$SERVER_URL/health" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Open browser
xdg-open "$SERVER_URL" 2>/dev/null || true

# Wait for process
wait "$ARES_PID"
