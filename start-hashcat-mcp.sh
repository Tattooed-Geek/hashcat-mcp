#!/bin/bash
# Hashcat MCP Server - Startup Script
# Starts the hashcat MCP server in HTTP mode for remote access
#
# Usage:
#   ./start-hashcat-mcp.sh              # default port 9090
#   ./start-hashcat-mcp.sh 8080         # custom port
#   ./start-hashcat-mcp.sh 9090 --debug # verbose logging

PORT="${1:-9090}"
ARGS="--http --port $PORT"

if [ "$2" = "--debug" ]; then
    ARGS="$ARGS --debug"
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PID_FILE="$SCRIPT_DIR/.hashcat-mcp.pid"
LOG_FILE="$SCRIPT_DIR/hashcat-mcp.log"

# Check if already running
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE")
    if kill -0 "$OLD_PID" 2>/dev/null; then
        echo "[-] Server already running (PID: $OLD_PID)"
        echo "    Stop it first: kill $OLD_PID"
        exit 1
    fi
    rm -f "$PID_FILE"
fi

# Check hashcat is installed
if ! command -v hashcat &>/dev/null; then
    echo "[-] hashcat not found in PATH"
    echo "    Install: brew install hashcat"
    exit 1
fi

echo "[+] Starting hashcat MCP server on port $PORT..."
cd "$SCRIPT_DIR" || exit 1
nohup python3 hashcatmcp.py $ARGS > "$LOG_FILE" 2>&1 &
PID=$!
echo "$PID" > "$PID_FILE"

# Wait and verify
sleep 1
if kill -0 "$PID" 2>/dev/null; then
    echo "[+] Server started (PID: $PID)"
    echo "    Logs: $LOG_FILE"
    echo "    Test: curl http://localhost:$PORT/health"
else
    echo "[-] Server failed to start. Check logs:"
    tail -5 "$LOG_FILE"
    rm -f "$PID_FILE"
    exit 1
fi
