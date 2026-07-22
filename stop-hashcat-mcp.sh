#!/bin/bash
# Stop the hashcat MCP server

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PID_FILE="$SCRIPT_DIR/.hashcat-mcp.pid"

if [ ! -f "$PID_FILE" ]; then
    echo "[-] No PID file found. Is the server running?"
    echo "    Try: pkill -f 'hashcatmcp.py --http'"
    exit 1
fi

PID=$(cat "$PID_FILE")
if kill -0 "$PID" 2>/dev/null; then
    kill "$PID" 2>/dev/null
    sleep 1
    if kill -0 "$PID" 2>/dev/null; then
        echo "[-] Process still running, sending SIGKILL..."
        kill -9 "$PID" 2>/dev/null
    fi
    echo "[+] Server stopped (PID: $PID)"
else
    echo "[-] Process $PID not running"
fi
rm -f "$PID_FILE"
