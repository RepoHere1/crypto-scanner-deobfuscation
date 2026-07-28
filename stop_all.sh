#!/data/data/com.termux/files/usr/bin/bash
# Stop all scanning services cleanly

set -euo pipefail

HOME_DIR="$HOME"
PID_DIR="$HOME_DIR/.run_pids"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

stop_pidfile() {
    local pidfile="$1"
    local name="$2"
    if [ -f "$pidfile" ]; then
        local pid
        pid="$(cat "$pidfile")"
        if kill -0 "$pid" 2>/dev/null; then
            log "[*] Stopping $name (PID $pid)..."
            kill "$pid" 2>/dev/null || true
            sleep 1
            if kill -0 "$pid" 2>/dev/null; then
                log "[*] Force killing $name..."
                kill -9 "$pid" 2>/dev/null || true
            fi
        fi
        rm -f "$pidfile"
    fi
}

log "[*] Stopping all scanning services..."
stop_pidfile "$PID_DIR/mass_scan.pid" "mass scan"
stop_pidfile "$PID_DIR/crypto_scanner.pid" "crypto scanner"

# Fallback pkill
pkill -f run_throttled.py 2>/dev/null || true
pkill -f crypto_scanner.py 2>/dev/null || true

if command -v termux-notification >/dev/null 2>&1; then
    termux-notification --title "Crypto Scanner" --content "All scanning services stopped" 2>/dev/null || true
fi

log "[+] All services stopped"
