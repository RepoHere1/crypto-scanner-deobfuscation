#!/data/data/com.termux/files/usr/bin/bash
#
# LAUNCH_ALL - Start all scanning and monitoring tasks in harmony
# Runs: throttled mass scan + crypto scanner + optional startup notification
#

set -o pipefail

# API keys used by scanners
export ALCHEMY_API_KEY="${ALCHEMY_API_KEY:-mi8wM6xm7rRBMYTCjHfM5}"

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
HOME_DIR="$HOME"
LOGFILE="$HOME_DIR/launch_all.log"
PID_DIR="$HOME_DIR/.run_pids"
MASS_RESULTS="$HOME_DIR/.trufflehog_mass_results.jsonl"
SCAN_RESULTS="$HOME_DIR/.trufflehog_results.jsonl"

mkdir -p "$(dirname "$LOGFILE")" "$PID_DIR"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOGFILE"
}

notify() {
    local title="$1"
    local msg="$2"
    if command -v termux-notification >/dev/null 2>&1; then
        termux-notification --title "$title" --content "$msg" 2>/dev/null || true
    fi
}

is_running() {
    local pidfile="$1"
    [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null
}

stop_if_running() {
    local pidfile="$1"
    if is_running "$pidfile"; then
        kill "$(cat "$pidfile")" 2>/dev/null || true
        rm -f "$pidfile"
    fi
}

# ---------------------------------------------------------------------------
# Startup banner
# ---------------------------------------------------------------------------
log "========================================"
log "LAUNCH_ALL - Starting all services"
log "========================================"

# Ensure crypto scanner input file is fresh (old results discarded)
: > "$SCAN_RESULTS"

# Process paste box to populate fresh input
if [ -f "$HOME_DIR/paste_box.py" ]; then
    log "[*] Processing paste box..."
    python3 "$HOME_DIR/paste_box.py" >> "$LOGFILE" 2>&1 || true
fi

# ---------------------------------------------------------------------------
# 1. Throttled mass scan
# ---------------------------------------------------------------------------
MASS_PIDFILE="$PID_DIR/mass_scan.pid"
if [ -f "$HOME_DIR/run_throttled.py" ]; then
    if is_running "$MASS_PIDFILE"; then
        log "[*] Mass scan already running (PID $(cat "$MASS_PIDFILE"))"
    else
        log "[*] Launching throttled mass scan (background)..."
        nohup python3 "$HOME_DIR/run_throttled.py" >> "$LOGFILE" 2>&1 &
        echo $! > "$MASS_PIDFILE"
        log "[+] Mass scan started (PID: $(cat "$MASS_PIDFILE"))"
    fi
else
    log "[!] WARNING: run_throttled.py not found, skipping mass scan"
fi

# ---------------------------------------------------------------------------
# 2. Crypto scanner
# ---------------------------------------------------------------------------
SCAN_PIDFILE="$PID_DIR/crypto_scanner.pid"
if [ -f "$HOME_DIR/crypto_scanner.py" ]; then
    if is_running "$SCAN_PIDFILE"; then
        log "[*] Crypto scanner already running (PID $(cat "$SCAN_PIDFILE"))"
    else
        log "[*] Launching crypto scanner..."
        nohup python3 "$HOME_DIR/crypto_scanner.py" "$SCAN_RESULTS" >> "$HOME_DIR/crypto_scanner_scanner.log" 2>&1 &
        echo $! > "$SCAN_PIDFILE"
        log "[+] Crypto scanner started (PID: $(cat "$SCAN_PIDFILE"))"
    fi
else
    log "[!] WARNING: crypto_scanner.py not found, skipping crypto scanner"
fi

# ---------------------------------------------------------------------------
# 3. Notification
# ---------------------------------------------------------------------------
notify "Crypto Scanner" "All scanning services started"

# ---------------------------------------------------------------------------
# 4. Summary
# ---------------------------------------------------------------------------
log "[*] Background jobs:"
jobs -l | tee -a "$LOGFILE"
log "[*] All services launched"
log "[*] Main log: $LOGFILE"
log "[*] Crypto scanner log: $HOME_DIR/crypto_scanner_scanner.log"
log "[*] To see live output: tail -f $LOGFILE"
log "[*] To stop all: bash $HOME_DIR/stop_all.sh"

echo ""
echo "========================================"
echo "SUMMARY"
echo "========================================"
echo "Status: All services running in background"
echo "Logs:   $LOGFILE"
echo "        $HOME_DIR/crypto_scanner_scanner.log"
echo ""
echo "Useful commands:"
echo "  tail -f $LOGFILE               # Watch live main logs"
echo "  tail -f ~/crypto_scanner_scanner.log  # Watch crypto scanner"
echo "  bash $HOME_DIR/stop_all.sh     # Stop all services"
echo "  pkill -f run_throttled.py      # Stop truffle scan"
echo "  pkill -f crypto_scanner.py     # Stop crypto scanner"
echo "  scanmem                        # Tail latest findings"
echo "  scanstatus                     # Show scanner status"
echo "========================================"
