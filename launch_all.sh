#!/data/data/com.termux/files/usr/bin/bash
#
# LAUNCH_ALL - Run all scanning and monitoring tasks in harmony
# This script orchestrates multiple background tasks
#

set -o pipefail

# Log file
LOGFILE="$HOME/launch_all.log"
mkdir -p "$(dirname "$LOGFILE")"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOGFILE"
}

log "========================================"
log "LAUNCH_ALL - Starting all services"
log "========================================"

# 1. Launch the throttled mass scan (trufflehog-mass with 2 jobs)
#    This runs the heavy lifting in background with low CPU priority
if [ -f "$HOME/run_throttled.py" ]; then
    log "[*] Launching throttled mass scan (background)..."
    nohup python3 "$HOME/run_throttled.py" >> "$LOGFILE" 2>&1 &
    SCAN_PID=$!
    log "[+] Mass scan started (PID: $SCAN_PID)"
else
    log "[!] WARNING: run_throttled.py not found, skipping mass scan"
fi

# 2. Launch crypto scanner
if [ -f "$HOME/crypto_scanner.py" ]; then
    log "[*] Launching crypto scanner..."
    nohup python3 "$HOME/crypto_scanner.py" "$HOME/.trufflehog_results.jsonl" >> "$HOME/crypto_scanner_scanner.log" 2>&1 &
    SCANNER_PID=$!
    log "[+] Crypto scanner started (PID: $SCANNER_PID)"
else
    log "[!] WARNING: crypto_scanner.py not found, skipping crypto scanner"
fi

# 3. (Optional) You can add more services here
#    Example: start a web server, monitoring daemon, etc.
#
# if [ -f "$HOME/my_service.py" ]; then
#     log "[*] Launching my_service.py..."
#     nohup python3 "$HOME/my_service.py" >> "$LOGFILE" 2>&1 &
#     log "[+] my_service started (PID: $!)"
# fi

# 4. Show running background jobs
log "[*] Background jobs:"
jobs -l | tee -a "$LOGFILE"

log "[*] All services launched"
log "[*] Main log: $LOGFILE"
log "[*] Crypto scanner log: $HOME/crypto_scanner_scanner.log"
log "[*] To see live output: tail -f $LOGFILE"
log "[*] To stop all: kill %1 %2 ... or use 'killall python3'"

echo ""
echo "========================================"
echo "SUMMARY"
echo "========================================"
echo "Status: All services running in background"
echo "Logs:   $LOGFILE"
echo "        $HOME/crypto_scanner_scanner.log"
echo ""
echo "Useful commands:"
echo "  tail -f $LOGFILE               # Watch live main logs"
echo "  tail -f ~/crypto_scanner_scanner.log  # Watch crypto scanner"
echo "  jobs -l                        # List background jobs"
echo "  kill %1                        # Stop job number 1"
echo "  pkill -f run_throttled.py      # Stop truffle scan"
echo "  pkill -f crypto_scanner.py     # Stop crypto scanner"
echo "  scanmem                        # Tail latest findings"
echo "  scanstatus                     # Show scanner status"
echo "========================================"
