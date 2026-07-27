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

# 2. (Optional) You can add more services here
#    Example: start a web server, monitoring daemon, etc.
#
# if [ -f "$HOME/my_service.py" ]; then
#     log "[*] Launching my_service.py..."
#     nohup python3 "$HOME/my_service.py" >> "$LOGFILE" 2>&1 &
#     log "[+] my_service started (PID: $!)"
# fi

# 3. Show running background jobs
log "[*] Background jobs:"
jobs -l | tee -a "$LOGFILE"

log "[*] All services launched"
log "[*] Log file: $LOGFILE"
log "[*] To see live output: tail -f $LOGFILE"
log "[*] To stop all: kill %1 %2 ... or use 'killall python3'"

echo ""
echo "========================================"
echo "SUMMARY"
echo "========================================"
echo "Status: All services running in background"
echo "Logs:   $LOGFILE"
echo ""
echo "Useful commands:"
echo "  tail -f $LOGFILE   # Watch live logs"
echo "  jobs -l            # List background jobs"
echo "  kill %1            # Stop job number 1"
echo "  pkill -f run_throttled.py  # Stop scan"
echo "========================================"
