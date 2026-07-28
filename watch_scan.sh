#!/data/data/com.termux/files/usr/bin/bash
# Watch scanner with a live spinner and status updates

HOME_DIR="$HOME"
PID_DIR="$HOME_DIR/.run_pids"
MASS_PIDFILE="$PID_DIR/mass_scan.pid"
SCAN_PIDFILE="$PID_DIR/crypto_scanner.pid"
STATUS_FILE="$HOME_DIR/crypto_scanner_status.txt"
MASS_LOG="$HOME_DIR/launch_all.log"
SCAN_LOG="$HOME_DIR/crypto_scanner_scanner.log"

SPINNER='|/-\\'
i=0

cleanup() {
    echo ""
    echo "[*] Stopped watching."
    exit 0
}
trap cleanup INT TERM

is_running() {
    local pidfile="$1"
    [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null
}

last_mass_lines=0
last_scan_lines=0

printf "[*] Watching scanners...\n"

while true; do
    char="${SPINNER:i%4:1}"

    mass_status="stopped"
    scan_status="stopped"
    is_running "$MASS_PIDFILE" && mass_status="running"
    is_running "$SCAN_PIDFILE" && scan_status="running"

    status_text="unknown"
    [ -f "$STATUS_FILE" ] && status_text="$(cat "$STATUS_FILE" | tr '\n' ' ')"

    mass_lines=$(wc -l < "$MASS_LOG" 2>/dev/null || echo 0)
    scan_lines=$(wc -l < "$SCAN_LOG" 2>/dev/null || echo 0)

    printf "\r %s Mass: %s | Crypto: %s | Status: %s | mass_log:%s scan_log:%s " \
        "$char" "$mass_status" "$scan_status" "$status_text" "$mass_lines" "$scan_lines"

    sleep 0.3
    ((i++))
done
