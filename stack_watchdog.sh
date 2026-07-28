#!/data/data/com.termux/files/usr/bin/bash
HOME_DIR="$HOME"
PID_DIR="$HOME_DIR/.run_pids"
LOG="$HOME_DIR/watchdog.log"
mkdir -p "$PID_DIR"
while true; do
  # crypto
  if [ ! -f "$PID_DIR/crypto_scanner.pid" ] || ! kill -0 "$(cat "$PID_DIR/crypto_scanner.pid" 2>/dev/null)" 2>/dev/null; then
    SCAN_FILE="$HOME_DIR/.trufflehog_mass_results.jsonl"
    [ -s "$SCAN_FILE" ] || SCAN_FILE="$HOME_DIR/.trufflehog_results.jsonl"
    : >> "$SCAN_FILE"
    nohup python3 "$HOME_DIR/crypto_scanner.py" "$SCAN_FILE" >>"$HOME_DIR/crypto_scanner_scanner.log" 2>&1 &
    echo $! > "$PID_DIR/crypto_scanner.pid"
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] restarted crypto_scanner pid=$!" >>"$LOG"
  fi
  # adaptive / mass
  if [ ! -f "$PID_DIR/adaptive_scan.pid" ] || ! kill -0 "$(cat "$PID_DIR/adaptive_scan.pid" 2>/dev/null)" 2>/dev/null; then
    if [ ! -f "$PID_DIR/mass_scan.pid" ] || ! kill -0 "$(cat "$PID_DIR/mass_scan.pid" 2>/dev/null)" 2>/dev/null; then
      if [ -f "$HOME_DIR/adaptive_throttler.py" ]; then
        nohup python3 "$HOME_DIR/adaptive_throttler.py" >>"$HOME_DIR/adaptive_scan.log" 2>&1 &
        echo $! > "$PID_DIR/adaptive_scan.pid"
        echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] restarted adaptive pid=$!" >>"$LOG"
      elif [ -f "$HOME_DIR/run_throttled.py" ]; then
        nohup python3 "$HOME_DIR/run_throttled.py" >>"$HOME_DIR/run_throttled_out.log" 2>&1 &
        echo $! > "$PID_DIR/mass_scan.pid"
        echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] restarted mass pid=$!" >>"$LOG"
      fi
    fi
  fi
  sleep 60
done
