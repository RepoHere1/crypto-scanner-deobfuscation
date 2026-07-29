#!/data/data/com.termux/files/usr/bin/bash
HOME_DIR="${HOME:-/data/data/com.termux/files/home}"
PID_DIR="$HOME_DIR/.run_pids"
LOG="$HOME_DIR/watchdog.log"
mkdir -p "$PID_DIR"
# refresh wake-lock periodically so multi-day survives doze
termux-wake-lock >/dev/null 2>&1 || true

_alive_pidfile() {
  local f="$1"
  [ -f "$f" ] || return 1
  local p
  p=$(tr -d ' \r\n' <"$f" 2>/dev/null)
  [ -n "$p" ] && kill -0 "$p" 2>/dev/null
}

while true; do
  termux-wake-lock >/dev/null 2>&1 || true

  # keepalive supervisor
  if ! _alive_pidfile "$PID_DIR/keepalive.pid" && ! pgrep -f "keepalive.py" >/dev/null 2>&1; then
    nohup python3 "$HOME_DIR/keepalive.py" >>"$HOME_DIR/keepalive.log" 2>&1 &
    echo $! > "$PID_DIR/keepalive.pid"
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] restarted keepalive pid=$!" >>"$LOG"
  fi

  # crypto scanner
  if ! _alive_pidfile "$PID_DIR/crypto_scanner.pid" && ! pgrep -f "crypto_scanner.py" >/dev/null 2>&1; then
    SCAN_FILE="$HOME_DIR/.trufflehog_mass_results.jsonl"
    [ -s "$SCAN_FILE" ] || SCAN_FILE="$HOME_DIR/.trufflehog_results.jsonl"
    : >> "$SCAN_FILE"
    nohup env BALANCE_WORKERS="${BALANCE_WORKERS:-24}" MASS_SCAN_JOBS="${MASS_SCAN_JOBS:-4}" python3 "$HOME_DIR/crypto_scanner.py" "$SCAN_FILE" >>"$HOME_DIR/crypto_scanner_scanner.log" 2>&1 &
    echo $! > "$PID_DIR/crypto_scanner.pid"
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] restarted crypto_scanner pid=$!" >>"$LOG"
  fi

  # adaptive / mass
  if ! _alive_pidfile "$PID_DIR/adaptive_scan.pid" && ! pgrep -f "adaptive_throttler.py" >/dev/null 2>&1; then
    if ! _alive_pidfile "$PID_DIR/mass_scan.pid" && ! pgrep -f "mass_scan.py" >/dev/null 2>&1; then
      if [ -f "$HOME_DIR/adaptive_throttler.py" ]; then
        nohup env MASS_SCAN_JOBS="${MASS_SCAN_JOBS:-4}" BALANCE_WORKERS="${BALANCE_WORKERS:-24}" python3 "$HOME_DIR/adaptive_throttler.py" >>"$HOME_DIR/adaptive_scan.log" 2>&1 &
        echo $! > "$PID_DIR/adaptive_scan.pid"
        echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] restarted adaptive pid=$!" >>"$LOG"
      elif [ -f "$HOME_DIR/run_throttled.py" ]; then
        nohup python3 "$HOME_DIR/run_throttled.py" >>"$HOME_DIR/run_throttled_out.log" 2>&1 &
        echo $! > "$PID_DIR/mass_scan.pid"
        echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] restarted mass pid=$!" >>"$LOG"
      fi
    fi
  fi

  sleep 45
done
