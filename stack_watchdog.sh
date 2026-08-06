#!/data/data/com.termux/files/usr/bin/bash
# Detached stack watchdog — restarts services OUTSIDE any Termux session TTY.
# Also rotates multi-GB result/log files so they cannot OOM / LMK Termux again.
HOME_DIR="${HOME:-/data/data/com.termux/files/home}"
PID_DIR="$HOME_DIR/.run_pids"
LOG="$HOME_DIR/watchdog.log"
mkdir -p "$PID_DIR"

# Safer phone defaults (override via env before stack_on)
export MASS_SCAN_JOBS="${MASS_SCAN_JOBS:-1}"
export BALANCE_WORKERS="${BALANCE_WORKERS:-4}"
export SCAN_LINE_MAX_BYTES="${SCAN_LINE_MAX_BYTES:-65536}"
export SCAN_TEXT_MAX_CHARS="${SCAN_TEXT_MAX_CHARS:-24000}"
export SCAN_LINE_SLEEP="${SCAN_LINE_SLEEP:-0.01}"
export SCAN_CHECKPOINT_SEC="${SCAN_CHECKPOINT_SEC:-30}"

# Keep CPU awake across doze / app switches
termux-wake-lock >/dev/null 2>&1 || true

_alive_pidfile() {
  local f="$1"
  [ -f "$f" ] || return 1
  local p
  p=$(tr -d ' \r\n' <"$f" 2>/dev/null)
  [ -n "$p" ] && kill -0 "$p" 2>/dev/null
}

_spawn() {
  local pidf="$1" logf="$2"; shift 2
  local envparts=()
  while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do
    envparts+=("$1"); shift
  done
  [ "$1" = "--" ] && shift
  if [ "${#envparts[@]}" -gt 0 ]; then
    nohup setsid env "${envparts[@]}" "$@" >>"$logf" 2>&1 </dev/null &
  else
    nohup setsid "$@" >>"$logf" 2>&1 </dev/null &
  fi
  echo $! > "$pidf"
}

_rotate_if_huge() {
  # $1=path  $2=max_bytes  $3=keep_tail_bytes
  local path="$1" maxb="$2" keep="${3:-67108864}"
  [ -f "$path" ] || return 0
  local sz
  sz=$(wc -c <"$path" 2>/dev/null | tr -d ' ' || echo 0)
  [ -n "$sz" ] || return 0
  if [ "$sz" -gt "$maxb" ]; then
    local bak="${path}.rotated.$(date +%Y%m%d%H%M%S)"
    if command -v tail >/dev/null 2>&1; then
      mv -f "$path" "$bak" 2>/dev/null || return 0
      tail -c "$keep" "$bak" >"$path" 2>/dev/null || : >"$path"
      echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] rotated $path ($sz bytes) -> $bak (kept tail ${keep})" >>"$LOG"
    else
      : >"$path"
      echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] truncated $path ($sz bytes)" >>"$LOG"
    fi
    rm -f "$HOME_DIR/.scanner_checkpoint"
  fi
}

_rotate_log_if_huge() {
  local path="$1" maxb="$2"
  [ -f "$path" ] || return 0
  local sz
  sz=$(wc -c <"$path" 2>/dev/null | tr -d ' ' || echo 0)
  if [ -n "$sz" ] && [ "$sz" -gt "$maxb" ]; then
    mv -f "$path" "${path}.1" 2>/dev/null || : >"$path"
    : >"$path"
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] rotated log $path ($sz bytes)" >>"$LOG"
  fi
}

_mem_pressure() {
  local avail
  avail=$(awk '/MemAvailable:/ {print int($2/1024)}' /proc/meminfo 2>/dev/null)
  [ -n "$avail" ] || return 1
  [ "$avail" -lt 800 ]
}

_renice_stack() {
  for pat in "crypto_scanner.py" "mass_scan.py" "adaptive_throttler.py" "keepalive.py"; do
    pgrep -f "$pat" 2>/dev/null | while read -r p; do
      renice 10 -p "$p" >/dev/null 2>&1 || true
    done
  done
}

while true; do
  termux-wake-lock >/dev/null 2>&1 || true

  # Rotate monsters before they kill the phone again
  _rotate_if_huge "$HOME_DIR/.trufflehog_mass_results.jsonl" 2147483648 67108864
  _rotate_if_huge "$HOME_DIR/.trufflehog_results.jsonl" 2147483648 67108864
  _rotate_log_if_huge "$HOME_DIR/crypto_scanner.log" 52428800
  _rotate_log_if_huge "$HOME_DIR/crypto_scanner_scanner.log" 52428800
  _rotate_log_if_huge "$HOME_DIR/adaptive_scan.log" 20971520
  _rotate_log_if_huge "$HOME_DIR/launch_all.log" 20971520
  _rotate_log_if_huge "$HOME_DIR/keepalive.log" 10485760

  _renice_stack

  if _mem_pressure; then
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] mem pressure — skip heavy restarts this cycle" >>"$LOG"
    sleep 60
    continue
  fi

  if ! _alive_pidfile "$PID_DIR/keepalive.pid" && ! pgrep -f "keepalive.py" >/dev/null 2>&1; then
    _spawn "$PID_DIR/keepalive.pid" "$HOME_DIR/keepalive.log" -- python3 "$HOME_DIR/keepalive.py"
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] restarted keepalive pid=$(cat "$PID_DIR/keepalive.pid")" >>"$LOG"
  fi

  if ! _alive_pidfile "$PID_DIR/crypto_scanner.pid" && ! pgrep -f "crypto_scanner.py" >/dev/null 2>&1; then
    SCAN_FILE="$HOME_DIR/.trufflehog_mass_results.jsonl"
    [ -s "$SCAN_FILE" ] || SCAN_FILE="$HOME_DIR/.trufflehog_results.jsonl"
    : >> "$SCAN_FILE"
    _spawn "$PID_DIR/crypto_scanner.pid" "$HOME_DIR/crypto_scanner_scanner.log" \
      "BALANCE_WORKERS=${BALANCE_WORKERS:-4}" "MASS_SCAN_JOBS=${MASS_SCAN_JOBS:-1}" \
      "SCAN_LINE_MAX_BYTES=${SCAN_LINE_MAX_BYTES:-65536}" \
      "SCAN_TEXT_MAX_CHARS=${SCAN_TEXT_MAX_CHARS:-24000}" \
      "SCAN_LINE_SLEEP=${SCAN_LINE_SLEEP:-0.01}" \
      -- python3 "$HOME_DIR/crypto_scanner.py" "$SCAN_FILE"
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] restarted crypto_scanner pid=$(cat "$PID_DIR/crypto_scanner.pid")" >>"$LOG"
  fi

  if ! _alive_pidfile "$PID_DIR/adaptive_scan.pid" && ! pgrep -f "adaptive_throttler.py" >/dev/null 2>&1; then
    if ! _alive_pidfile "$PID_DIR/mass_scan.pid" && ! pgrep -f "mass_scan.py" >/dev/null 2>&1; then
      if [ -f "$HOME_DIR/adaptive_throttler.py" ]; then
        _spawn "$PID_DIR/adaptive_scan.pid" "$HOME_DIR/adaptive_scan.log" \
          "MASS_SCAN_JOBS=${MASS_SCAN_JOBS:-1}" "BALANCE_WORKERS=${BALANCE_WORKERS:-4}" \
          -- python3 "$HOME_DIR/adaptive_throttler.py"
        echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] restarted adaptive pid=$(cat "$PID_DIR/adaptive_scan.pid")" >>"$LOG"
      elif [ -f "$HOME_DIR/run_throttled.py" ]; then
        _spawn "$PID_DIR/mass_scan.pid" "$HOME_DIR/run_throttled_out.log" -- python3 "$HOME_DIR/run_throttled.py"
        echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] restarted mass pid=$(cat "$PID_DIR/mass_scan.pid")" >>"$LOG"
      fi
    fi
  fi

  sleep 45
done
