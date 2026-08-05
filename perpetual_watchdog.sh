#!/data/data/com.termux/files/usr/bin/bash
# perpetual_watchdog — master daemon that keeps ALL services alive forever.
# Immune to pkill, terminal close, crashes.  Run once, never touch again.
# Spawned by dashgo.  All children use setsid so they survive anything.
set +e
HOME_DIR="${HOME:-/data/data/com.termux/files/home}"
cd "$HOME_DIR" || exit 1

LOG="$HOME_DIR/perpetual_watchdog.log"
exec >>"$LOG" 2>&1

echo "============================================"
echo "[PERPETUAL] Master watchdog started $(date)"
echo "[PERPETUAL] PID: $$"
echo "[PERPETUAL] All children use setsid — immune to pkill"

declare -A SERVICES
declare -A COUNTS

# Service definitions: name -> (check_cmd, start_cmd)
# check_cmd returns 0 if running, non-zero if dead
register() {
    local name="$1"; local check="$2"; local start="$3"
    SERVICES["$name|check"]="$check"
    SERVICES["$name|start"]="$start"
    COUNTS["$name"]=0
}

register "walletx_server" \
    "curl -sf -m 3 http://0.0.0.0:8080/api/health >/dev/null 2>&1" \
    "setsid python3 $HOME_DIR/walletx_server.py >>$HOME_DIR/walletx_server.log 2>&1 < /dev/null &"

register "crypto_scanner" \
    "pgrep -f crypto_scanner.py >/dev/null 2>&1" \
    "SCAN=$HOME_DIR/.trufflehog_mass_results.jsonl; [ -s \$SCAN ] || SCAN=$HOME_DIR/.trufflehog_results.jsonl; : >> \$SCAN; setsid python3 $HOME_DIR/crypto_scanner.py \$SCAN >>$HOME_DIR/crypto_scanner_scanner.log 2>&1 < /dev/null &"

register "adaptive_throttler" \
    "pgrep -f adaptive_throttler.py >/dev/null 2>&1" \
    "setsid python3 $HOME_DIR/adaptive_throttler.py >>$HOME_DIR/adaptive_scan.log 2>&1 < /dev/null &"

register "paste_watcher" \
    "pgrep -f paste_box_watcher.py >/dev/null 2>&1" \
    "setsid python3 $HOME_DIR/paste_box_watcher.py >>$HOME_DIR/paste_watcher.log 2>&1 < /dev/null &"

register "keepalive" \
    "pgrep -f keepalive.py >/dev/null 2>&1" \
    "setsid python3 $HOME_DIR/keepalive.py >>$HOME_DIR/keepalive.log 2>&1 < /dev/null &"

register "notify_hits" \
    "pgrep -f notify_hits.py >/dev/null 2>&1" \
    "setsid python3 $HOME_DIR/notify_hits.py >>$HOME_DIR/notify_hits.log 2>&1 < /dev/null &"

register "deobfuscation_daemon" \
    "pgrep -f deobfuscation_daemon.py >/dev/null 2>&1" \
    "setsid python3 $HOME_DIR/deobfuscation_daemon.py >>$HOME_DIR/deobfuscation_daemon.log 2>&1 < /dev/null &"

register "stack_watchdog" \
    "pgrep -f stack_watchdog.sh >/dev/null 2>&1" \
    "setsid bash $HOME_DIR/stack_watchdog.sh >>$HOME_DIR/watchdog.log 2>&1 < /dev/null &"

register "auto_decrypt" \
    "true" \
    "[ -f $HOME_DIR/auto_decrypt.py ] && [ -f $HOME_DIR/.encrypt_passphrase ] && setsid python3 $HOME_DIR/auto_decrypt.py >>$HOME_DIR/auto_decrypt.log 2>&1 < /dev/null &"

# ── Main loop ───────────────────────────────────────────────────
CHECK_INTERVAL=10
CYCLE=0

while true; do
    CYCLE=$((CYCLE + 1))
    for name in walletx_server crypto_scanner adaptive_throttler paste_watcher keepalive notify_hits deobfuscation_daemon stack_watchdog auto_decrypt; do
        check="${SERVICES[${name}|check]}"
        start="${SERVICES[${name}|start]}"
        if ! eval "$check"; then
            COUNTS[$name]=$((COUNTS[$name] + 1))
            echo "[PERPETUAL] #${COUNTS[$name]} $name dead — restarting..."
            eval "$start"
            sleep 2
            if eval "$check"; then
                echo "[PERPETUAL] #${COUNTS[$name]} $name restored OK"
            fi
        fi
    done
    sleep $CHECK_INTERVAL
done
