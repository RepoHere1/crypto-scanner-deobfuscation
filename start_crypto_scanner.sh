#!/data/data/com.termux/files/usr/bin/bash
# Start only the crypto scanner
set -e

export ALCHEMY_API_KEY="${ALCHEMY_API_KEY:-mi8wM6xm7rRBMYTCjHfM5}"
export ANKR_API_KEY="${ANKR_API_KEY:-686c37d4360af4d79afda6313ea426fef99f5c4320b380589ccb2c93d830112e}"

SCAN_RESULTS="$HOME/.trufflehog_results.jsonl"
: > "$SCAN_RESULTS"
cd "$HOME"
mkdir -p "$HOME/.run_pids"
PIDFILE="$HOME/.run_pids/crypto_scanner.pid"
if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "[*] CryptoScanner already running (PID $(cat "$PIDFILE"))"
else
    rm -f "$PIDFILE"
    nohup python3 "$HOME/crypto_scanner.py" "$SCAN_RESULTS" > "$HOME/crypto_scanner_scanner.log" 2>&1 &
    echo $! > "$PIDFILE"
    echo "CryptoScanner started. Memory: $HOME/crypto_scanner_memory.jsonl"
fi
