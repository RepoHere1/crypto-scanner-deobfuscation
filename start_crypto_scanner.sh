#!/data/data/com.termux/files/usr/bin/bash
set -e
cd "$HOME"
python3 "$HOME/crypto_scanner.py" "$HOME/.trufflehog_results.jsonl" > "$HOME/crypto_scanner_scanner.log" 2>&1 &
echo "CryptoScanner started. Memory: $HOME/crypto_scanner/crypto_scanner_memory.jsonl"
