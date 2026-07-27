# Crypto Scanner + Deobfuscation Gadgets

Two tools built for fast triage of `.jsonl` output:

- `crypto_scanner.py` — continuously scans a `.jsonl` file for BIP39 mnemonics, private keys, high-entropy base64/base58, PEM blocks, and crypto addresses; checks balances across blockchains in threads.
- `deobfuscate.py` — strips backspace/ANSI-obfuscation to recover original text.

## Quick start

```bash
# clone
 git clone <repo-url>
 cd <repo>

# run crypto scanner against trufflehog results
 python3 crypto_scanner.py .trufflehog_results.jsonl
```
