# Encrypted Findings — How to Decrypt After Phone Format

This document explains how to recover your encrypted crypto scanner findings
on **any** phone or computer, even after formatting the original device.

## What gets encrypted

`encrypt_offload.py` encrypts these files with **AES-256-CBC + PBKDF2**
(using the `openssl` command-line tool):

| File | Contains |
|------|----------|
| `crypto_scanner_memory.jsonl` | Every finding with timestamps |
| `high_confidence_hits.jsonl` | Correlated keys + derived addresses |
| `balances_hit.jsonl` | Balance checks for found addresses |
| `crypto_scanner_scanner.log` | Scanner log output |

## Prerequisites (on any new phone)

1. **Install Termux** from F-Droid (not the Play Store version)
2. **Install openssl**: `pkg install openssl-tool`
3. **Copy encrypted files** to your home dir (`~/`) — via USB, cloud, email, etc.
4. **Copy the passphrase** you saved when you ran encryption

## Verify you have the right files

```bash
ls ~/crypto_scanner_memory.jsonl.enc
ls ~/high_confidence_hits.jsonl.enc
ls ~/balances_hit.jsonl.enc
```

## Decrypt everything at once

```bash
cd ~
for f in *.enc; do
  openssl enc -d -aes-256-cbc -pbkdf2 \
    -in "$f" -out "${f%.enc}" -pass pass:YOUR_PASSPHRASE
done
```

## Decrypt a single file

```bash
openssl enc -d -aes-256-cbc -pbkdf2 \
  -in crypto_scanner_memory.jsonl.enc \
  -out crypto_scanner_memory.jsonl \
  -pass pass:YOUR_PASSPHRASE
```

## Verify decrypted files are valid

```bash
# Check JSONL format
head -1 crypto_scanner_memory.jsonl
# Should show a JSON object like: {"ts": "...", "findings": {...}, ...}

# Validate all lines parse as JSON
python3 -c "
import json
count = 0
with open('crypto_scanner_memory.jsonl') as f:
    for line in f:
        if line.strip():
            json.loads(line)
            count += 1
print(f'OK — {count} valid JSON records')
"

# Check balance hits
python3 -c "
import json
with open('balances_hit.jsonl') as f:
    for line in f:
        if line.strip():
            rec = json.loads(line)
            print(f\"{rec['chain']} {rec['address']} => {rec['balance']}\")
"
```

## Passphrase backup (do this before formatting!)

The passphrase is stored at `~/.encrypt_passphrase`. Back it up to:

- A **password manager** (Bitwarden, KeePass, 1Password, etc.)
- A **printed note** kept in a physical safe
- A **cloud note** you can access from any device (but encrypt the note itself)

If you lose the passphrase, the encrypted files are unrecoverable.
There is no backdoor.

## How to re-encrypt after formatting

On the new phone, after decrypting and reviewing:

```bash
python3 ~/encrypt_offload.py --keep  # encrypt + keep originals
```

Then when satisfied, originals can be removed:

```bash
rm crypto_scanner_memory.jsonl high_confidence_hits.jsonl balances_hit.jsonl
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `openssl: command not found` | `pkg install openssl-tool` |
| `bad decrypt` error | Wrong passphrase — try again |
| Decrypted file is binary garbage | Wrong cipher/pbkdf2 — make sure you use `-pbkdf2` |
| `401 Unauthorized` from GitHub Gist | Check `~/.github_token` is valid |

