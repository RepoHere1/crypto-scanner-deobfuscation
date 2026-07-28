#!/usr/bin/env python3
"""
encrypt_offload.py — Encrypt findings and offload to GitHub.

Uses the local openssl binary (installed via Termux) to AES-256-CBC encrypt
key findings files with a user-chosen passphrase, then uploads the encrypted
payloads to a private GitHub Gist using the existing API token.

After encryption the unencrypted originals can be optionally deleted to
reclaim disk space.  The passphrase is the only way to decrypt the files —
store it in a password manager or write it down somewhere safe.

Usage:
    python3 ~/encrypt_offload.py                  # encrypt + upload
    python3 ~/encrypt_offload.py --keep           # encrypt but keep originals
    python3 ~/encrypt_offload.py --passphrase abc # use custom passphrase
    python3 ~/encrypt_offload.py --decrypt          # decrypt local .enc files
    python3 ~/encrypt_offload.py --decrypt-file <file>  # decrypt single file
    python3 ~/encrypt_offload.py --dry-run          # list files to encrypt
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
try:
    import urllib.request, urllib.error
except ImportError:
    urllib_request = urllib_error = None

HOME = Path.home()
APP_DIR = HOME
GITHUB_TOKEN_FILE = HOME / ".github_token"
GITHUB_API = "https://api.github.com"
FINDINGS_FILES = [
    "crypto_scanner_memory.jsonl",
    "high_confidence_hits.jsonl",
    "balances_hit.jsonl",
    "crypto_scanner_scanner.log",
]
ENCRYPTED_SUFFIX = ".enc"
PASSPHRASE_FILE = HOME / ".encrypt_passphrase"


def load_github_token() -> str:
    if not GITHUB_TOKEN_FILE.exists():
        print("[!] No GitHub token at", GITHUB_TOKEN_FILE, file=sys.stderr)
        sys.exit(1)
    token = GITHUB_TOKEN_FILE.read_text().strip()
    if not token:
        print("[!] GitHub token file is empty", file=sys.stderr)
        sys.exit(1)
    return token


def _openssl(args: list) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["openssl"] + args,
        capture_output=True, text=True, timeout=300,
    )


def openssl_encrypt(input_path: Path, output_path: Path, passphrase: str) -> bool:
    try:
        result = _openssl([
            "enc", "-aes-256-cbc", "-pbkdf2",
            "-salt", "-in", str(input_path), "-out", str(output_path),
            "-pass", f"pass:{passphrase}",
        ])
        if result.returncode != 0:
            print(f"[!] openssl encrypt failed for {input_path.name}: {result.stderr}", file=sys.stderr)
            return False
        return True
    except FileNotFoundError:
        print("[!] openssl not found — install: pkg install openssl-tool", file=sys.stderr)
        return False
    except subprocess.TimeoutExpired:
        print(f"[!] openssl encrypt timed out for {input_path.name}", file=sys.stderr)
        return False


def openssl_decrypt(input_path: Path, output_path: Path, passphrase: str) -> bool:
    try:
        result = _openssl([
            "enc", "-d", "-aes-256-cbc", "-pbkdf2",
            "-in", str(input_path), "-out", str(output_path),
            "-pass", f"pass:{passphrase}",
        ])
        if result.returncode != 0:
            print(f"[!] openssl decrypt failed for {input_path.name}: {result.stderr}", file=sys.stderr)
            return False
        return True
    except FileNotFoundError:
        print("[!] openssl not found — install: pkg install openssl-tool", file=sys.stderr)
        return False
    except subprocess.TimeoutExpired:
        print(f"[!] openssl decrypt timed out for {input_path.name}", file=sys.stderr)
        return False


def generate_passphrase(length: int = 32) -> str:
    try:
        result = _openssl(["rand", "-base64", str(length)])
        if result.returncode == 0:
            return result.stdout.strip().replace("/", "_").replace("+", "-")
    except Exception:
        pass
    return hashlib.sha256(str(time.time()).encode()).hexdigest()[:length]


def get_passphrase() -> str:
    if PASSPHRASE_FILE.exists():
        return PASSPHRASE_FILE.read_text().strip()
    print("No passphrase stored at", PASSPHRASE_FILE)
    print("This passphrase is the ONLY way to decrypt your findings later.")
    print("Store it in a password manager or write it down safely.")
    p1 = input("Enter a new passphrase: ")
    p2 = input("Confirm passphrase: ")
    if p1 != p2:
        print("[!] Passphrases do not match", file=sys.stderr)
        sys.exit(1)
    if len(p1) < 8:
        print("[!] Passphrase must be at least 8 characters", file=sys.stderr)
        sys.exit(1)
    PASSPHRASE_FILE.write_text(p1)
    print("Passphrase saved to", PASSPHRASE_FILE)
    print("  WARNING: BACK THIS UP — write it down or store in a password manager!")
    return p1


def encrypt_files(passphrase: str, keep_originals: bool = False) -> list:
    results = []
    for fname in FINDINGS_FILES:
        src = APP_DIR / fname
        if not src.exists():
            continue
        encrypted = src.with_suffix(src.suffix + ENCRYPTED_SUFFIX)
        print(f"Encrypting {fname} -> {encrypted.name} ... ", end="", flush=True)
        if openssl_encrypt(src, encrypted, passphrase):
            enc_size = encrypted.stat().st_size
            src_size = src.stat().st_size
            print(f"OK ({src_size} -> {enc_size} bytes)")
            results.append((src, encrypted))
            if not keep_originals:
                src.unlink()
                print(f"  Removed original {fname} to reclaim space.")
        else:
            print("FAILED")
    return results


def decrypt_files(passphrase: str) -> None:
    enc_files = sorted(APP_DIR.glob(f"*{ENCRYPTED_SUFFIX}"))
    if not enc_files:
        print("No .enc files found to decrypt.")
        return
    for enc in enc_files:
        orig = enc.with_suffix("")
        print(f"Decrypting {enc.name} -> {orig.name} ... ", end="", flush=True)
        if openssl_decrypt(enc, orig, passphrase):
            print("OK")
        else:
            print("FAILED - wrong passphrase?")


def decrypt_single_file(input_path: Path, passphrase: str) -> None:
    if not input_path.exists():
        print(f"[!] File not found: {input_path}", file=sys.stderr)
        return
    if input_path.suffix == ENCRYPTED_SUFFIX:
        out = input_path.with_suffix("")
    else:
        out = input_path.with_suffix(input_path.suffix + ".dec")
    print(f"Decrypting {input_path.name} -> {out.name} ... ", end="", flush=True)
    if openssl_decrypt(input_path, out, passphrase):
        print("OK")
    else:
        print("FAILED - wrong passphrase?")


def create_gist(token: str, encrypted_files: list, passphrase_hint: str) -> str:
    files_payload = {}
    for orig, enc in encrypted_files:
        fname = enc.name
        content = enc.read_bytes()
        # decode as latin-1 for transport (arbitrary binary -> text)
        files_payload[fname] = {
            "content": content.decode("latin-1", errors="replace"),
            "filename": fname,
        }

    readme_content = (
        "# Encrypted crypto scanner findings\n\n"
        f"Created: {datetime.now(timezone.utc).isoformat()}\n"
        "Encryption: AES-256-CBC with PBKDF2 (openssl enc)\n"
        f"Passphrase hint: {passphrase_hint}\n\n"
        "## Decryption (any system with openssl)\n\n"
        "```bash\n"
        "# Decrypt a single file:\n"
        "openssl enc -d -aes-256-cbc -pbkdf2 \\\n"
        "  -in <file>.enc -out <file> -pass pass:<YOUR_PASSPHRASE>\n"
        "\n"
        "# Decrypt all .enc files in a directory:\n"
        "for f in *.enc; do\n"
        "  openssl enc -d -aes-256-cbc -pbkdf2 \\\n"
        "    -in \"$f\" -out \"${f%.enc}\" -pass pass:<YOUR_PASSPHRASE>\n"
        "done\n"
        "```\n"
        "\n"
        "## Verify after decryption\n\n"
        "```bash\n"
        "head -1 crypto_scanner_memory.jsonl\n"
        "python3 -c \"import json; [json.loads(l) for l in open('crypto_scanner_memory.jsonl')]; print('OK')\"\n"
        "```\n"
    )
    files_payload["README_decryption_instructions.md"] = {
        "content": readme_content,
        "filename": "README_decryption_instructions.md",
    }

    body = {
        "description": f"Encrypted crypto scanner findings - {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "public": False,
        "files": files_payload,
    }

    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        f"{GITHUB_API}/gists",
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "User-Agent": "RepoHere1-Termux",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp_data = json.loads(resp.read().decode())
            return resp_data.get("html_url", "")
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", errors="replace")
        print(f"[!] GitHub API error {e.code}: {body_text}", file=sys.stderr)
        return ""
    except Exception as e:
        print(f"[!] Failed to create Gist: {e}", file=sys.stderr)
        return ""


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Encrypt findings with openssl and offload to GitHub Gist.",
    )
    parser.add_argument("--keep", action="store_true", help="Keep unencrypted originals after encryption")
    parser.add_argument("--decrypt", action="store_true", help="Decrypt all .enc files in ~/")
    parser.add_argument("--decrypt-file", type=str, help="Decrypt a single .enc file")
    parser.add_argument("--passphrase", default=None, help="Encryption/decryption passphrase (will prompt if omitted)")
    parser.add_argument("--dry-run", action="store_true", help="List files to encrypt without doing it")
    args = parser.parse_args()

    if args.passphrase:
        passphrase = args.passphrase
    elif args.decrypt or args.decrypt_file:
        passphrase = input("Enter decryption passphrase: ")
    else:
        passphrase = get_passphrase()

    token = load_github_token()

    if args.decrypt:
        decrypt_files(passphrase)
        return

    if args.decrypt_file:
        decrypt_single_file(Path(args.decrypt_file), passphrase)
        return

    if args.dry_run:
        print("Files that would be encrypted:")
        for fname in FINDINGS_FILES:
            p = APP_DIR / fname
            if p.exists():
                print(f"  {fname} ({p.stat().st_size} bytes)")
        return

    print(f"[+] Encrypting findings with AES-256-CBC (PBKDF2)...")
    encrypted = encrypt_files(passphrase, keep_originals=args.keep)

    if not encrypted:
        print("[!] No files were encrypted. Nothing to upload.")
        return

    print(f"[+] Uploading {len(encrypted)} encrypted file(s) to GitHub Gist...")
    url = create_gist(token, encrypted, passphrase_hint="<your passphrase>")
    if url:
        print(f"\nOK Encrypted Gist: {url}")
        print("  Save the passphrase and URL somewhere safe.")
        print("  On any new phone: openssl enc -d -aes-256-cbc -pbkdf2 -in <file> -out <file> -pass pass:<PASSPHRASE>")
    else:
        print("\nWARNING: Gist upload failed, but encrypted files are on disk:")
        for _, enc in encrypted:
            print(f"  {enc}")
        print("  You can manually upload them or retry later.")

    manifest = {
        "encrypted_at": datetime.now(timezone.utc).isoformat(),
        "files": [str(enc) for _, enc in encrypted],
        "gist_url": url,
        "passphrase_stored_at": str(PASSPHRASE_FILE),
    }
    (APP_DIR / ".encrypt_manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"\nManifest saved to .encrypt_manifest.json")


if __name__ == "__main__":
    main()
