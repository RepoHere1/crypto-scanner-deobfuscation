#!/usr/bin/env python3
"""
encrypt_offload.py — Production encrypt + optional GitHub offload for findings.

Backends (auto):
  1. PyCryptodome AES-256-GCM  (if installed) — authenticated, no passphrase in ps
  2. OpenSSL AES-256-CBC + PBKDF2 + high iter — passphrase via env, not argv

Usage:
    python3 ~/encrypt_offload.py --live-backup   # safe while scanner runs
    python3 ~/encrypt_offload.py --keep          # full encrypt, keep originals
    python3 ~/encrypt_offload.py                 # full encrypt, delete originals
    python3 ~/encrypt_offload.py --decrypt
    python3 ~/encrypt_offload.py --decrypt-file FILE.enc
    python3 ~/encrypt_offload.py --dry-run
    python3 ~/encrypt_offload.py --backend auto|openssl|pycryptodome
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import urllib.request
    import urllib.error
except ImportError:
    urllib = None  # type: ignore

HOME = Path.home()
APP_DIR = HOME
GITHUB_TOKEN_FILE = HOME / ".github_token"
GITHUB_API = "https://api.github.com"

# Full offload set (can be huge — do not use --live-backup for memory).
FINDINGS_FILES = [
    "crypto_scanner_memory.jsonl",
    "high_confidence_hits.jsonl",
    "balances_hit.jsonl",
    "crypto_scanner_scanner.log",
]

# Safe while scanner is live: small/critical only, always keep originals.
LIVE_BACKUP_FILES = [
    "balances_hit.jsonl",
    "high_confidence_hits.jsonl",
    "crypto_scanner_status.txt",
]

ENCRYPTED_SUFFIX = ".enc"
PASSPHRASE_FILE = HOME / ".encrypt_passphrase"
MANIFEST_FILE = HOME / ".encrypt_manifest.json"
VAULT_DIR = HOME / ".vault"

# OpenSSL PBKDF2 iterations (OpenSSL 3 default is 10000 — raise for production).
OPENSSL_ITER = 600_000

# PyCryptodome container: magic|kdf_id|salt|nonce|ciphertext|tag
PCDOME_MAGIC = b"PCDOM1\n"
PBKDF2_ROUNDS_GCM = 600_000


def _have_pycryptodome() -> bool:
    try:
        from Crypto.Cipher import AES  # noqa: F401
        from Crypto.Protocol.KDF import PBKDF2  # noqa: F401
        from Crypto.Random import get_random_bytes  # noqa: F401
        return True
    except Exception:
        return False


def resolve_backend(requested: str) -> str:
    req = (requested or "auto").lower()
    if req == "auto":
        return "pycryptodome" if _have_pycryptodome() else "openssl"
    if req in ("pycryptodome", "openssl"):
        if req == "pycryptodome" and not _have_pycryptodome():
            print("[!] pycryptodome not installed — falling back to openssl", file=sys.stderr)
            return "openssl"
        return req
    print(f"[!] unknown backend {requested!r}, using auto", file=sys.stderr)
    return resolve_backend("auto")


def load_github_token() -> str:
    if not GITHUB_TOKEN_FILE.exists():
        return ""
    token = GITHUB_TOKEN_FILE.read_text().strip()
    return token or ""


def _chmod_private(path: Path) -> None:
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
    except Exception:
        pass


def _openssl(args: list, env: dict | None = None, timeout: int = 600) -> subprocess.CompletedProcess:
    run_env = os.environ.copy()
    if env:
        run_env.update(env)
    return subprocess.run(
        ["openssl"] + args,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=run_env,
    )


def openssl_encrypt(input_path: Path, output_path: Path, passphrase: str) -> bool:
    """AES-256-CBC + PBKDF2. Passphrase via env — never on argv."""
    tmp = output_path.with_suffix(output_path.suffix + ".partial")
    try:
        if tmp.exists():
            tmp.unlink()
        result = _openssl(
            [
                "enc", "-aes-256-cbc", "-pbkdf2",
                "-iter", str(OPENSSL_ITER),
                "-salt",
                "-in", str(input_path),
                "-out", str(tmp),
                "-pass", "env:ENCRYPT_PASS",
            ],
            env={"ENCRYPT_PASS": passphrase},
            timeout=max(600, int(input_path.stat().st_size / (5 * 1024 * 1024)) + 120),
        )
        if result.returncode != 0:
            print(f"[!] openssl encrypt failed for {input_path.name}: {result.stderr.strip()}", file=sys.stderr)
            if tmp.exists():
                tmp.unlink()
            return False
        tmp.replace(output_path)
        _chmod_private(output_path)
        return True
    except FileNotFoundError:
        print("[!] openssl not found — install: pkg install openssl-tool", file=sys.stderr)
        return False
    except subprocess.TimeoutExpired:
        print(f"[!] openssl encrypt timed out for {input_path.name}", file=sys.stderr)
        if tmp.exists():
            try:
                tmp.unlink()
            except Exception:
                pass
        return False
    except Exception as exc:
        print(f"[!] openssl encrypt error for {input_path.name}: {exc}", file=sys.stderr)
        if tmp.exists():
            try:
                tmp.unlink()
            except Exception:
                pass
        return False


def openssl_decrypt(input_path: Path, output_path: Path, passphrase: str) -> bool:
    tmp = output_path.with_suffix(output_path.suffix + ".partial")
    try:
        if tmp.exists():
            tmp.unlink()
        # Try production iter first, then legacy default (older files).
        for iters in (OPENSSL_ITER, 10_000, None):
            args = ["enc", "-d", "-aes-256-cbc", "-pbkdf2", "-in", str(input_path), "-out", str(tmp), "-pass", "env:ENCRYPT_PASS"]
            if iters is not None:
                args[4:4] = ["-iter", str(iters)]
            result = _openssl(args, env={"ENCRYPT_PASS": passphrase})
            if result.returncode == 0 and tmp.exists() and tmp.stat().st_size >= 0:
                tmp.replace(output_path)
                _chmod_private(output_path)
                return True
            if tmp.exists():
                tmp.unlink()
        print(f"[!] openssl decrypt failed for {input_path.name}: bad passphrase or format", file=sys.stderr)
        return False
    except FileNotFoundError:
        print("[!] openssl not found — install: pkg install openssl-tool", file=sys.stderr)
        return False
    except subprocess.TimeoutExpired:
        print(f"[!] openssl decrypt timed out for {input_path.name}", file=sys.stderr)
        return False
    except Exception as exc:
        print(f"[!] openssl decrypt error: {exc}", file=sys.stderr)
        return False


def pycryptodome_encrypt(input_path: Path, output_path: Path, passphrase: str) -> bool:
    """AES-256-GCM with PBKDF2-HMAC-SHA256. Authenticated encryption."""
    try:
        from Crypto.Cipher import AES
        from Crypto.Protocol.KDF import PBKDF2
        from Crypto.Hash import SHA256
        from Crypto.Random import get_random_bytes
    except ImportError:
        return False
    tmp = output_path.with_suffix(output_path.suffix + ".partial")
    try:
        salt = get_random_bytes(16)
        nonce = get_random_bytes(12)
        key = PBKDF2(passphrase, salt, dkLen=32, count=PBKDF2_ROUNDS_GCM, hmac_hash_module=SHA256)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        # Stream in chunks to limit RAM on large files
        hasher_size = 0
        ct_chunks = []
        with open(input_path, "rb") as inf:
            while True:
                chunk = inf.read(1024 * 1024)
                if not chunk:
                    break
                hasher_size += len(chunk)
                ct_chunks.append(cipher.encrypt(chunk))
        ciphertext = b"".join(ct_chunks)
        tag = cipher.digest()
        with open(tmp, "wb") as out:
            out.write(PCDOME_MAGIC)
            out.write(salt)
            out.write(nonce)
            out.write(tag)
            out.write(ciphertext)
        tmp.replace(output_path)
        _chmod_private(output_path)
        return True
    except Exception as exc:
        print(f"[!] pycryptodome encrypt failed for {input_path.name}: {exc}", file=sys.stderr)
        if tmp.exists():
            try:
                tmp.unlink()
            except Exception:
                pass
        return False


def pycryptodome_decrypt(input_path: Path, output_path: Path, passphrase: str) -> bool:
    try:
        from Crypto.Cipher import AES
        from Crypto.Protocol.KDF import PBKDF2
        from Crypto.Hash import SHA256
    except ImportError:
        return False
    tmp = output_path.with_suffix(output_path.suffix + ".partial")
    try:
        data = input_path.read_bytes()
        if not data.startswith(PCDOME_MAGIC):
            return False
        off = len(PCDOME_MAGIC)
        salt = data[off : off + 16]
        off += 16
        nonce = data[off : off + 12]
        off += 12
        tag = data[off : off + 16]
        off += 16
        ciphertext = data[off:]
        key = PBKDF2(passphrase, salt, dkLen=32, count=PBKDF2_ROUNDS_GCM, hmac_hash_module=SHA256)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plain = cipher.decrypt_and_verify(ciphertext, tag)
        tmp.write_bytes(plain)
        tmp.replace(output_path)
        _chmod_private(output_path)
        return True
    except Exception as exc:
        print(f"[!] pycryptodome decrypt failed for {input_path.name}: {exc}", file=sys.stderr)
        if tmp.exists():
            try:
                tmp.unlink()
            except Exception:
                pass
        return False


def detect_format(path: Path) -> str:
    try:
        with open(path, "rb") as f:
            head = f.read(16)
        if head.startswith(PCDOME_MAGIC):
            return "pycryptodome"
        if head.startswith(b"Salted__"):
            return "openssl"
    except Exception:
        pass
    return "unknown"


def encrypt_one(input_path: Path, output_path: Path, passphrase: str, backend: str) -> bool:
    if backend == "pycryptodome":
        ok = pycryptodome_encrypt(input_path, output_path, passphrase)
        if ok:
            return True
        print(f"[!] pycryptodome failed for {input_path.name}, trying openssl…", file=sys.stderr)
        return openssl_encrypt(input_path, output_path, passphrase)
    return openssl_encrypt(input_path, output_path, passphrase)


def decrypt_one(input_path: Path, output_path: Path, passphrase: str) -> bool:
    fmt = detect_format(input_path)
    if fmt == "pycryptodome":
        return pycryptodome_decrypt(input_path, output_path, passphrase)
    if fmt == "openssl":
        return openssl_decrypt(input_path, output_path, passphrase)
    # Try both
    if pycryptodome_decrypt(input_path, output_path, passphrase):
        return True
    return openssl_decrypt(input_path, output_path, passphrase)


def generate_passphrase(length: int = 32) -> str:
    try:
        result = _openssl(["rand", "-base64", str(length)])
        if result.returncode == 0:
            return result.stdout.strip().replace("/", "_").replace("+", "-")
    except Exception:
        pass
    return hashlib.sha256(os.urandom(64)).hexdigest()[:length]


def get_passphrase(cli: str | None = None, allow_generate: bool = True) -> str:
    if cli:
        return cli
    env_p = os.environ.get("ENCRYPT_PASSPHRASE") or os.environ.get("ENCRYPT_PASS")
    if env_p:
        return env_p.strip()
    if PASSPHRASE_FILE.exists():
        p = PASSPHRASE_FILE.read_text().strip()
        if p:
            return p
    if not allow_generate:
        print("[!] No passphrase. Set ENCRYPT_PASSPHRASE or create", PASSPHRASE_FILE, file=sys.stderr)
        sys.exit(1)
    print("No passphrase stored at", PASSPHRASE_FILE)
    print("This passphrase is the ONLY way to decrypt your findings later.")
    if sys.stdin.isatty():
        p1 = input("Enter a new passphrase (empty = auto-generate strong one): ").strip()
        if not p1:
            p1 = generate_passphrase(40)
            print("[+] Auto-generated passphrase (SAVE THIS):")
            print(p1)
        else:
            p2 = input("Confirm passphrase: ").strip()
            if p1 != p2:
                print("[!] Passphrases do not match", file=sys.stderr)
                sys.exit(1)
            if len(p1) < 12:
                print("[!] Passphrase must be at least 12 characters", file=sys.stderr)
                sys.exit(1)
    else:
        p1 = generate_passphrase(40)
        print("[+] Non-interactive: auto-generated passphrase written to", PASSPHRASE_FILE)
        print("[+] BACK IT UP NOW:", p1)
    PASSPHRASE_FILE.write_text(p1 + "\n")
    _chmod_private(PASSPHRASE_FILE)
    print("Passphrase saved to", PASSPHRASE_FILE, "(mode 600)")
    print("  WARNING: BACK THIS UP — password manager / offline note.")
    return p1


def encrypt_files(
    passphrase: str,
    file_list: list[str],
    keep_originals: bool = False,
    backend: str = "openssl",
    dest_dir: Path | None = None,
) -> list:
    results = []
    dest_dir = dest_dir or APP_DIR
    dest_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(dest_dir, 0o700)
    except Exception:
        pass

    for fname in file_list:
        src = APP_DIR / fname
        if not src.exists() or src.stat().st_size == 0:
            continue
        # Skip enormous live memory unless explicitly in full mode list and user asked
        encrypted = dest_dir / (src.name + ENCRYPTED_SUFFIX)
        print(f"Encrypting {fname} -> {encrypted} [{backend}] ... ", end="", flush=True)
        if encrypt_one(src, encrypted, passphrase, backend):
            enc_size = encrypted.stat().st_size
            src_size = src.stat().st_size
            print(f"OK ({src_size} -> {enc_size} bytes)")
            results.append({
                "src": str(src),
                "enc": str(encrypted),
                "src_size": src_size,
                "enc_size": enc_size,
                "backend": detect_format(encrypted),
                "sha256_src": _sha256_file(src),
            })
            if not keep_originals:
                # Never delete if scanner likely has file open and it's the memory file
                if fname == "crypto_scanner_memory.jsonl" and _scanner_running():
                    print(f"  Kept original {fname} (scanner running — refusing delete).")
                else:
                    src.unlink()
                    print(f"  Removed original {fname} to reclaim space.")
        else:
            print("FAILED")
    return results


def _sha256_file(path: Path, limit: int = 0) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            if limit > 0:
                h.update(f.read(limit))
            else:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def _scanner_running() -> bool:
    try:
        r = subprocess.run(["pgrep", "-f", "crypto_scanner.py"], capture_output=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False


def decrypt_files(passphrase: str) -> None:
    enc_files = sorted(APP_DIR.glob(f"*{ENCRYPTED_SUFFIX}"))
    enc_files += sorted(VAULT_DIR.glob(f"*{ENCRYPTED_SUFFIX}")) if VAULT_DIR.exists() else []
    # dedupe
    seen = set()
    uniq = []
    for p in enc_files:
        if p.resolve() in seen:
            continue
        seen.add(p.resolve())
        uniq.append(p)
    if not uniq:
        print("No .enc files found to decrypt.")
        return
    for enc in uniq:
        orig = APP_DIR / enc.name[: -len(ENCRYPTED_SUFFIX)]
        print(f"Decrypting {enc} -> {orig.name} [{detect_format(enc)}] ... ", end="", flush=True)
        if decrypt_one(enc, orig, passphrase):
            print("OK")
        else:
            print("FAILED - wrong passphrase or corrupt?")


def decrypt_single_file(input_path: Path, passphrase: str) -> None:
    if not input_path.exists():
        print(f"[!] File not found: {input_path}", file=sys.stderr)
        return
    if input_path.suffix == ENCRYPTED_SUFFIX:
        out = APP_DIR / input_path.name[: -len(ENCRYPTED_SUFFIX)]
    else:
        out = input_path.with_suffix(input_path.suffix + ".dec")
    print(f"Decrypting {input_path.name} -> {out.name} [{detect_format(input_path)}] ... ", end="", flush=True)
    if decrypt_one(input_path, out, passphrase):
        print("OK")
    else:
        print("FAILED - wrong passphrase or corrupt?")


def create_gist(token: str, encrypted_meta: list, backend: str) -> str:
    """Upload small encrypted files as base64 to a private gist."""
    if not token:
        return ""
    try:
        import urllib.request
        import urllib.error
    except ImportError:
        print("[!] urllib missing", file=sys.stderr)
        return ""

    import base64

    files_payload = {}
    max_gist_file = 8 * 1024 * 1024  # stay sane for Gist API
    uploaded = 0
    skipped = []
    for meta in encrypted_meta:
        enc = Path(meta["enc"])
        size = enc.stat().st_size
        if size > max_gist_file:
            skipped.append(f"{enc.name} ({size} bytes > 8MB gist limit)")
            continue
        b64 = base64.b64encode(enc.read_bytes()).decode("ascii")
        files_payload[enc.name + ".b64.txt"] = {
            "content": b64,
            "filename": enc.name + ".b64.txt",
        }
        uploaded += 1

    readme = (
        "# Encrypted crypto scanner findings\n\n"
        f"Created: {datetime.now(timezone.utc).isoformat()}\n"
        f"Backend: {backend}\n"
        f"OpenSSL iter: {OPENSSL_ITER} | GCM PBKDF2: {PBKDF2_ROUNDS_GCM}\n\n"
        "Files are **base64** of the binary .enc payload.\n\n"
        "## Restore\n\n"
        "```bash\n"
        "base64 -d file.enc.b64.txt > file.enc\n"
        "python3 ~/encrypt_offload.py --decrypt-file file.enc\n"
        "# or openssl (openssl-backend files only):\n"
        f"openssl enc -d -aes-256-cbc -pbkdf2 -iter {OPENSSL_ITER} \\\n"
        "  -in file.enc -out file -pass env:ENCRYPT_PASS\n"
        "```\n"
    )
    if skipped:
        readme += "\n## Skipped (too large for Gist)\n\n" + "\n".join(f"- {s}" for s in skipped) + "\n"

    files_payload["README_decryption_instructions.md"] = {
        "content": readme,
        "filename": "README_decryption_instructions.md",
    }

    if uploaded == 0:
        print("[!] No files small enough for Gist upload; encrypted copies remain on disk.")
        return ""

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
        with urllib.request.urlopen(req, timeout=60) as resp:
            resp_data = json.loads(resp.read().decode())
            return resp_data.get("html_url", "")
    except Exception as e:
        print(f"[!] Failed to create Gist: {e}", file=sys.stderr)
        return ""


def write_manifest(meta: list, backend: str, gist_url: str, mode: str) -> None:
    manifest = {
        "encrypted_at": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "backend": backend,
        "openssl_iter": OPENSSL_ITER,
        "gcm_pbkdf2": PBKDF2_ROUNDS_GCM,
        "files": [m["enc"] for m in meta],
        "file_meta": meta,
        "gist_url": gist_url,
        "passphrase_stored_at": str(PASSPHRASE_FILE),
        "passphrase_present": PASSPHRASE_FILE.exists(),
    }
    MANIFEST_FILE.write_text(json.dumps(manifest, indent=2))
    _chmod_private(MANIFEST_FILE)
    print(f"\nManifest saved to {MANIFEST_FILE}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Production encrypt findings (OpenSSL / PyCryptodome) + optional Gist offload.",
    )
    parser.add_argument("--keep", action="store_true", help="Keep unencrypted originals")
    parser.add_argument("--live-backup", action="store_true",
                        help="Safe live backup of hits/status only (always keeps originals, vault dir)")
    parser.add_argument("--decrypt", action="store_true", help="Decrypt all .enc files")
    parser.add_argument("--decrypt-file", type=str, help="Decrypt a single .enc file")
    parser.add_argument("--passphrase", default=None, help="Passphrase (or ENCRYPT_PASSPHRASE env)")
    parser.add_argument("--dry-run", action="store_true", help="List files only")
    parser.add_argument("--no-gist", action="store_true", help="Skip GitHub Gist upload")
    parser.add_argument("--backend", default="auto", choices=("auto", "openssl", "pycryptodome"))
    args = parser.parse_args()

    backend = resolve_backend(args.backend)

    if args.decrypt or args.decrypt_file:
        passphrase = get_passphrase(args.passphrase, allow_generate=False)
        if args.decrypt:
            decrypt_files(passphrase)
        else:
            decrypt_single_file(Path(args.decrypt_file), passphrase)
        return

    if args.dry_run:
        print(f"Backend: {backend} (pycryptodome installed={_have_pycryptodome()})")
        names = LIVE_BACKUP_FILES if args.live_backup else FINDINGS_FILES
        print("Files that would be encrypted:")
        for fname in names:
            p = APP_DIR / fname
            if p.exists():
                print(f"  {fname} ({p.stat().st_size} bytes)")
            else:
                print(f"  {fname} (missing)")
        return

    passphrase = get_passphrase(args.passphrase, allow_generate=True)

    if args.live_backup:
        print(f"[+] LIVE BACKUP [{backend}] — hits/status only, originals kept, vault={VAULT_DIR}")
        meta = encrypt_files(
            passphrase,
            LIVE_BACKUP_FILES,
            keep_originals=True,
            backend=backend,
            dest_dir=VAULT_DIR,
        )
        mode = "live-backup"
        do_gist = False  # live backups stay local by default
    else:
        print(f"[+] Encrypting findings [{backend}] (AES, PBKDF2 iter={OPENSSL_ITER})...")
        meta = encrypt_files(
            passphrase,
            FINDINGS_FILES,
            keep_originals=args.keep,
            backend=backend,
            dest_dir=APP_DIR,
        )
        mode = "full"
        do_gist = not args.no_gist

    if not meta:
        print("[!] No files were encrypted.")
        write_manifest([], backend, "", mode)
        return

    gist_url = ""
    if do_gist:
        token = load_github_token()
        if token:
            print(f"[+] Uploading eligible encrypted file(s) to GitHub Gist...")
            gist_url = create_gist(token, meta, backend)
            if gist_url:
                print(f"\nOK Encrypted Gist: {gist_url}")
            else:
                print("\nWARNING: Gist upload failed or skipped; encrypted files on disk.")
        else:
            print("[!] No GitHub token — skipping Gist (encrypted files on disk).")

    write_manifest(meta, backend, gist_url, mode)
    print("[+] Done. Decrypt: python3 ~/encrypt_offload.py --decrypt")
    print("    Or: ENCRYPT_PASSPHRASE='…' python3 ~/encrypt_offload.py --decrypt-file FILE.enc")


if __name__ == "__main__":
    main()
