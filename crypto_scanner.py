#!/usr/bin/env python3
"""Crypto Scanner and Balance Checker"""
import json, re, sys, os, time, math, hashlib, base64
from urllib.request import Request, urlopen
from urllib.error import URLError
from datetime import datetime, timezone
import threading
from typing import Dict, List

CHECK_INTERVAL = 5
ENTROPY_THRESHOLD = 4.0
MIN_BASE64_LEN = 20
MIN_BASE58_LEN = 25
SCAN_FILE = sys.argv[1] if len(sys.argv) > 1 else ".trufflehog_results.jsonl"
APP_DIR = os.path.dirname(os.path.abspath(__file__))
MEMORY_FILE = os.path.join(APP_DIR, "crypto_scanner_memory.jsonl")
PID_FILE = os.path.join(APP_DIR, "crypto_scanner.pid")
STATUS_FILE = os.path.join(APP_DIR, "crypto_scanner_status.txt")

BIP39_WORDS = {
    "abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse",
    "access","accident","account","accuse","achieve","acid","acoustic","acquire","across","act",
    "action","actor","actress","actual","adapt","add","addict","address","adjust","admit",
    "adult","advance","advice","aerobic","affair","afford","afraid","again","age","agent",
    "agree","ahead","aim","air","airport","aisle","alarm","album","alcohol","alert",
    "alien","all","alley","allow","almost","alone","alpha","already","also","alter",
    "always","amateur","amazing","among","amount","amused","analyst","anchor","ancient","anger",
    "angle","angry","animal","ankle","announce","annual","another","answer","antenna","antique",
    "anxiety","any","apart","apology","appear","apple","approve","april","arch","arctic",
    "area","arena","argue","arm","armed","armor","army","around","arrange","arrest",
    "arrive","arrow","art","artefact","artist","artwork","ask","aspect","assault","asset",
    "assist","assume","asthma","athlete","atom","attack","attend","attitude","attract","auction",
    "audit","august","aunt","author","auto","autumn","average","avocado","avoid","awake",
    "aware","away","awesome","awful","awkward","axis",
    "baby","bachelor","bacon","badge","bag","balance","balcony","ball","bamboo","banana",
    "banner","bar","barely","bargain","barrel","base","basic","basket","battle","beach",
    "bean","beauty","because","become","beef","before","begin","behave","behind","believe",
    "below","belt","bench","benefit","best","betray","better","between","beyond","bicycle",
    "bid","bike","bind","biology","bird","birth","bitter","black","blade","blame",
    "blanket","blast","bleak","bless","blind","blood","blossom","blouse","blue","blur",
    "blush","board","boat","body","boil","bomb","bone","bonus","book","boost",
    "border","boring","borrow","boss","bottom","bounce","box","boy","bracket","brain",
    "brand","brass","brave","bread","breeze","brick","bridge","brief","bright","bring",
    "brisk","broccoli","broken","bronze","broom","brother","brown","brush","bubbles","buddy",
    "budget","buffalo","build","bulb","bulk","bullet","bundle","bunker","burden","burger",
    "burst","bus","business","busy","butter","buyer","buzz"
}
WIF_PAT = re.compile(r"\b[5KL][1-9A-HJ-NP-Za-km-z]{51}\b")
HEX_KEY_PAT = re.compile(r"\b[0-9a-fA-F]{64}\b")
BTC_ADDR = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
BTC_BECH32 = re.compile(r"\bbc1[a-z0-9]{8,87}\b")
ETH_ADDR = re.compile(r"\b0x[0-9a-fA-F]{40}\b")
LTC_ADDR = re.compile(r"\b[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\b")
LTC_BECH32 = re.compile(r"\bltc1[a-z0-9]{8,87}\b")
SOL_ADDR = re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b")
DOGE_ADDR = re.compile(r"\bD[5KL][1-9A-HJ-NP-Za-km-z]{32,34}\b")
XRP_ADDR = re.compile(r"\br[1-9A-HJ-NP-Za-km-z]{25,34}\b")
TON_ADDR = re.compile(r"\b[UE]Q[a-zA-Z0-9_-]{46}\b")
AVAX_ADDR = re.compile(r"\b[XC][0-9a-zA-Z]{41}\b")
MATIC_ADDR = ETH_ADDR
PEM_PAT = re.compile(r"-----BEGIN ([A-Z ]+?)-----\r?\n[\s\S]+?-----END \1-----", re.MULTILINE)
B64_PAT = re.compile(r"\b[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/]{40,}={0,2}\b")
B58_PAT = re.compile(r"\b[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{30,}\b")
ANSI_PAT = re.compile(r"\x1b\[[\d;]*m")
WORD_PAT = re.compile(r"[a-zA-Z]+")



def calc_entropy(s: str) -> float:
    if not s:
        return 0.0
    ent = 0.0
    for x in dict.fromkeys(s):
        p = s.count(x) / len(s)
        ent -= p * math.log2(p)
    return ent


def looks_bip39(words):
    return len(words) in (12, 18, 24) and all(w.lower() in BIP39_WORDS for w in words)

def extract_bip39(text):
    words = WORD_PAT.findall(text)
    found = []
    for i in range(len(words) - 11):
        for l in (12, 18, 24):
            if i + l <= len(words) and looks_bip39(words[i:i + l]):
                phrase = " ".join(words[i:i + l])
                if phrase not in found:
                    found.append(phrase)
    return found

def clean_ansi(text):
    return ANSI_PAT.sub("", text)

def is_valid_b64(s):
    s2 = s.rstrip("=")
    if len(s2) < MIN_BASE64_LEN:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/]+", s2):
        return False
    if len(s2) % 4 != 0:
        return False
    try:
        pad = "=" * ((4 - len(s2) % 4) % 4)
        base64.b64decode(s2 + pad, validate=True)
        return True
    except Exception:
        return False

def scan_line(line):
    findings = {
        "bip39": [], "wif": [], "hex_key": [], "base64": [], "base58": [],
        "pem": [], "btc": [], "eth": [], "ltc": [], "sol": [],
        "doge": [], "xrp": [], "ton": [], "avax": [], "matic": [], "high_entropy": []
    }
    try:
        record = json.loads(line)
        text = json.dumps(record, ensure_ascii=False)
    except Exception:
        text = line

    text = clean_ansi(text)

    findings["bip39"].extend(extract_bip39(text))

    for m in WIF_PAT.finditer(text):
        findings["wif"].append(m.group(0))

    for m in HEX_KEY_PAT.finditer(text):
        h = m.group(0)
        if calc_entropy(h) > 5.0:
            findings["hex_key"].append(h)

    for m in B64_PAT.finditer(text):
        s = m.group(0)
        if is_valid_b64(s):
            try:
                pad = "=" * ((4 - len(s.rstrip("=")) % 4) % 4)
                dec = base64.b64decode(s.rstrip("=") + pad, validate=True)
                if len(dec) >= 16 and calc_entropy(dec.hex()) > ENTROPY_THRESHOLD:
                    findings["base64"].append(s)
                    findings["high_entropy"].append(f"b64:{s}")
            except Exception:
                pass

    for m in B58_PAT.finditer(text):
        s = m.group(0)
        if len(s) >= MIN_BASE58_LEN and calc_entropy(s) > ENTROPY_THRESHOLD:
            findings["base58"].append(s)
            findings["high_entropy"].append(f"b58:{s}")

    for m in PEM_PAT.finditer(text):
        findings["pem"].append(m.group(0))

    for m in BTC_ADDR.finditer(text):
        findings["btc"].append(m.group(0))
    for m in BTC_BECH32.finditer(text):
        findings["btc"].append(m.group(0))
    for m in ETH_ADDR.finditer(text):
        findings["eth"].append(m.group(0))
        findings["matic"].append(m.group(0))
    for m in LTC_ADDR.finditer(text):
        findings["ltc"].append(m.group(0))
    for m in LTC_BECH32.finditer(text):
        findings["ltc"].append(m.group(0))
    for m in SOL_ADDR.finditer(text):
        findings["sol"].append(m.group(0))
    for m in DOGE_ADDR.finditer(text):
        findings["doge"].append(m.group(0))
    for m in XRP_ADDR.finditer(text):
        findings["xrp"].append(m.group(0))
    for m in TON_ADDR.finditer(text):
        findings["ton"].append(m.group(0))
    for m in AVAX_ADDR.finditer(text):
        findings["avax"].append(m.group(0))

    for k in findings:
        findings[k] = list(dict.fromkeys(findings[k]))

    return findings



def check_balance(chain, address):
    url = None
    try:
        if chain == "btc":
            url = f"https://blockchain.info/balance?active={address}"
        elif chain == "eth":
            url = f"https://api.etherscan.io/api?module=account&action=balance&address={address}&tag=latest"
        elif chain == "matic":
            url = f"https://api.polygonscan.com/api?module=account&action=balance&address={address}&tag=latest"
        elif chain == "ltc":
            url = f"https://chainz.cryptoid.info/ltc/api.dws?q=getbalance&a={address}"
        elif chain == "sol":
            url = f"https://api.mainnet-beta.solana.com"
        elif chain == "doge":
            url = f"https://dogechain.info/api/v1/address/balance/{address}"
        elif chain == "xrp":
            url = f"https://api.xrpscan.com/api/v1/account/{address}"
        elif chain == "ton":
            url = f"https://toncenter.com/api/v2/getAddressBalance?address={address}"
        elif chain == "avax":
            url = f"https://api.snowtrace.io/api?module=account&action=balance&address={address}&tag=latest"
        else:
            return None
        if not url:
            return None
        req = Request(url, headers={"User-Agent": "crypto-scanner/1.0"})
        with urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            bal = None
            if chain == "btc" and "final_balance" in data:
                bal = data["final_balance"] / 1e8
            elif chain == "eth" and data.get("message") == "OK" and "result" in data:
                bal = int(data["result"]) / 1e18
            elif chain == "matic":
                bal = int(data.get("result", 0)) / 1e18
            elif chain == "doge" and "balance" in data:
                bal = float(data["balance"])
            elif chain == "xrp" and "account" in data:
                bal = float(data["account"].get("balance", 0)) / 1e6
            return bal
    except Exception:
        return None


def check_balances(addresses):
    results = []
    threads = []
    lock = threading.Lock()

    def run(chain, addr):
        bal = check_balance(chain, addr)
        with lock:
            results.append({
                "chain": chain, "address": addr,
                "balance": bal, "ts": datetime.now(timezone.utc).isoformat() + "Z"
            })

    for chain, addrs in addresses.items():
        if not addrs:
            continue
        for a in addrs:
            t = threading.Thread(target=run, args=(chain, a))
            threads.append(t)
            t.start()

    for t in threads:
        t.join()

    return results





def tail_file(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, 0)
        while True:
            line = f.readline()
            if line:
                yield line.rstrip("\n")
            else:
                time.sleep(0.5)


def main():
    scan_path = SCAN_FILE
    if not os.path.exists(scan_path):
        print(f"[!] Scan file not found: {scan_path}")
        sys.exit(1)

    print(f"[*] Crypto Scanner starting...")
    print(f"[*] Monitoring: {scan_path}")
    print(f"[*] Memory: {MEMORY_FILE}")
    print(f"[*] Interval: {CHECK_INTERVAL}s")
    print(f"[*] Press Ctrl+C to stop\n")

    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))

    seen_lines = set()
    processed = 0
    findings_total = 0
    start_ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    with open(STATUS_FILE, "w") as f:
        f.write(f"started={start_ts}, processed=0, findings=0, memory=0 bytes")

    try:
        for line in tail_file(scan_path):
            if not line.strip():
                continue
            h = hashlib.md5(line.encode()).hexdigest()
            if h in seen_lines:
                continue
            seen_lines.add(h)
            if len(seen_lines) > 100_000:
                seen_lines.clear()

            findings = scan_line(line)
            if any(findings[k] for k in findings if k != "high_entropy"):
                processed += 1
                record = {
                    "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "findings": findings,
                    "source_line": line[:200],
                }
                with open(MEMORY_FILE, "a") as f:
                    f.write(json.dumps(record) + "\n")

                print(f"[+] Findings #{processed} at {record['ts']}:")
                for k, vs in findings.items():
                    if vs and k != "high_entropy":
                        print(f"    {k}: {vs}")

                addr_map = {
                    k: v for k, v in findings.items()
                    if k in ("btc","eth","ltc","sol","doge","xrp","ton","avax","matic")
                }
                if addr_map:
                    bal_results = check_balances(addr_map)
                    for b in bal_results:
                        if b["balance"] is not None and b["balance"] > 0:
                            print(f"    *** BALANCE FOUND *** {b['chain']} {b['address']} => {b['balance']}")
                            with open("balances_hit.jsonl", "a") as f:
                                f.write(json.dumps(b) + "\n")
                            findings_total += 1

            status = f"processed={processed}, findings={findings_total}, memory={os.path.getsize(MEMORY_FILE) if os.path.exists(MEMORY_FILE) else 0} bytes"
            with open(STATUS_FILE, "w") as f:
                f.write(status)

    except KeyboardInterrupt:
        print(f"\n[+] Stopped. Processed {processed} finding-blocks, {findings_total} balance hits.")
    finally:
        try:
            os.remove(PID_FILE)
        except OSError:
            pass


if __name__ == "__main__":
    main()

