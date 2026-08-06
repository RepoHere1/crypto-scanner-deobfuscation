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

import requests, ecdsa
import balance_db as db
import multichain as mc

# ── RLP encoder (pure Python, no deps) ──────────────────────────
def _ib(n): return b"" if n==0 else n.to_bytes((n.bit_length()+7)//8,"big")
def _rlp(item):
    if isinstance(item,int): return _rlp(_ib(item))
    if isinstance(item,bytes):
        if len(item)==1 and item[0]<0x80: return item
        if len(item)<56: return bytes([0x80+len(item)])+item
        lb=_ib(len(item)); return bytes([0xb7+len(lb)])+lb+item
    if isinstance(item,list):
        p=b"".join(_rlp(i) for i in item)
        if len(p)<56: return bytes([0xc0+len(p)])+p
        lb=_ib(len(p)); return bytes([0xf7+len(lb)])+lb+p

try:
    from flask import Flask, jsonify, request, render_template_string
except ImportError:
    print("[!] Flask not installed. Run: pip install flask", file=sys.stderr)
    sys.exit(1)

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False


def _api_error(message, status=500, **extra):
    """Always return JSON for API failures (never HTML)."""
    payload = {"ok": False, "error": str(message)}
    payload.update(extra)
    return jsonify(payload), int(status)


@app.errorhandler(404)
def _err_404(e):
    if request.path.startswith("/api/"):
        return _api_error("Not found: " + request.path, 404)
    return e


@app.errorhandler(405)
def _err_405(e):
    if request.path.startswith("/api/"):
        return _api_error("Method not allowed", 405)
    return e


@app.errorhandler(500)
def _err_500(e):
    if request.path.startswith("/api/"):
        return _api_error("Internal server error: " + str(getattr(e, "description", e)), 500)
    return e


@app.errorhandler(Exception)
def _err_any(e):
    # Only force-JSON for API routes; let non-API bubble as normal if needed
    try:
        if request.path.startswith("/api/"):
            return _api_error(type(e).__name__ + ": " + str(e), 500)
    except Exception:
        pass
    raise e


# ── HTML template (tabbed dashboard) ────────────────────────────────
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
hdr{display:flex;align-items:center;gap:12px;padding:12px 8px;border-bottom:2px solid #ff8c00;margin-bottom:4px;flex-wrap:wrap}
hdr .logo{font-size:22px;font-weight:bold;color:#ff8c00}
hdr .stat{font-size:12px;color:#888}
hdr .stat .val{color:#ffd700}
.live{color:#0f0}.cached{color:#666}
#tabs{display:flex;gap:4px;padding:4px 0 0;overflow-x:auto}
#tabs button{padding:8px 16px;background:#111;color:#888;border:1px solid #333;border-bottom:none;border-radius:4px 4px 0 0;cursor:pointer;font:inherit;font-size:13px;white-space:nowrap}
#tabs button.active{background:#1a1a1a;color:#ff8c00;border-color:#ff8c00;font-weight:bold}
.tab-panel{display:none;border:1px solid #333;border-radius:0 4px 4px 4px;background:#0a0a0a;padding:12px;min-height:400px}
.tab-panel.active{display:block}
#stats{display:flex;gap:16px;flex-wrap:wrap;padding:4px 0;margin-bottom:4px}
#stats .s{font-size:11px;color:#888}
#stats .s .n{color:#ffd700;font-weight:bold}
#searchbar{display:flex;gap:8px;padding:0 0 8px;flex-wrap:wrap}
#searchbar input,#searchbar select,#searchbar button,.form-row input,.form-row select,.form-row button,.form-row textarea{padding:8px 12px;background:#1a1a1a;color:#fff;border:1px solid #333;border-radius:4px;font:inherit;font-size:13px}
#searchbar input{flex:1;min-width:160px}
#searchbar button,.btn-orange{background:#ff8c00;color:#000;font-weight:bold;border:none;cursor:pointer}
#searchbar button:active,.btn-orange:active{opacity:.8}
.btn-orange:disabled{opacity:.4}
#main{display:flex;gap:8px;height:calc(100vh - 260px)}
#leaderboard{flex:1;overflow-y:auto;border:1px solid #333;border-radius:4px;background:#0a0a0a;min-width:260px}
#detail{flex:1;overflow-y:auto;border:1px solid #333;border-radius:4px;background:#0a0a0a;min-width:260px;padding:12px}
.wallet{padding:8px 12px;border-bottom:1px solid #1a1a1a;cursor:pointer;display:flex;gap:8px;align-items:center;font-size:13px}
.wallet:hover{background:#1a1a1a}
.wallet.active{background:#2a1a00;border-left:3px solid #ff8c00}
.wallet .r{color:#ff8c00;font-weight:bold;min-width:28px}
.wallet .c{color:#0af;min-width:36px;font-size:11px}
.wallet .bal{color:#0f0;text-align:right;min-width:90px}
.wallet .addr{color:#999;font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:180px}
#detail .section{margin-bottom:12px}
#detail .label{color:#ff8c00;font-weight:bold;display:block;margin-bottom:4px}
#detail .val{word-break:break-all;font-size:13px;line-height:1.6;color:#ffd700}
#detail .addr-row{display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid #1a1a1a;font-size:12px}
#detail .addr-row .chain{color:#0af;min-width:50px}
#detail .addr-row .addr{color:#999;flex:1;margin:0 8px;word-break:break-all}
#detail .btns{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}
#detail .btns button{padding:6px 12px;background:#1a1a1a;color:#ff8c00;border:1px solid #ff8c00;border-radius:4px;cursor:pointer;font:inherit;font-size:12px}
#detail .btns button:hover{background:#2a1a00}
.nav{display:flex;gap:8px;justify-content:center;padding:12px}
.nav button{padding:10px 24px;background:#ff8c00;color:#000;font-weight:bold;border:none;border-radius:4px;cursor:pointer;font:inherit;font-size:14px}
.nav button:disabled{opacity:.4}
.nav .pg{color:#888;font-size:13px;align-self:center}
#toast{position:fixed;bottom:20px;right:20px;background:#ff8c00;color:#000;padding:12px 20px;border-radius:4px;font-weight:bold;display:none;z-index:99}
.form-row{display:flex;gap:8px;margin-bottom:10px;flex-wrap:wrap;align-items:center}
.form-row label{color:#888;font-size:12px;min-width:50px}
.form-row input,.form-row select{flex:1;min-width:120px}
.result-box{margin-top:12px;padding:12px;background:#111;border:1px solid #333;border-radius:4px;max-height:300px;overflow-y:auto;font-size:12px;word-break:break-all;color:#ffd700}
.result-box .err{color:#f44}
.result-box .ok{color:#0f0}
.addr-card{display:flex;justify-content:space-between;align-items:center;padding:6px 8px;border-bottom:1px solid #1a1a1a;font-size:12px}
.addr-card .chain{color:#0af;min-width:60px;font-weight:bold}
.addr-card .ad{color:#ffd700;flex:1;margin:0 8px;word-break:break-all;font-size:11px}
.addr-card button{font-size:10px;padding:2px 8px;background:#1a1a1a;color:#ff8c00;border:1px solid #ff8c00;border-radius:3px;cursor:pointer}
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
<div id="tabs">
<button class="active" onclick="switchTab('balances')">💰 Balances</button>
<button onclick="switchTab('send')">📤 Send</button>
<button onclick="switchTab('swap')">🔄 Swap</button>
<button onclick="switchTab('bridge')">🌉 Bridge</button>
<button onclick="switchTab('receive')">📥 Receive</button>
</div>

<!-- Balances Tab -->
<div id="tab-balances" class="tab-panel active">
<div id="stats"></div>
<div id="searchbar">
<input type="text" id="q" placeholder="Search address, chain, balance..." oninput="doSearch()">
<select id="chainFilter" onchange="doFilter()">
<option value="">All chains</option>
<option>ETH</option><option>MATIC</option><option>BTC</option><option>SOL</option><option>BNB</option><option>AVAX</option><option>BASE</option><option>ARB</option><option>OP</option><option>LTC</option><option>DOGE</option>
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

<!-- Send Tab -->
<div id="tab-send" class="tab-panel">
<div class="form-row"><label>Chain</label><select id="sendChain">
<option>ETH</option><option>MATIC</option><option>BNB</option><option>AVAX</option><option>BASE</option><option>ARB</option><option>OP</option>
</select></div>
<div class="form-row"><label>Private Key</label><input type="password" id="sendKey" placeholder="64-char hex private key"></div>
<div class="form-row"><label>To Address</label><input id="sendTo" placeholder="0x... or BTC/SOL address"></div>
<div class="form-row"><label>Amount</label><input id="sendAmt" placeholder="0.01" type="number" step="any"></div>
<div class="form-row">
<button class="btn-orange" onclick="doSend()" style="flex:1">📤 Send</button>
<button onclick="doSendLiveBalance()" style="background:#1a1a1a;color:#0af;border:1px solid #0af">💰 Check Balance</button>
</div>
<div id="sendResult" class="result-box" style="display:none"></div>
</div>

<!-- Swap Tab -->
<div id="tab-swap" class="tab-panel">
<div class="form-row"><label>Chain</label><select id="swapChain" onchange="updateSwapTokens()">
<option value="eth">ETH</option><option value="matic">MATIC</option><option value="bnb">BNB</option><option value="base">BASE</option><option value="arb">ARB</option><option value="sol">SOL</option>
</select></div>
<div class="form-row"><label>From</label><select id="swapFrom"></select><input id="swapAmt" placeholder="0.01" type="number" step="any" style="max-width:120px"></div>
<div class="form-row"><label>To</label><select id="swapTo"></select></div>
<div class="form-row"><label>Address</label><input id="swapAddr" placeholder="Your wallet address"></div>
<div class="form-row"><button class="btn-orange" onclick="doSwapQuote()" style="flex:1">🔄 Get Quote</button></div>
<div id="swapResult" class="result-box" style="display:none"></div>
</div>

<!-- Bridge Tab -->
<div id="tab-bridge" class="tab-panel">
<div class="form-row"><label>From</label><select id="bridgeFrom">
<option value="eth">ETH</option><option value="matic">MATIC</option><option value="bnb">BNB</option><option value="avax">AVAX</option><option value="base">BASE</option><option value="arb">ARB</option><option value="op">OP</option>
</select></div>
<div class="form-row"><label>To</label><select id="bridgeTo">
<option value="base">BASE</option><option value="arb">ARB</option><option value="op">OP</option><option value="matic">MATIC</option><option value="bnb">BNB</option><option value="eth">ETH</option>
</select></div>
<div class="form-row"><label>Token</label><input id="bridgeToken" value="ETH" placeholder="ETH/USDC"></div>
<div class="form-row"><label>Amount</label><input id="bridgeAmt" placeholder="0.01" type="number" step="any"></div>
<div class="form-row"><label>Address</label><input id="bridgeAddr" placeholder="Your wallet address"></div>
<div class="form-row"><button class="btn-orange" onclick="doBridgeQuote()" style="flex:1">🌉 Get Bridge Quote</button></div>
<div id="bridgeResult" class="result-box" style="display:none"></div>
</div>

<!-- Receive Tab -->
<div id="tab-receive" class="tab-panel">
<div class="form-row"><label>Private Key</label><input type="password" id="recvKey" placeholder="64-char hex private key" style="flex:1"></div>
<div class="form-row"><button class="btn-orange" onclick="doReceive()" style="flex:1">📥 Derive All Addresses</button></div>
<div id="recvResult" class="result-box" style="display:none"></div>
</div>

</div>
<div id="toast"></div>
<script>
// ── Tab switching ──
function switchTab(name){
 document.querySelectorAll('#tabs button').forEach(b=>b.classList.remove('active'));
 document.querySelectorAll('.tab-panel').forEach(p=>p.classList.remove('active'));
 document.getElementById('tab-'+name).classList.add('active');
 event.target.classList.add('active');
}

// ── Shared ──
function toast(m){let t=document.getElementById('toast');t.textContent=m;t.style.display='block';setTimeout(()=>t.style.display='none',2000)}
function copyAddr(a){navigator.clipboard.writeText(a);toast('Copied!')}

// ── Balances tab (existing logic) ──
let PAGE=0,PERPAGE=50,TOTAL=0,focus=null,wallets=[],autoTimer=null;
async function load(){
 try{
  let u=`/api/balances?limit=${PERPAGE}&offset=${PAGE*PERPAGE}&funded_only=true&keyed_only=true&sort_by=${document.getElementById('sortBy').value}`;
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
 }catch(e){console.error(e);document.getElementById('stLive').textContent='○ ERR';document.getElementById('leaderboard').innerHTML='<div style="color:#f66;padding:12px">API error</div>';}
}
function renderLb(){
 let lb=document.getElementById('leaderboard'),h='';
 wallets.forEach((w,i)=>{
  let bal=w.balance,bs=bal>1e6?(bal/1e6).toFixed(1)+'M':bal>1?(bal).toFixed(2):bal>1e-8?bal.toFixed(8):'0';
  let addr=(w.address||''),as=addr.length>20?addr.slice(0,10)+'...'+addr.slice(-8):addr;
  h+=`<div class="wallet${focus===i?' active':''}" onclick="showDetail(${i})" title="${addr}">
   <span class="r">#${PAGE*PERPAGE+i+1}</span><span class="c">${(w.chain||'?').toUpperCase()}</span>
   <span class="bal">${bs}</span><span class="addr">${as}</span></div>`;
 });
 lb.innerHTML=h||'<div style="color:#666;padding:12px">No funded wallets found</div>';
}
async function showDetail(i){
 focus=i;renderLb();let w=wallets[i],d=document.getElementById('detail');
 let bal=w.balance,bs=bal>1e6?(bal/1e6).toFixed(6)+'M':bal>1?bal.toFixed(6):bal.toFixed(12);
 d.innerHTML=`<div class="section"><span class="label">CHAIN</span><span class="val">${(w.chain||'?').toUpperCase()}</span></div>
 <div class="section"><span class="label">ADDRESS</span><span class="val" style="font-size:11px">${w.address||''}</span></div>
 <div class="section"><span class="label">BALANCE</span><span class="val">${bs}</span></div>
 <div class="btns"><button onclick="copyAddr('${w.address}')">📋 Copy</button>
 <button onclick="openExplorer('${w.chain}','${w.address}')">🔗 Explorer</button>
 <button onclick="fillSend('${w.chain}','${w.address}')">📤 Send</button></div>
 <div id="keySection" style="margin-top:12px"><span style="color:#888">🔑 Loading keys...</span></div>`;
 let addr=encodeURIComponent(w.address||'');
 try{let r=await fetch('/api/wallet/'+addr),kd=await r.json(),ks=document.getElementById('keySection');
  if(!kd.found){ks.innerHTML='<div class="section"><span class="label">🔑 KEY</span><span class="val" style="color:#888">'+kd.reason+'</span></div>';return}
  let kh='<div class="section"><span class="label">🔑 KEY MATERIAL</span></div>';
  if(kd.hex_keys&&kd.hex_keys.length){kh+='<div class="section"><span class="label">HEX KEYS</span>';
   kd.hex_keys.forEach((k,j)=>{kh+=`<div class="val" style="font-size:10px;margin:2px 0">[${j+1}] ${k} <button onclick="copyAddr('${k}')" style="font-size:10px;padding:2px 6px;background:#1a1a1a;color:#ff8c00;border:1px solid #ff8c00;border-radius:2px;cursor:pointer">📋</button></div>`});kh+='</div>';}
  if(kd.seeds&&kd.seeds.length){kh+='<div class="section"><span class="label">🌱 SEED PHRASES</span>';
   kd.seeds.forEach((k,j)=>{kh+=`<div class="val" style="font-size:11px;margin:2px 0;background:#0a0a0a;padding:8px;border:1px solid #333;border-radius:4px">[${j+1}] ${k} <button onclick="copyAddr('${k.replace(/'/g,"\\'")}')" style="font-size:10px;padding:2px 6px;background:#1a1a1a;color:#ff8c00;border:1px solid #ff8c00;border-radius:2px;cursor:pointer">📋</button></div>`});kh+='</div>';}
  ks.innerHTML=kh;
 }catch(e){document.getElementById('keySection').innerHTML='<span style="color:#f44">'+e.message+'</span>'}
}
function fillSend(chain,addr){switchTab('send');document.getElementById('sendChain').value=chain.toUpperCase();document.getElementById('sendTo').value=addr}
function openExplorer(c,a){
 let urls={ETH:`https://etherscan.io/address/${a}`,MATIC:`https://polygonscan.com/address/${a}`,BTC:`https://mempool.space/address/${a}`,SOL:`https://solscan.io/account/${a}`,BNB:`https://bscscan.com/address/${a}`,AVAX:`https://snowtrace.io/address/${a}`,BASE:`https://basescan.org/address/${a}`,ARB:`https://arbiscan.io/address/${a}`,OP:`https://optimistic.etherscan.io/address/${a}`,LTC:`https://litecoinspace.org/address/${a}`,DOGE:`https://dogechain.info/address/${a}`};
 window.open(urls[c.toUpperCase()]||urls.ETH,'_blank');
}
function prevPage(){if(PAGE>0){PAGE--;load()}}
function nextPage(){PAGE++;load()}
function doSearch(){PAGE=0;load()}
function doFilter(){PAGE=0;load()}
document.addEventListener('keydown',e=>{if(e.key==='ArrowRight')nextPage();if(e.key==='ArrowLeft')prevPage()});

// ── Send tab ──
async function doSend(){
 let r=document.getElementById('sendResult');r.style.display='block';r.innerHTML='<span style="color:#ff8c00">⏳ Sending...</span>';
 let chain=document.getElementById('sendChain').value.toLowerCase();
 let key=document.getElementById('sendKey').value.trim();
 let to=document.getElementById('sendTo').value.trim();
 let amt=parseFloat(document.getElementById('sendAmt').value);
 if(!key||!to||!amt){r.innerHTML='<span class="err">Fill all fields</span>';return}
 try{
  let resp=await fetch('/api/send-multi',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({chain:chain,private_key:key,to:to,amount:amt})});
  let d=await resp.json();
  if(d.ok){r.innerHTML=`<span class="ok">✓ TX SENT!</span><br>Hash: ${d.tx_hash}<br>From: ${d.from}<br>To: ${d.to}<br>Chain: ${d.chain}<br><a href="${d.explorer}" target="_blank" style="color:#0af">🔗 View on Explorer</a>`}
  else{r.innerHTML=`<span class="err">✗ ${d.error}</span><br><pre style="color:#888;font-size:11px">${JSON.stringify(d,null,2)}</pre>`}
 }catch(e){r.innerHTML=`<span class="err">✗ ${e.message}</span>`}
}
async function doSendLiveBalance(){
 let r=document.getElementById('sendResult');r.style.display='block';r.innerHTML='<span style="color:#ff8c00">⏳ Checking...</span>';
 let chain=document.getElementById('sendChain').value.toLowerCase();
 let key=document.getElementById('sendKey').value.trim();
 if(!key){r.innerHTML='<span class="err">Enter private key first</span>';return}
 try{
  let resp=await fetch('/api/receive',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({private_key:key})});
  let d=await resp.json();
  if(d.error){r.innerHTML=`<span class="err">${d.error}</span>`;return}
  let addr=d[chain]?d[chain].address:null;
  if(!addr){r.innerHTML='<span class="err">Cannot derive address for '+chain+'</span>';return}
  let br=await fetch(`/api/balance-live?chain=${chain}&address=${addr}`),bd=await br.json();
  if(bd.balance!=null){r.innerHTML=`<span class="ok">💰 ${bd.balance} ${bd.symbol} on ${chain.toUpperCase()}</span><br><span style="color:#888;font-size:11px">${addr}</span>`}
  else{r.innerHTML=`<span class="err">Balance check failed: ${bd.error||'unknown'}</span>`}
 }catch(e){r.innerHTML=`<span class="err">${e.message}</span>`}
}

// ── Swap tab ──
function updateSwapTokens(){
 let c=document.getElementById('swapChain').value;
 let opts={eth:['ETH','USDC','USDT','DAI','WBTC'],matic:['MATIC','USDC','USDT'],bnb:['BNB','USDC','USDT'],base:['ETH','USDC'],arb:['ETH','USDC','USDT'],sol:['SOL','USDC','USDT']};
 let tokens=opts[c]||['ETH','USDC'];
 let sf=document.getElementById('swapFrom'),st=document.getElementById('swapTo');
 sf.innerHTML=tokens.map(t=>`<option>${t}</option>`).join('');
 st.innerHTML=tokens.map(t=>`<option>${t}</option>`).join('');
 st.selectedIndex=1;
}
async function doSwapQuote(){
 let r=document.getElementById('swapResult');r.style.display='block';r.innerHTML='<span style="color:#ff8c00">⏳ Getting swap quote...</span>';
 let chain=document.getElementById('swapChain').value;
 let fromT=document.getElementById('swapFrom').value;
 let toT=document.getElementById('swapTo').value;
 let amt=parseFloat(document.getElementById('swapAmt').value);
 let addr=document.getElementById('swapAddr').value.trim();
 if(!amt||!addr){r.innerHTML='<span class="err">Fill amount and address</span>';return}
 try{
  let u=`/api/swap/quote?chain=${chain}&from_token=${fromT}&to_token=${toT}&amount=${amt}&from_addr=${addr}`;
  let resp=await fetch(u),d=await resp.json();
  if(d.ok){let q=d.quote;r.innerHTML=`<span class="ok">✓ Quote ready</span><br><br>From: ${amt} ${fromT}<br>To: ~${q.buyAmount?parseInt(q.buyAmount)/1e6:q.outAmount?parseInt(q.outAmount)/1e9:'?'} ${toT}<br>Price: ${q.price||'?'}<br><pre style="color:#888;font-size:10px;max-height:150px;overflow-y:auto">${JSON.stringify(q,null,2)}</pre>`}
  else{r.innerHTML=`<span class="err">✗ ${d.error}</span>`}
 }catch(e){r.innerHTML=`<span class="err">✗ ${e.message}</span>`}
}

// ── Bridge tab ──
async function doBridgeQuote(){
 let r=document.getElementById('bridgeResult');r.style.display='block';r.innerHTML='<span style="color:#ff8c00">⏳ Getting bridge quote...</span>';
 let fc=document.getElementById('bridgeFrom').value;
 let tc=document.getElementById('bridgeTo').value;
 let tok=document.getElementById('bridgeToken').value;
 let amt=parseFloat(document.getElementById('bridgeAmt').value);
 let addr=document.getElementById('bridgeAddr').value.trim();
 if(!amt||!addr){r.innerHTML='<span class="err">Fill amount and address</span>';return}
 try{
  let u=`/api/bridge/quote?from_chain=${fc}&to_chain=${tc}&from_token=${tok}&to_token=${tok}&amount=${amt}&from_addr=${addr}`;
  let resp=await fetch(u),d=await resp.json();
  if(d.ok&&d.quote){let q=d.quote;r.innerHTML=`<span class="ok">✓ Bridge quote ready</span><br><br>${q.action?.fromToken?.symbol||tok}: ${amt}<br>→ ${q.action?.toToken?.symbol||tok}: ~${q.estimate?.toAmount||'?'}<br>Bridge: ${q.tool||'LI.FI'}<br><pre style="color:#888;font-size:10px;max-height:150px;overflow-y:auto">${JSON.stringify(q,null,2)}</pre>`}
  else{r.innerHTML=`<span class="err">✗ ${d.error||'No routes found'}</span>`}
 }catch(e){r.innerHTML=`<span class="err">✗ ${e.message}</span>`}
}

// ── Receive tab ──
async function doReceive(){
 let r=document.getElementById('recvResult');r.style.display='block';r.innerHTML='<span style="color:#ff8c00">⏳ Deriving addresses...</span>';
 let key=document.getElementById('recvKey').value.trim();
 if(!key){r.innerHTML='<span class="err">Enter private key</span>';return}
 try{
  let resp=await fetch('/api/receive',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({private_key:key})});
  let d=await resp.json();
  if(d.error){r.innerHTML=`<span class="err">${d.error}</span>`;return}
  let h='<span class="ok">✓ Addresses derived</span><br><br>';
  for(let[chain,info]of Object.entries(d)){
   if(info.error){h+=`<div class="addr-card"><span class="chain">${chain.toUpperCase()}</span><span style="color:#f44">${info.error}</span></div>`}
   else{h+=`<div class="addr-card"><span class="chain">${chain.toUpperCase()}</span><span class="ad">${info.address}</span><button onclick="copyAddr('${info.address}')">📋</button><button onclick="window.open('${info.explorer}','_blank')" style="margin-left:4px">🔗</button></div>`}
  }
  r.innerHTML=h;
 }catch(e){r.innerHTML=`<span class="err">✗ ${e.message}</span>`}
}

// ── Init ──
updateSwapTokens();
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
    """Dashboard stats — KEYED wallets only (no bare addresses / contracts)."""
    base = db.get_stats()
    try:
        keyed_stats = _keyed_balance_stats()
        base.update(keyed_stats)
        # Override headline numbers so UI never shows contract junk
        base["total"] = keyed_stats.get("keyed_total", 0)
        base["nonzero"] = keyed_stats.get("keyed_funded", 0)
        base["chain_totals"] = keyed_stats.get("keyed_chain_totals", {})
        base["keys_only"] = True
    except Exception as exc:
        base["keys_only_error"] = str(exc)
        base["keys_only"] = False
    return jsonify(base)


@app.route("/api/balances")
def api_balances():
    """Leaderboard: ONLY addresses that have known private-key material.

    Contracts / bare addresses / keyless hits are never returned.
    Default keyed_only=true (pass keyed_only=false only for debug).
    """
    chain = request.args.get("chain")
    min_bal = request.args.get("min_balance", type=float)
    funded_only = request.args.get("funded_only", "true").lower() == "true"
    # DEFAULT TRUE — no key, no listing
    keyed_only = request.args.get("keyed_only", "true").lower() != "false"
    limit = min(int(request.args.get("limit", 50)), 500)
    offset = max(0, int(request.args.get("offset", 0)))
    sort_by = request.args.get("sort_by", "balance")

    if not keyed_only:
        rows, total = db.filter_balances(
            chain=chain, min_balance=min_bal, funded_only=funded_only,
            limit=limit, offset=offset, sort_by=sort_by,
        )
        return jsonify({"rows": rows, "total": total, "keyed_only": False})

    rows, total = _keyed_balances(
        chain=chain,
        min_balance=min_bal,
        funded_only=funded_only,
        limit=limit,
        offset=offset,
        sort_by=sort_by,
    )
    return jsonify({"rows": rows, "total": total, "keyed_only": True})


@app.route("/api/search")
def api_search():
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"rows": [], "total": 0})
    limit = min(int(request.args.get("limit", 100)), 500)
    offset = max(0, int(request.args.get("offset", 0)))
    keyed_only = request.args.get("keyed_only", "true").lower() != "false"
    results = db.search_addresses(q, limit=max(limit * 5, 200))
    if keyed_only:
        keyed = _keyed_address_set()
        results = [r for r in results if _is_keyed_address(r.get("address") or "", keyed)]
    total = len(results)
    return jsonify({"rows": results[offset:offset + limit], "total": total, "keyed_only": keyed_only})


@app.route("/api/hits")
def api_hits():
    limit = min(int(request.args.get("limit", 50)), 200)
    return jsonify(db.get_recent_hits(limit=limit))


@app.route("/api/scanner-status")
def api_scanner_status():
    """Return live scanner progress so the dashboard shows real-time activity."""
    sf = HOME / "crypto_scanner_status.txt"
    data = {"scanner_alive": False, "processed": 0, "findings": 0, "memory_mb": 0,
            "queue": 0, "offset": 0, "status_age_sec": -1}
    if sf.exists():
        try:
            for part in sf.read_text().strip().split(","):
                if "=" in part:
                    k, v = part.split("=", 1)
                    data[k.strip()] = v.strip()
            data["scanner_alive"] = True
            data["status_age_sec"] = time.time() - sf.stat().st_mtime
        except Exception:
            pass
    return jsonify(data)


@app.route("/api/refresh-balances", methods=["POST"])
def api_refresh_balances():
    """Force live RPC balance check on all addresses and update SQLite.
    Runs in a thread so it doesn't block the dashboard."""
    import threading
    def _do_refresh():
        try:
            import crypto_scanner as cs
            rows, _ = db.filter_balances(funded_only=False, limit=99999, sort_by="ts")
            updated = 0
            for r in rows:
                try:
                    rec = cs.get_balance(r["chain"], r["address"], force=True)
                    db.set_balance(r["chain"], r["address"], rec)
                    updated += 1
                except Exception:
                    pass
            print(f"[refresh] Updated {updated} balances via live RPC")
        except Exception as e:
            print(f"[refresh] Failed: {e}")
    t = threading.Thread(target=_do_refresh, daemon=True)
    t.start()
    return jsonify({"ok": True, "message": "Balance refresh started in background — check /api/stats in a few seconds"})


@app.route("/api/health")
def api_health():
    return jsonify({"status": "ok", "ts": time.time()})


@app.route("/api/legacy")
def api_legacy():
    """Return fork-claimable assets (ETHW, ETC, BCH, BSV + 25+ more) for all funded addresses."""
    try:
        import abandoned_coin_scanner as acs
        data = acs.scan_all_funded(max_per_chain=500)
        return jsonify(data)
    except Exception as e:
        # Fallback to legacy detector
        try:
            import legacy_asset_detector as ldr
            data = ldr.detect_all()
            return jsonify(data)
        except Exception as e2:
            return jsonify({"error": str(e)}), 500


@app.route("/api/legacy/address")
def api_legacy_address():
    """Check fork assets for a specific address."""
    address = request.args.get("address", "").strip()
    chain = request.args.get("chain", "eth").strip().lower()
    if not address:
        return _api_error("Missing address", 400)
    try:
        import abandoned_coin_scanner as acs
        findings = acs.scan_address(chain, address)
        return jsonify({"address": address, "chain": chain, "findings": findings})
    except Exception as e:
        return _api_error(str(e), 500)


@app.route("/api/verify-keys")
def api_verify_keys():
    """Run key verification on scanner memory — returns valid/invalid counts."""
    try:
        import key_verifier as kv
        report = kv.validate_scanner_memory()
        return jsonify(report)
    except Exception as e:
        return _api_error(str(e), 500)


# ── Full key material lookup from scanner memory ──────────────────
MEMORY_FILE = HOME / "crypto_scanner_memory.jsonl"
HC_FILE = HOME / "high_confidence_hits.jsonl"
_memory_cache: dict = {"ts": 0.0, "records": []}
_keyed_cache: dict = {"ts": 0.0, "addrs": set()}


def _norm_addr(ad: str) -> str:
    ad = (ad or "").strip()
    if ad.startswith("0x") or ad.startswith("0X"):
        return "0x" + ad[2:].lower()
    return ad  # keep BTC/SOL/etc case-sensitive-ish but lower for set membership of hex-like


def _keyed_address_set() -> set:
    """Addresses that belong to a stored private key / WIF / seed.

    Sources (union, comprehensive):
      1. wallets_forever.addr_index
      2. wallets_forever raw_json addresses[] (backfill if index thin)
      3. balance_cache.derivations
      4. LIVE crypto_scanner derive from every hex_key/wif/seed in scanner memory (high-confidence)
      5. LIVE crypto_scanner derive from every hex_key/wif/seed in wallets_forever

    This is the single source of truth for "do I own this address?".
    If an address cannot be traced to a private key we possess, it is NOT keyed.
    """
    now = time.time()
    if now - _keyed_cache["ts"] < 45 and _keyed_cache["addrs"]:
        return _keyed_cache["addrs"]
    addrs: set = set()

    # --- Source 1+2: wallets_forever.db (persistent key vault) ---
    try:
        import sqlite3
        wf = HOME / "wallets_forever.db"
        if wf.exists():
            c = sqlite3.connect(str(wf), timeout=8)
            for (ad,) in c.execute("SELECT DISTINCT address FROM addr_index"):
                if ad:
                    addrs.add(_norm_addr(str(ad)))
                    addrs.add(str(ad).lower())
            if len(addrs) < 100:
                for (raw,) in c.execute("SELECT raw_json FROM wallets"):
                    try:
                        rec = json.loads(raw)
                    except Exception:
                        continue
                    for d in rec.get("addresses") or []:
                        if isinstance(d, dict) and d.get("address"):
                            a = str(d["address"])
                            addrs.add(_norm_addr(a))
                            addrs.add(a.lower())
            c.close()
    except Exception:
        pass

    # --- Source 3: balance_cache derivations ---
    try:
        import sqlite3
        bdb = HOME / "balance_cache.db"
        if bdb.exists():
            c = sqlite3.connect(str(bdb), timeout=5)
            try:
                for (ad,) in c.execute("SELECT DISTINCT address FROM derivations"):
                    if ad:
                        addrs.add(_norm_addr(str(ad)))
                        addrs.add(str(ad).lower())
            except Exception:
                pass
            c.close()
    except Exception:
        pass

    # --- Source 4: LIVE derive from scanner memory hex_keys/wifs/seeds ---
    try:
        import crypto_scanner as _cs_live
        hc = HOME / "high_confidence_hits.jsonl"
        mem = HOME / "crypto_scanner_memory.jsonl"
        hex_keys_set: set = set()
        wifs_set: set = set()
        seeds_set: set = set()
        for path in (hc, mem):
            if not path.exists():
                continue
            try:
                size = path.stat().st_size
                with open(path, "rb") as bf:
                    if size > 6_000_000:
                        bf.seek(max(0, size - 6_000_000))
                        bf.readline()
                    text = bf.read().decode("utf-8", errors="ignore")
                for line in reversed(text.splitlines()):
                    if not line or len(line) > 256_000:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    f = rec.get("findings") if isinstance(rec.get("findings"), dict) else None
                    if f is None:
                        continue
                    w = f.get("wallet") if isinstance(f.get("wallet"), dict) else {}
                    for hk in (w.get("hex_keys") or []):
                        hkx = (hk or "").strip().lower().replace("0x", "")
                        if len(hkx) == 64 and hkx not in hex_keys_set:
                            hex_keys_set.add(hkx)
                    for wk in (w.get("wifs") or []):
                        wks = (wk or "").strip()
                        if len(wks) >= 50 and wks not in wifs_set:
                            wifs_set.add(wks)
                    for sk in (w.get("seed_phrases") or []):
                        sks = (sk or "").strip()
                        if sks and sks not in seeds_set:
                            seeds_set.add(sks)
                    if len(hex_keys_set) + len(wifs_set) + len(seeds_set) >= 2000:
                        break
            except Exception:
                pass

        derived_count = 0
        max_derive = 800
        for hkx in list(hex_keys_set):
            if derived_count >= max_derive:
                break
            try:
                raw = bytes.fromhex(hkx)
                if any(raw[i] == 0 for i in range(min(8, len(raw)))) or raw == b"\x00" * 32:
                    continue
                from crypto_iq import is_junk_hex as _junk
                if _junk and _junk(hkx):
                    continue
            except Exception:
                pass
            try:
                raw = bytes.fromhex(hkx)
                derived = _cs_live.priv_to_addresses(raw) or {}
            except Exception:
                continue
            derived_count += 1
            for _ch, addr in derived.items():
                if addr:
                    addrs.add(_norm_addr(str(addr)))
                    addrs.add(str(addr).lower())

        for wk in list(wifs_set):
            if derived_count >= max_derive:
                break
            try:
                p = _cs_live.wif_to_priv_bytes(wk)
                if p:
                    derived = _cs_live.priv_to_addresses(p) or {}
                    derived_count += 1
                    for _ch, addr in derived.items():
                        if addr:
                            addrs.add(_norm_addr(str(addr)))
                            addrs.add(str(addr).lower())
            except Exception:
                pass

        for sk in list(seeds_set):
            if derived_count >= max_derive:
                break
            try:
                derived = _cs_live.seed_to_addresses(sk) or {}
                derived_count += 1
                for _ch, addr in derived.items():
                    if addr:
                        addrs.add(_norm_addr(str(addr)))
                        addrs.add(str(addr).lower())
            except Exception:
                pass
    except Exception:
        pass

    # --- Source 5: LIVE derive from wallets_forever hex/wif/seed keys ---
    try:
        import sqlite3, crypto_scanner as _cs2
        wf = HOME / "wallets_forever.db"
        if wf.exists() and len(addrs) < 500:
            c = sqlite3.connect(str(wf), timeout=8)
            rows = c.execute(
                "SELECT key_type, key_value FROM wallets WHERE key_type IN ('hex','wif','seed') LIMIT 300"
            ).fetchall()
            c.close()
            for kt, kv in rows:
                if not kv:
                    continue
                try:
                    if kt == "hex":
                        hkx = kv.strip().lower().replace("0x", "")
                        if len(hkx) != 64:
                            continue
                        raw = bytes.fromhex(hkx)
                        derived = _cs2.priv_to_addresses(raw) or {}
                    elif kt == "wif":
                        p = _cs2.wif_to_priv_bytes(kv.strip())
                        if p:
                            derived = _cs2.priv_to_addresses(p) or {}
                        else:
                            continue
                    elif kt == "seed":
                        derived = _cs2.seed_to_addresses(kv.strip()) or {}
                    else:
                        continue
                    for _ch, addr in derived.items():
                        if addr:
                            addrs.add(_norm_addr(str(addr)))
                            addrs.add(str(addr).lower())
                except Exception:
                    continue
    except Exception:
        pass

    _keyed_cache["ts"] = now
    _keyed_cache["addrs"] = addrs
    return addrs


def _addr_match_keys(address: str) -> list:
    """Return lowercase / normalized forms used for set membership."""
    a = (address or "").strip()
    out = [a, a.lower(), _norm_addr(a)]
    return list(dict.fromkeys(out))


def _is_keyed_address(address: str, keyed: set | None = None) -> bool:
    keyed = keyed if keyed is not None else _keyed_address_set()
    for k in _addr_match_keys(address):
        if k in keyed:
            return True
        if k.lower() in keyed:
            return True
    return False


def _keyed_balances(
    *,
    chain=None,
    min_balance=None,
    funded_only=True,
    limit=50,
    offset=0,
    sort_by="balance",
):
    """Return (rows, total) of balance records whose address has key material."""
    keyed = _keyed_address_set()
    if not keyed:
        return [], 0

    # Pull funded (or all) balances, filter in Python against keyed set.
    # Cap pull so we stay fast; keyed set is the authority.
    pull = 20000 if funded_only else 50000
    rows, _ = db.filter_balances(
        chain=chain,
        min_balance=min_balance,
        funded_only=funded_only,
        limit=pull,
        offset=0,
        sort_by=sort_by,
    )
    filtered = [r for r in rows if _is_keyed_address(r.get("address") or "", keyed)]
    total = len(filtered)
    page = filtered[offset:offset + limit]
    return page, total


def _keyed_balance_stats() -> dict:
    """Counts for keys-only dashboard header."""
    keyed = _keyed_address_set()
    rows, _ = db.filter_balances(funded_only=False, limit=100000, offset=0, sort_by="balance")
    keyed_rows = [r for r in rows if _is_keyed_address(r.get("address") or "", keyed)]
    funded = [r for r in keyed_rows if isinstance(r.get("balance"), (int, float)) and float(r["balance"]) > 1e-12]
    chain_totals: dict = {}
    for r in funded:
        ch = (r.get("chain") or "?").lower()
        try:
            chain_totals[ch] = chain_totals.get(ch, 0.0) + float(r.get("balance") or 0)
        except Exception:
            pass
    return {
        "keyed_addresses": len(keyed),
        "keyed_total": len(keyed_rows),
        "keyed_funded": len(funded),
        "keyed_chain_totals": chain_totals,
    }


def _load_memory(max_lines: int = 4000, max_line_bytes: int = 256_000) -> list:
    """Load recent scanner memory / HC records. NEVER slurps the full 300MB+ file."""
    now = time.time()
    if now - _memory_cache["ts"] < 45 and _memory_cache["records"]:
        return _memory_cache["records"]
    records = []
    for path in (HC_FILE, MEMORY_FILE):
        if not path.exists():
            continue
        try:
            size = path.stat().st_size
            with open(path, "rb") as bf:
                if size > 8_000_000:
                    bf.seek(max(0, size - 8_000_000))
                    bf.readline()
                text = bf.read().decode("utf-8", errors="ignore")
            n = 0
            for line in reversed(text.splitlines()):
                if n >= max_lines:
                    break
                if not line or len(line) > max_line_bytes:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                f = rec.get("findings") if isinstance(rec.get("findings"), dict) else None
                if f is None:
                    continue
                w = f.get("wallet") if isinstance(f.get("wallet"), dict) else {}
                if not (w.get("hex_keys") or w.get("wifs") or w.get("seed_phrases")
                        or f.get("hex_key") or f.get("wif") or f.get("seed_phrase")):
                    continue
                records.append(rec)
                n += 1
        except Exception:
            pass
        if len(records) >= max_lines:
            break
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

    # Fast path: wallets_forever.db (indexed)
    try:
        import sqlite3
        wf = HOME / "wallets_forever.db"
        if wf.exists():
            c = sqlite3.connect(str(wf), timeout=5)
            rows = c.execute(
                "SELECT w.raw_json FROM addr_index a JOIN wallets w ON w.id=a.wallet_id "
                "WHERE lower(a.address)=? LIMIT 5",
                (addr_lower,),
            ).fetchall()
            c.close()
            if rows:
                hex_keys, wifs, seeds, derived, sources = [], [], [], [], []
                for (raw,) in rows:
                    try:
                        rec = json.loads(raw)
                    except Exception:
                        continue
                    kt = rec.get("key_type")
                    kv = rec.get("key_value")
                    if kt == "hex" and kv:
                        hex_keys.append(kv)
                    elif kt == "wif" and kv:
                        wifs.append(kv)
                    elif kt == "seed" and kv:
                        seeds.append(kv)
                    for d in rec.get("addresses") or []:
                        if isinstance(d, dict):
                            derived.append(d)
                    for s in rec.get("sources") or []:
                        if s:
                            sources.append(s)
                if hex_keys or wifs or seeds:
                    return jsonify({
                        "found": True,
                        "address": addr,
                        "hex_keys": list(dict.fromkeys(hex_keys)),
                        "wifs": list(dict.fromkeys(wifs)),
                        "seeds": list(dict.fromkeys(seeds)),
                        "derived_addresses": derived,
                        "source": sources[0] if sources else "wallets_forever",
                        "timestamp": "",
                        "from_forever": True,
                    })
    except Exception:
        pass

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

    # If not found by direct lookup, try reverse-derivation: does any known
    # key produce this address?  (Many funded wallets are standalone addresses
    # found in source code without their key — but the key IS in memory.)
    if best is None:
        import crypto_scanner as _cs
        for rec in records:
            w = (rec.get("findings") or {}).get("wallet") or {}
            hex_keys = w.get("hex_keys") or rec.get("findings", {}).get("hex_key") or []
            wifs = w.get("wifs") or rec.get("findings", {}).get("wif") or []
            seeds = w.get("seed_phrases") or rec.get("findings", {}).get("seed_phrase") or []
            all_derived = {}
            try:
                for hk in hex_keys:
                    all_derived.update(_cs.priv_to_addresses(bytes.fromhex(hk)))
                for wif in wifs:
                    p = _cs.wif_to_priv_bytes(wif)
                    if p: all_derived.update(_cs.priv_to_addresses(p))
                for seed in seeds:
                    all_derived.update(_cs.seed_to_addresses(seed))
            except Exception:
                continue
            for ch, a in all_derived.items():
                if a.lower() == addr_lower:
                    best = {
                        "hex_keys": list(hex_keys),
                        "wifs": list(wifs),
                        "seeds": list(seeds),
                        "derived_addresses": [{"chain": ch, "address": a, "from": "reverse_derived"} for ch, a in all_derived.items()],
                        "source": rec.get("source") or rec.get("source_uri") or "reverse-derived from known key",
                        "timestamp": rec.get("ts") or rec.get("timestamp") or "",
                        "reverse_derived": True,
                    }
                    break
            if best is not None:
                break

    if best is None:
        return jsonify({"found": False, "address": addr,
                         "reason": "no_key"})

    return jsonify({"found": True, "address": addr, **best})


# ── Import key: paste a private key, derive addresses, check balances ──

@app.route("/api/import-key", methods=["POST"])
def api_import_key():
    """Accept a private key (HEX, WIF, or BIP39 seed), derive addresses
    on all chains, check balances, and write to scanner memory."""
    try:
        body = request.get_json(force=True, silent=True) or {}
    except Exception:
        body = {}
    key = (body.get("key") or "").strip()
    if not key:
        return jsonify({"ok": False, "error": "No key provided"}), 400

    import crypto_scanner as cs
    from datetime import datetime, timezone

    hex_keys = []
    wifs = []
    seeds = []
    addrs = {}

    # Auto-detect key type
    key_clean = key.strip()
    if key_clean.startswith("0x"):
        key_clean = key_clean[2:]
    # Try HEX
    if len(key_clean) == 64 and all(c in "0123456789abcdefABCDEF" for c in key_clean):
        try:
            priv_bytes = bytes.fromhex(key_clean)
            addrs = cs.priv_to_addresses(priv_bytes)
            hex_keys = [key_clean]
        except Exception as e:
            return jsonify({"ok": False, "error": f"Invalid hex key: {e}"}), 400
    # Try WIF
    elif len(key_clean) >= 50 and (key_clean[0] in "5KL"):
        try:
            priv_bytes = cs.wif_to_priv_bytes(key_clean)
            if priv_bytes:
                addrs = cs.priv_to_addresses(priv_bytes)
                wifs = [key_clean]
                # Also get hex
                hex_keys = [priv_bytes.hex()]
            else:
                return jsonify({"ok": False, "error": "Invalid WIF key"}), 400
        except Exception as e:
            return jsonify({"ok": False, "error": f"Invalid WIF: {e}"}), 400
    # Try seed phrase
    elif " " in key_clean and len(key_clean.split()) in (12, 24):
        try:
            addrs = cs.seed_to_addresses(key_clean)
            seeds = [key_clean]
        except Exception as e:
            return jsonify({"ok": False, "error": f"Invalid seed: {e}"}), 400
    else:
        return jsonify({"ok": False, "error": f"Unknown key format. Provide 64-char hex, WIF (starts with 5/K/L), or 12/24-word BIP39 seed."}), 400

    if not addrs:
        return jsonify({"ok": False, "error": "Could not derive any addresses from this key"}), 400

    # Check balances for all derived addresses
    balances = {}
    for chain, addr in addrs.items():
        try:
            rec = db.get_balance(chain, addr)
            bal = rec.get("balance") if rec else None
            balances[chain] = {"address": addr, "balance": bal, "live": bool(rec.get("live")) if rec else False}
        except Exception:
            balances[chain] = {"address": addr, "balance": None, "live": False}

    # Write to scanner memory
    now_ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    rec = {
        "findings": {
            "wallet": {"hex_keys": hex_keys, "wifs": wifs, "seed_phrases": seeds},
            "derived_addresses": [{"chain": c, "address": a, "from": "manual_import"} for c, a in addrs.items()],
            "confidence": "high",
        },
        "source": "manual_import",
        "timestamp": now_ts,
        "source_uri": "imported via walletx dashboard",
    }
    try:
        with open(MEMORY_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
    except Exception as e:
        return jsonify({"ok": False, "error": f"Failed to write memory: {e}"}), 500

    # Permanent key vault (deduped upsert)
    try:
        import wallets_forever as _wf
        _wf.upsert_from_record(rec)
    except Exception:
        pass

    # Count funded chains
    funded = {c: b for c, b in balances.items() if b["balance"] and b["balance"] > 1e-12}
    total_funded = sum(b["balance"] for b in funded.values())

    return jsonify({
        "ok": True,
        "key_type": "hex" if hex_keys else ("wif" if wifs else "seed"),
        "hex_keys": hex_keys,
        "wifs": wifs,
        "seeds": seeds,
        "addresses": addrs,
        "balances": balances,
        "funded_chains": list(funded.keys()),
        "total_funded_value": total_funded,
        "n_funded": len(funded),
        "written_to_memory": True,
    })


# ── Send transaction: sign with private key + broadcast via RPC ──

def _keccak256(data: bytes) -> bytes:
    from Crypto.Hash import keccak
    return keccak.new(digest_bits=256).update(data).digest()

def _sign_eth_tx(priv_hex: str, to_addr: str, value_wei: int, nonce: int,
                 gas_price: int, gas_limit: int, chain_id: int) -> str:
    """Sign ETH tx — proven against live RPC (mevblocker.io validated)."""
    pk = bytes.fromhex(priv_hex.replace("0x", ""))
    sk = ecdsa.SigningKey.from_string(pk, curve=ecdsa.SECP256k1)
    to_b = bytes.fromhex(to_addr[2:]) if to_addr.startswith("0x") else bytes.fromhex(to_addr)
    utx = [nonce, gas_price, gas_limit, to_b, value_wei, b"", chain_id, 0, 0]
    h = _keccak256(_rlp(utx))
    sig = sk.sign_digest(h, sigencode=ecdsa.util.sigencode_der)
    r, s = ecdsa.util.sigdecode_der(sig, ecdsa.SECP256k1.generator.order())
    v = chain_id * 2 + 35
    n = ecdsa.SECP256k1.generator.order()
    if s > n // 2: s = n - s; v ^= 1
    stx = [nonce, gas_price, gas_limit, to_b, value_wei, b"",
           v, r.to_bytes(32, "big"), s.to_bytes(32, "big")]
    return "0x" + _rlp(stx).hex()


@app.route("/api/send", methods=["POST"])
def api_send():
    """Sign a transaction with a private key and broadcast it via RPC.

    Always returns JSON (never HTML), even on unexpected exceptions.
    """
    try:
        try:
            body = request.get_json(force=True, silent=True) or {}
        except Exception:
            body = {}
        if not isinstance(body, dict):
            body = {}

        priv_key = (body.get("private_key") or body.get("key") or "").strip()
        to_addr = (body.get("to") or "").strip()
        value_eth = body.get("value_eth", body.get("amount"))
        chain = (body.get("chain") or "eth").strip().lower()
        if chain in ("polygon", "poly"):
            chain = "matic"

        if not priv_key or not to_addr or value_eth is None:
            return _api_error("Missing private_key, to, or value_eth", 400)

        try:
            value_wei = int(float(value_eth) * 1e18)
        except (ValueError, TypeError):
            return _api_error("Invalid value_eth", 400)
        if value_wei <= 0:
            return _api_error("value_eth must be > 0", 400)

        if not to_addr.startswith("0x") or len(to_addr) != 42:
            return _api_error("to must be a 0x-prefixed 40-hex EVM address", 400)

        pk = priv_key.strip().replace("0x", "").replace(" ", "")
        if len(pk) != 64 or not all(c in "0123456789abcdefABCDEF" for c in pk):
            return _api_error("Private key must be 64 hex characters", 400)

        import ecdsa

        _RPC_SETS = {
            "eth":   ["https://rpc.mevblocker.io", "https://cloudflare-eth.com", "https://eth.drpc.org", "https://ethereum.publicnode.com"],
            "matic": ["https://polygon.drpc.org", "https://polygon.publicnode.com", "https://1rpc.io/matic"],
            "bnb":   ["https://bsc.drpc.org", "https://bsc.publicnode.com", "https://1rpc.io/bnb"],
            "avax":  ["https://avalanche.drpc.org", "https://avalanche.publicnode.com", "https://api.avax.network/ext/bc/C/rpc"],
            "base":  ["https://base.drpc.org", "https://base.publicnode.com", "https://mainnet.base.org"],
            "arb":   ["https://arbitrum.drpc.org", "https://arbitrum.publicnode.com", "https://arb1.arbitrum.io/rpc"],
            "op":    ["https://optimism.drpc.org", "https://optimism.publicnode.com", "https://mainnet.optimism.io"],
        }
        if chain not in _RPC_SETS:
            return _api_error(
                f"Unsupported chain '{chain}'. Use: " + ", ".join(sorted(_RPC_SETS)),
                400,
            )
        rpc_list = _RPC_SETS[chain]

        sk = ecdsa.SigningKey.from_string(bytes.fromhex(pk), curve=ecdsa.SECP256k1)
        from_addr = "0x" + _keccak256((bytes([4]) + sk.get_verifying_key().to_string())[1:])[-20:].hex()

        # LIVE balance via scanner RPCs
        try:
            import crypto_scanner as _cs
            live_rec = _cs.get_balance(chain, from_addr, force=True) or {}
        except Exception as exc:
            return _api_error(f"Balance check failed: {exc}", 500)

        bal_f = live_rec.get("balance")
        if bal_f is None:
            return _api_error(
                f"Could not check live balance on {chain.upper()} — scanner RPCs all failed",
                500,
            )
        live_bal_wei = int(float(bal_f) * 1e18)
        live_bal_eth = live_bal_wei / 1e18
        gas_estimate_wei = 21000 * 50_000_000_000
        if live_bal_wei < value_wei + gas_estimate_wei:
            return _api_error(
                f"Insufficient funds: live balance is {live_bal_eth:.6f} {chain.upper()}, "
                f"need {float(value_eth):.6f} {chain.upper()} + ~0.00105 {chain.upper()} gas. "
                f"Cache may be stale.",
                400,
                live_balance=live_bal_eth,
                from_addr=from_addr,
            )

        nonce = None
        for rpc_url in rpc_list:
            try:
                nr = requests.post(
                    rpc_url,
                    json={"jsonrpc": "2.0", "id": 1, "method": "eth_getTransactionCount",
                          "params": [from_addr, "latest"]},
                    timeout=10,
                    headers={"Content-Type": "application/json"},
                )
                nonce = int(nr.json()["result"], 16)
                break
            except Exception:
                continue
        if nonce is None:
            return _api_error(f"All {len(rpc_list)} RPCs failed for nonce on {chain}", 500)

        gas_price = None
        for rpc_url in rpc_list:
            try:
                gr = requests.post(
                    rpc_url,
                    json={"jsonrpc": "2.0", "id": 1, "method": "eth_gasPrice", "params": []},
                    timeout=10,
                    headers={"Content-Type": "application/json"},
                )
                gas_price = int(gr.json()["result"], 16)
                break
            except Exception:
                continue
        if gas_price is None:
            gas_price = 50_000_000_000

        chain_ids = {"eth": 1, "matic": 137, "bnb": 56, "avax": 43114,
                     "base": 8453, "arb": 42161, "op": 10}
        cid = chain_ids.get(chain, 1)

        try:
            signed_hex = _sign_eth_tx(pk, to_addr, value_wei, nonce, gas_price, 21000, cid)
        except Exception as e:
            return _api_error(f"Signing failed: {e}", 500)

        last_err = ""
        tx_hash = None
        for rpc_url in rpc_list:
            try:
                br = requests.post(
                    rpc_url,
                    json={"jsonrpc": "2.0", "id": 1, "method": "eth_sendRawTransaction",
                          "params": [signed_hex]},
                    timeout=20,
                    headers={"Content-Type": "application/json"},
                )
                result = br.json()
                if "error" in result:
                    last_err = f"{rpc_url}: {result['error'].get('message', result['error'])}"
                    err_s = str(result["error"]).lower()
                    if "insufficient" in err_s or "balance" in err_s:
                        return _api_error(
                            f"Insufficient funds: {result['error'].get('message', result['error'])}",
                            400,
                        )
                    continue
                tx_hash = result.get("result")
                if tx_hash:
                    break
                last_err = f"{rpc_url}: empty result"
            except Exception as e:
                last_err = f"{rpc_url}: {e}"
                continue

        if not tx_hash:
            return _api_error(f"All RPCs failed to broadcast. Last: {last_err}", 500)

        explorers = {
            "eth": f"https://etherscan.io/tx/{tx_hash}",
            "matic": f"https://polygonscan.com/tx/{tx_hash}",
            "bnb": f"https://bscscan.com/tx/{tx_hash}",
            "avax": f"https://snowtrace.io/tx/{tx_hash}",
            "base": f"https://basescan.org/tx/{tx_hash}",
            "arb": f"https://arbiscan.io/tx/{tx_hash}",
            "op": f"https://optimistic.etherscan.io/tx/{tx_hash}",
        }
        return jsonify({
            "ok": True,
            "tx_hash": tx_hash,
            "from": from_addr,
            "to": to_addr,
            "value_wei": value_wei,
            "value_eth": float(value_eth),
            "chain": chain,
            "nonce": nonce,
            "gas_price": gas_price,
            "explorer": explorers.get(chain, f"https://etherscan.io/tx/{tx_hash}"),
        })
    except Exception as exc:
        # Last-resort JSON — never let Flask render HTML to the dashboard
        return _api_error(f"{type(exc).__name__}: {exc}", 500)


# ── Multichain endpoints (send/swap/bridge/receive) ──────────────────

@app.route("/api/send-multi", methods=["POST"])
def api_send_multi():
    """Send on any chain via multichain engine."""
    try:
        body = request.get_json(force=True, silent=True) or {}
    except Exception:
        body = {}
    priv_key = (body.get("private_key") or body.get("key") or "").strip()
    to_addr = (body.get("to") or "").strip()
    amount = body.get("amount", body.get("value_eth"))
    chain = (body.get("chain") or "eth").strip().lower()
    if not priv_key or not to_addr or amount is None:
        return _api_error("Missing private_key, to, or amount", 400)
    try:
        result = mc.send(chain, priv_key, to_addr, float(amount))
    except Exception as e:
        return _api_error(str(e), 500)
    return jsonify(result)


@app.route("/api/swap/quote")
def api_swap_quote():
    """Get swap quote from 0x (EVM) or Jupiter (Solana)."""
    chain = request.args.get("chain", "eth").strip().lower()
    from_token = request.args.get("from_token", "ETH").strip()
    to_token = request.args.get("to_token", "USDC").strip()
    amount = request.args.get("amount", type=float)
    from_addr = request.args.get("from_addr", "").strip()
    slippage = request.args.get("slippage", 0.01, type=float)
    if not amount or not from_addr:
        return _api_error("Missing amount or from_addr", 400)
    try:
        result = mc.get_swap_quote(chain, from_token, to_token, amount, from_addr, slippage)
    except Exception as e:
        return _api_error(str(e), 500)
    return jsonify(result)


@app.route("/api/swap/execute", methods=["POST"])
def api_swap_execute():
    """Execute a swap using a quote from /api/swap/quote."""
    try:
        body = request.get_json(force=True, silent=True) or {}
    except Exception:
        body = {}
    chain = (body.get("chain") or "eth").strip().lower()
    priv_key = (body.get("private_key") or "").strip()
    quote = body.get("quote", {})
    if not priv_key or not quote:
        return _api_error("Missing private_key or quote", 400)
    try:
        result = mc.execute_swap(chain, priv_key, quote)
    except Exception as e:
        return _api_error(str(e), 500)
    return jsonify(result)


@app.route("/api/bridge/quote")
def api_bridge_quote():
    """Get cross-chain bridge quote from LI.FI."""
    from_chain = request.args.get("from_chain", "eth").strip().lower()
    to_chain = request.args.get("to_chain", "base").strip().lower()
    from_token = request.args.get("from_token", "ETH").strip()
    to_token = request.args.get("to_token", "ETH").strip()
    amount = request.args.get("amount", type=float)
    from_addr = request.args.get("from_addr", "").strip()
    if not amount or not from_addr:
        return _api_error("Missing amount or from_addr", 400)
    try:
        result = mc.get_bridge_quote(from_chain, to_chain, from_token, to_token, amount, from_addr)
    except Exception as e:
        return _api_error(str(e), 500)
    return jsonify(result)


@app.route("/api/receive", methods=["POST"])
def api_receive():
    """Derive all chain addresses from a private key."""
    try:
        body = request.get_json(force=True, silent=True) or {}
    except Exception:
        body = {}
    priv_key = (body.get("private_key") or body.get("key") or "").strip()
    if not priv_key:
        return _api_error("Missing private_key", 400)
    try:
        result = mc.get_all_addresses(priv_key)
    except Exception as e:
        return _api_error(str(e), 500)
    return jsonify(result)


@app.route("/api/balance-live")
def api_balance_live():
    """Get live balance for an address on any chain via multichain."""
    chain = request.args.get("chain", "eth").strip().lower()
    address = request.args.get("address", "").strip()
    if not address:
        return _api_error("Missing address", 400)
    try:
        result = mc.get_balance(chain, address)
    except Exception as e:
        return _api_error(str(e), 500)
    return jsonify(result)


# ── Vault API ───────────────────────────────────────────────────────
VAULT_DB = HOME / "wallets_forever.db"


def _vault_conn():
    import sqlite3
    c = sqlite3.connect(str(VAULT_DB), timeout=10)
    c.execute("""CREATE TABLE IF NOT EXISTS wallets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_type TEXT NOT NULL,
        key_value TEXT NOT NULL,
        address TEXT,
        chain TEXT,
        balance REAL DEFAULT 0,
        balance_checked_at TEXT,
        proof_verified INTEGER DEFAULT 0,
        imported_at TEXT NOT NULL
    )""")
    c.execute("""CREATE UNIQUE INDEX IF NOT EXISTS idx_wallets_key
        ON wallets(key_type, key_value)""")
    c.commit()
    return c


@app.route("/api/vault/import", methods=["POST"])
def api_vault_import():
    """Bulk import keys — auto-detect BIP39/hex/WIF/PEM, derive addresses, check balances."""
    try:
        body = request.get_json(force=True, silent=True) or {}
    except Exception:
        body = {}
    raw = (body.get("raw") or "").strip()
    if not raw:
        return _api_error("No key data provided", 400)

    import re, threading, queue
    from datetime import datetime, timezone

    # ── Extract key candidates ──────────────────────────────────
    # Split by whitespace, newlines, commas, semicolons
    tokens = re.split(r'[\s,;]+', raw)
    # Also look for PEM blocks
    pem_blocks = re.findall(r'-----BEGIN[^-]*PRIVATE KEY-----.*?-----END[^-]*PRIVATE KEY-----', raw, re.DOTALL)
    tokens = [t for t in tokens if t] + pem_blocks

    candidates: list[dict] = []
    seen = set()

    # BIP39 wordlist for detection
    bip39_words = None
    try:
        from mnemonic import Mnemonic
        bip39_words = frozenset(Mnemonic("english").wordlist)
    except Exception:
        bip39_words = frozenset()

    for tok in tokens:
        tok = tok.strip().strip('"').strip("'")
        if not tok or tok in seen:
            continue
        seen.add(tok)

        kt = None
        # PEM
        if tok.startswith("-----BEGIN") and "PRIVATE KEY" in tok:
            kt = "pem"
        # WIF (base58, ~51-52 chars, starts with 5/K/L)
        elif re.match(r'^[5KL][1-9A-HJ-NP-Za-km-z]{50,51}$', tok):
            kt = "wif"
        # Hex private key (64 chars)
        elif re.match(r'^(0x)?[a-fA-F0-9]{64}$', tok.replace("0x", "")):
            kt = "hex"
        # BIP39 seed phrase (12/15/18/21/24 words)
        elif bip39_words:
            words = tok.lower().split()
            if len(words) in (12, 15, 18, 21, 24) and all(w in bip39_words for w in words):
                kt = "seed"
        # Raw bytes hex (any length divisible by 2)? Skip.
        else:
            continue

        candidates.append({"type": kt, "value": tok})

    if not candidates:
        return jsonify({"ok": True, "found": 0, "imported": 0, "funded": 0, "empty": 0,
                        "errors": 0, "samples": [], "message": "No valid keys found in input"})

    # ── Derive addresses and check balances ─────────────────────
    import crypto_scanner as cs
    now_utc = datetime.now(timezone.utc).isoformat()
    results: list[dict] = []
    imported = 0
    funded = 0
    empty = 0
    errs = 0

    conn = _vault_conn()

    for cand in candidates:
        try:
            kt = cand["type"]
            kv = cand["value"]
            addresses: dict[str, str] = {}

            if kt == "hex":
                hk = kv.lower().replace("0x", "")
                if len(hk) != 64:
                    continue
                raw_bytes = bytes.fromhex(hk)
                addresses = cs.priv_to_addresses(raw_bytes) or {}
            elif kt == "wif":
                pk = cs.wif_to_priv_bytes(kv)
                if pk:
                    addresses = cs.priv_to_addresses(pk) or {}
            elif kt == "seed":
                addresses = cs.seed_to_addresses(kv) or {}
            elif kt == "pem":
                # Extract raw key bytes from PEM
                import base64
                b64 = kv.replace("-----BEGIN", "").replace("PRIVATE KEY-----", "")
                b64 = b64.replace("-----END", "").replace("-----", "")
                b64 = re.sub(r'\s+', '', b64)
                try:
                    raw_bytes = base64.b64decode(b64)
                    # Try to extract the 32-byte key (usually last 32 bytes for secp256k1)
                    if len(raw_bytes) >= 32:
                        raw_bytes = raw_bytes[-32:]
                    addresses = cs.priv_to_addresses(raw_bytes) or {}
                except Exception:
                    errs += 1
                    continue

            if not addresses:
                errs += 1
                continue

            # Check balance for each derived address
            for chain_name, addr in addresses.items():
                if not addr:
                    continue
                bal = 0.0
                try:
                    rec = cs.get_balance(chain_name, addr, force=False)
                    bal = float(rec.get("balance", 0) or 0)
                except Exception:
                    pass

                proof_ok = 1  # We derived the address from the key = proof

                # Upsert into vault
                try:
                    conn.execute(
                        """INSERT OR REPLACE INTO wallets
                        (key_type, key_value, address, chain, balance, balance_checked_at, proof_verified, imported_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                        (kt, kv, addr, chain_name, round(bal, 12), now_utc, proof_ok, now_utc),
                    )
                    conn.commit()
                except Exception:
                    pass

                imported += 1
                if bal > 1e-12:
                    funded += 1
                else:
                    empty += 1

                results.append({
                    "type": kt,
                    "preview": kv[:20] + ("…" if len(kv) > 20 else ""),
                    "address": addr,
                    "chain": chain_name,
                    "balance": round(bal, 8),
                    "funded": bal > 1e-12,
                })

        except Exception:
            errs += 1
            continue

    conn.close()

    return jsonify({
        "ok": True,
        "found": len(candidates),
        "imported": imported,
        "funded": funded,
        "empty": empty,
        "errors": errs,
        "samples": results[:20],
    })


@app.route("/api/vault/list")
def api_vault_list():
    """List all keys in the forever vault."""
    try:
        conn = _vault_conn()
        rows = conn.execute(
            "SELECT id, key_type, key_value, address, chain, balance, proof_verified, imported_at "
            "FROM wallets ORDER BY balance DESC, imported_at DESC LIMIT 500"
        ).fetchall()
        conn.close()
        out = []
        for r in rows:
            out.append({
                "id": r[0], "key_type": r[1], "key_value": r[2],
                "address": r[3], "chain": r[4], "balance": r[5],
                "proof_verified": bool(r[6]), "imported_at": r[7],
            })
        return jsonify({"rows": out, "total": len(out)})
    except Exception as e:
        return _api_error(str(e), 500)


@app.route("/api/vault/stats")
def api_vault_stats():
    """Vault summary stats."""
    try:
        conn = _vault_conn()
        total = conn.execute("SELECT COUNT(*) FROM wallets").fetchone()[0]
        funded = conn.execute("SELECT COUNT(*) FROM wallets WHERE balance > 1e-12").fetchone()[0]
        verified = conn.execute("SELECT COUNT(*) FROM wallets WHERE proof_verified = 1").fetchone()[0]
        conn.close()
        return jsonify({"total": total, "funded": funded, "verified": verified})
    except Exception as e:
        return _api_error(str(e), 500)


@app.route("/api/vault/delete", methods=["POST"])
def api_vault_delete():
    """Delete a single key from the vault."""
    try:
        body = request.get_json(force=True, silent=True) or {}
    except Exception:
        body = {}
    kid = body.get("id")
    if not kid:
        return _api_error("Missing id", 400)
    try:
        conn = _vault_conn()
        conn.execute("DELETE FROM wallets WHERE id = ?", (int(kid),))
        conn.commit()
        conn.close()
        return jsonify({"ok": True})
    except Exception as e:
        return _api_error(str(e), 500)


@app.route("/api/vault/clear", methods=["POST"])
def api_vault_clear():
    """Delete ALL keys from the vault."""
    try:
        conn = _vault_conn()
        conn.execute("DELETE FROM wallets")
        conn.commit()
        conn.close()
        return jsonify({"ok": True})
    except Exception as e:
        return _api_error(str(e), 500)


# ── Main ─────────────────────────────────────────────────────────────

def import_existing_cache():
    """Import balances once; always backfill hits from balances_hit.jsonl."""
    jsonl = HOME / "balance_cache.jsonl"
    if jsonl.exists():
        count = db.count_balances()
        if count == 0:
            n = db.import_from_jsonl(str(jsonl))
            print(f"[walletx-server] imported {n} records from balance_cache.jsonl")
        else:
            print(f"[walletx-server] SQLite already has {count} records — skipping balance import")
    else:
        print("[walletx-server] no balance_cache.jsonl found — starting fresh")

    hits_path = HOME / "balances_hit.jsonl"
    if hits_path.exists():
        try:
            before = db.get_stats().get("hits", 0)
            n_new = 0
            with open(hits_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    chain = rec.get("chain")
                    addr = rec.get("address")
                    bal = rec.get("balance")
                    if not chain or not addr or bal is None:
                        continue
                    try:
                        bal_f = float(bal)
                    except Exception:
                        continue
                    if bal_f <= 1e-12:
                        continue
                    if db.record_hit(str(chain), str(addr), bal_f, source="balances_hit.jsonl"):
                        n_new += 1
            after = db.get_stats().get("hits", 0)
            print(f"[walletx-server] hits sync: +{n_new} new (table now {after}, was {before})")
        except Exception as exc:
            print(f"[walletx-server] hits sync failed: {exc}")


def main():
    import threading
    # Import balances quickly (skip if already populated). Hits sync is heavy — do it AFTER bind.
    try:
        jsonl = HOME / "balance_cache.jsonl"
        if jsonl.exists() and db.count_balances() == 0:
            n = db.import_from_jsonl(str(jsonl))
            print(f"[walletx-server] imported {n} records from balance_cache.jsonl")
        else:
            print(f"[walletx-server] SQLite balances ready ({db.count_balances()})")
    except Exception as exc:
        print(f"[walletx-server] balance import skipped: {exc}")

    stats = db.get_stats()
    port = int(os.environ.get("WALLETX_PORT", "8080"))
    host = os.environ.get("WALLETX_HOST", "0.0.0.0")
    print(f"[walletx-server] starting on http://{host}:{port} (waitress)")
    print(f"  balances: {stats['total']}  funded: {stats['nonzero']}  hits: {stats['hits']}")

    def _bg_hits():
        import time
        time.sleep(1.5)
        try:
            import_existing_cache()  # mainly hits sync; balances already present
        except Exception as exc:
            print(f"[walletx-server] bg import failed: {exc}")

    threading.Thread(target=_bg_hits, daemon=True).start()

    from waitress import serve
    # ipv4 only avoids odd dual-stack EADDRINUSE on some Android/Termux builds
    serve(
        app,
        host=host,
        port=port,
        threads=8,
        channel_timeout=60,
        clear_untrusted_proxy_headers=True,
        ident="walletx",
    )


if __name__ == "__main__":
    main()
