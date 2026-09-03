#!/usr/bin/env python3
"""Local Xverse/PSBT web application for pos_recover (standard library only)."""
import argparse, json, secrets, sys, threading, time, webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
import pos_recover as core

TOKEN, NONCE = secrets.token_urlsafe(32), secrets.token_urlsafe(20)
MAX_BODY, TTL = 2*1024*1024, 30*60
STATE_LOCK = threading.RLock()
STATE = {"network":"mainnet","network_locked":False,"ctx":None,"wallet":None,"plan":None,"psbt":None,"verified":None,"touched":time.monotonic()}
LOGO_PATH = Path(__file__).resolve().parent / "img" / "raresatscards-logo.png"

PAGE=r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Pos Recovery — Xverse</title>
<style nonce="__NONCE__">:root{color-scheme:dark;--b:#11100d;--p:#211e18;--f:#eee7d9;--m:#aaa08e;--g:#d0aa32;--r:#e0523b}*{box-sizing:border-box}body{margin:0;background:var(--b);color:var(--f);font:15px/1.55 system-ui}.w{max-width:820px;margin:auto;padding:32px 20px 80px}.logo{display:block;width:min(100%,340px);height:auto;margin:0 auto 24px}.toplink{text-align:center;margin:-10px 0 24px}.toplink a{color:var(--g);text-underline-offset:3px}h1{font:34px Georgia}section{border-top:1px solid #3d372f;padding:24px 0}.hint{color:var(--m)}label{display:block;margin:13px 0 5px;color:var(--m);font-size:12px;text-transform:uppercase}.check,.network-option{display:flex;align-items:center;gap:9px;text-transform:none;letter-spacing:0;cursor:pointer}.check{display:inline-flex}.check input,.network-option input{width:auto;margin:0;flex:0 0 auto;accent-color:var(--g)}.network-option{padding:9px 0;color:var(--f);font-size:14px}.advanced{margin-top:8px;color:var(--m)}.advanced summary{cursor:pointer}.badge{display:inline-block;border:1px solid var(--gold,var(--g));padding:6px 10px;color:var(--g);font:700 12px monospace;letter-spacing:.08em}.badge.test{border-color:var(--m);color:var(--m)}input,select,textarea{width:100%;padding:11px;background:var(--p);color:var(--f);border:1px solid #4c4438;font:13px monospace}button{margin:15px 8px 0 0;padding:10px 16px;border:1px solid var(--g);background:var(--g);font-weight:700}button.alt{background:transparent;color:var(--f)}button:disabled{opacity:.4}.msg{white-space:pre-wrap;color:var(--r);margin-top:12px}.ok{color:var(--g)}.warn{border:2px solid var(--r);padding:12px;color:#ff9c8d;font-weight:700}.box{font:13px monospace;white-space:pre-wrap;background:var(--p);padding:14px;overflow:auto}.hide{display:none}</style></head><body><main class="w"><img class="logo" src="/img/raresatscards-logo.png?t=__TOKEN__" alt="Rare Sats Cards"><p class="toplink"><a href="/guide?t=__TOKEN__">Read the user guide before you begin</a></p><p class="hint">Local · no telemetry · no automatic broadcast</p><h1>Move the Rare Sat from your Proof of Sats card</h1><div id="mw" class="warn">MAINNET — real and irreversible operation. Check every address before continuing.</div>
<section><h2>1. Bitcoin network</h2><p class="hint">Choose Mainnet to recover your card for real, or Signet only for technical testing.</p><div id="network-choice"><label class="network-option"><input type="radio" name="network" value="mainnet" checked> Mainnet — real recovery</label><details class="advanced"><summary>Advanced options</summary><label class="network-option"><input type="radio" name="network" value="signet"> Signet — developers and testing only</label><div id="sw" class="warn hide">TEST MODE — use only valueless Signet keys and sats. A Mainnet card will not work here.</div></details><button id="lock">Confirm network and continue</button></div><div id="network-badge" class="badge hide"></div><div id="nm" class="msg"></div></section>
<section><h2>2. Card</h2><p class="hint">Enter the Bitcoin output associated with your card and the private key revealed under its seal.</p><label>Outpoint TXID:VOUT</label><input id="card"><label>WIF (local memory only, erased after signing)</label><input id="wif" type="password" autocomplete="new-password"><button id="cardb" disabled>Verify</button><div id="cm" class="msg"></div></section>
<section><h2>3. Xverse</h2><p class="hint">Connect your wallet, then carefully check the Ordinals address that will receive your card’s Rare Sat.</p><button id="conn" disabled>Connect Xverse</button><div id="wa" class="box hide"></div><label class="check"><input id="aok" type="checkbox"> I have visually verified the Ordinals address</label><div id="wm" class="msg"></div></section>
<section><h2>4. Funding</h2><p class="hint">Enter a confirmed Xverse payment UTXO and verify that it contains no inscription, rune, or rare sat that must be preserved.</p><label>Xverse outpoint</label><input id="fund"><button id="fundb" disabled>Verify</button><label class="check"><input id="uok" type="checkbox"> I have checked and accept this UTXO</label><div id="fm" class="msg"></div></section>
<section><h2>5. Plan + card signature</h2><p class="hint">Choose the fee rate, then review the plan before locally signing the card input.</p><label>Fee rate (sat/vB)</label><input id="rate" value="5"><button id="build" disabled>Sign input 0 only</button><div id="sum" class="box hide"></div><div id="pm" class="msg"></div></section>
<section><h2>6. Xverse signature</h2><p class="hint">Allow Xverse to sign the funding input only; nothing is broadcast at this stage.</p><button id="sign" disabled>Sign input 1 only with Xverse</button><div id="vm" class="msg"></div></section>
<section><h2>7. Separate broadcast</h2><p class="hint">Review or download the verified transaction, then separately confirm its broadcast to the Bitcoin network.</p><textarea id="raw" rows="6" readonly></textarea><button id="dl" class="alt" disabled>Download</button><label>Type DIFFUSER</label><input id="word"><button id="send" disabled>Broadcast verified bytes</button><div id="bm" class="msg"></div></section></main>
<script nonce="__NONCE__">'use strict';const T='__TOKEN__',$=x=>document.getElementById(x);let net=null,wallet=null,provider=null,psbt=null;function m(id,s,ok){$(id).textContent=s||'';$(id).className=ok?'msg ok':'msg'}async function api(p,b){let r=await fetch(p,{method:'POST',cache:'no-store',headers:{'Content-Type':'application/json','X-Session-Token':T},body:JSON.stringify(b||{})}),d=await r.json();if(!r.ok)throw Error(d.error||'Error');return d}function xp(){let direct=window.XverseProviders?.BitcoinProvider||window.xverseProviders?.BitcoinProvider||window.BitcoinProvider;if(direct?.request)return direct;let advertised=Array.from(window.btc_providers||[]).find(x=>/xverse/i.test(String(x?.name||x?.id||'')));return advertised?.provider?.request?advertised.provider:(advertised?.request?advertised:null)}async function wr(method,params){if(!provider?.request)throw Error('Xverse extension missing or Bitcoin provider not injected');try{let r=await provider.request(method,params);if(r?.status==='error')throw Error(`${r.error?.message||'Xverse request rejected'} [${r.error?.code??'no code'}]`);return r?.status==='success'?r.result:r}catch(e){throw Error(`${method}: ${e?.message||String(e)}`)}}function list(r){return Array.isArray(r)?r:(r?.addresses||r?.result?.addresses||[])}function signedPsbt(r){let found=[];function walk(v,depth){if(depth>3||v==null)return;if(typeof v==='string'){if(/^cHNidP8/.test(v))found.push(v);return}if(typeof v!=='object'||Array.isArray(v))return;for(let k of ['psbt','psbtBase64','signedPsbt','result'])if(Object.prototype.hasOwnProperty.call(v,k))walk(v[k],depth+1)}walk(r,0);found=[...new Set(found)];if(found.length!==1){let keys=r&&typeof r==='object'?Object.keys(r).join(', ')||'none':'response type '+typeof r;throw Error(found.length?'Ambiguous Xverse response':'Signed PSBT missing (received fields: '+keys+')')}return found[0]}
document.querySelectorAll('input[name="network"]').forEach(x=>x.onchange=()=>{let signet=document.querySelector('input[name="network"]:checked').value==='signet';$('mw').classList.toggle('hide',signet);$('sw').classList.toggle('hide',!signet)});
$('lock').onclick=async()=>{try{net=document.querySelector('input[name="network"]:checked').value;await api('/api/network',{network:net});document.querySelectorAll('input[name="network"]').forEach(x=>x.disabled=true);$('network-choice').classList.add('hide');let badge=$('network-badge');badge.textContent=net==='mainnet'?'NETWORK: MAINNET':'NETWORK: SIGNET — TEST';badge.classList.toggle('test',net==='signet');badge.classList.remove('hide');$('cardb').disabled=$('conn').disabled=false;m('nm','Network confirmed and locked.',true)}catch(e){m('nm',e.message)}};
$('cardb').onclick=async()=>{try{let d=await api('/api/card',{network:net,outpoint:$('card').value});m('cm',`${d.value} sats · confirmed · ${d.kind} · ordinal ranges ${d.ranges?'available':'unavailable'}`,true)}catch(e){m('cm',e.message)}};
$('conn').onclick=async()=>{try{provider=xp();if(!provider)throw Error('Xverse was not detected. Enable the extension for this site, then reload the page.');let requestedNetwork=net==='signet'?'Signet':'Mainnet';try{await wr('wallet_connect',{addresses:['ordinals','payment'],message:'Pos Recovery is requesting your Bitcoin addresses.',network:requestedNetwork})}catch(e){if(!/method not found|not support|unsupported|32601/i.test(e.message))throw e}let a=list(await wr('getAddresses',{purposes:['ordinals','payment'],message:'Pos Recovery is requesting your addresses.'})),o=a.find(x=>String(x.purpose).toLowerCase()==='ordinals'),p=a.find(x=>String(x.purpose).toLowerCase()==='payment');if(!o||!p)throw Error('Xverse did not return both the Ordinals and payment addresses. Check that its active network is '+requestedNetwork+'.');wallet={ordinals:o,payment:p};await api('/api/wallet',{network:net,...wallet});$('wa').textContent=`Ordinals — output 0, full card value\n${o.address}\n\nPayment / change\n${p.address}`;$('wa').classList.remove('hide');$('fundb').disabled=false;m('wm','Connected to '+requestedNetwork+'. Verify the Ordinals address.',true)}catch(e){m('wm',e.message)}};
$('fundb').onclick=async()=>{try{if(!$('uok').checked)throw Error('Asset check not confirmed');let d=await api('/api/funding',{network:net,outpoint:$('fund').value});$('build').disabled=false;m('fm',`${d.value} sats · confirmed · ${d.kind}`,true)}catch(e){m('fm',e.message)}};
$('build').onclick=async()=>{try{if(!$('aok').checked)throw Error('Ordinals address not confirmed');let d=await api('/api/build',{network:net,feerate:$('rate').value,wif:$('wif').value});$('wif').value='';psbt=d.psbt;$('sum').textContent=d.summary;$('sum').classList.remove('hide');$('sign').disabled=false;m('pm','Input 0 signed and verified. WIF erased.',true)}catch(e){$('wif').value='';m('pm',e.message)}};
$('sign').onclick=async()=>{try{let a=list(await wr('getAddresses',{purposes:['ordinals','payment']})),o=a.find(x=>String(x.purpose).toLowerCase()==='ordinals'),p=a.find(x=>String(x.purpose).toLowerCase()==='payment');if(o?.address!==wallet.ordinals.address||p?.address!==wallet.payment.address)throw Error('Xverse account changed');let r=await wr('signPsbt',{psbt,signInputs:{[p.address]:[1]},broadcast:false}),signed=signedPsbt(r);let d=await api('/api/verify',{network:net,psbt:signed,paymentAddress:p.address,ordinalsAddress:o.address});$('raw').value=d.hex;$('dl').disabled=$('send').disabled=false;m('vm',`VERIFIED\ntxid ${d.txid}\n${d.vsize} vB · ${d.fee} sats · ${d.feerate.toFixed(2)} sat/vB`,true)}catch(e){m('vm',e.message)}};
$('dl').onclick=()=>{let u=URL.createObjectURL(new Blob([$('raw').value+'\n'],{type:'text/plain'})),a=document.createElement('a');a.href=u;a.download='verified-transaction.hex';a.click();URL.revokeObjectURL(u)};$('send').onclick=async()=>{try{if($('word').value!=='DIFFUSER')throw Error('Type DIFFUSER exactly');let d=await api('/api/broadcast',{network:net,confirmation:'DIFFUSER',hex:$('raw').value});m('bm','Broadcast: '+d.txid,true)}catch(e){m('bm',e.message)}};</script></body></html>'''

GUIDE_PAGE=r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Pos Recovery — User Guide</title>
<style nonce="__NONCE__">:root{color-scheme:dark;--b:#11100d;--p:#211e18;--f:#eee7d9;--m:#aaa08e;--g:#d0aa32;--r:#e0523b}*{box-sizing:border-box}body{margin:0;background:var(--b);color:var(--f);font:15px/1.65 system-ui}.w{max-width:820px;margin:auto;padding:32px 20px 80px}.logo{display:block;width:min(100%,340px);height:auto;margin:0 auto 24px}h1{font:36px Georgia;margin-bottom:8px}h2{font:24px Georgia;margin:0 0 8px}h3{font-size:16px;color:var(--g);margin:22px 0 6px}.lead,.muted{color:var(--m)}section{border-top:1px solid #3d372f;padding:26px 0}a{color:var(--g);text-underline-offset:3px}.back{display:inline-block;margin-bottom:20px}.callout{border-left:3px solid var(--g);background:var(--p);padding:14px 16px;margin:18px 0}.danger{border-color:var(--r);color:#ffb2a6}.step{display:grid;grid-template-columns:34px 1fr;gap:12px;margin:18px 0}.num{display:grid;place-items:center;width:28px;height:28px;border:1px solid var(--g);border-radius:50%;color:var(--g);font:12px monospace}.step p{margin:0}.mono{font-family:monospace}ul{padding-left:22px}li{margin:7px 0}@media(max-width:520px){h1{font-size:30px}}</style></head><body><main class="w"><img class="logo" src="/img/raresatscards-logo.png?t=__TOKEN__" alt="Rare Sats Cards"><a class="back" href="/?t=__TOKEN__">← Back to Pos Recovery</a><h1>User guide</h1><p class="lead">How to safely move the Rare Sat from a Proof of Sats card to your Xverse Ordinals address.</p>
<div class="callout danger"><strong>Before you start:</strong> a Mainnet Bitcoin transaction is real and irreversible. Never share or photograph the private key revealed under the card seal. Read the complete plan before signing or broadcasting.</div>
<section><h2>What this tool does</h2><p>Pos Recovery moves the entire Bitcoin UTXO held by your card into output 0 of a new transaction. Output 0 pays your Xverse Ordinals address and has exactly the same value as the card UTXO. A separate Xverse payment UTXO pays every mining fee.</p><p>This structure keeps all card sats together and in their original order. The Rare Sat therefore keeps the same offset inside the protected output instead of being consumed by mining fees.</p></section>
<section><h2>Why Xverse is used</h2><p>Xverse is an Ordinals-aware Bitcoin wallet that clearly separates its Ordinals address from its payment address. This makes it well suited to receiving and managing rare sats while keeping the fee-paying funds separate.</p><p>Your Xverse wallet must be funded before recovery. Keep <strong>a few thousand sats</strong> on its payment address so the tool can select a confirmed payment UTXO, pay the mining fee, and return change above the dust limit. The exact amount required depends on the current fee rate; funding it with approximately 5,000 to 10,000 sats generally leaves a comfortable margin.</p><div class="callout">Do not use the Ordinals address as the funding source. The Ordinals address receives the protected card output; the Xverse payment address supplies the separate fee input.</div></section>
<section><h2>What you need</h2><ul><li>The card outpoint in <span class="mono">TXID:VOUT</span> format.</li><li>The WIF private key revealed under the card seal.</li><li>The Xverse browser extension, unlocked and connected to the correct Bitcoin network.</li><li>A confirmed Xverse payment UTXO containing enough sats for fees and change.</li><li>Time to verify every address and transaction detail without rushing.</li></ul></section>
<section><h2>Step-by-step instructions</h2>
<div class="step"><span class="num">1</span><p><strong>Confirm the network.</strong> Use Mainnet for a real recovery. Signet is reserved for developers and technical testing. Once confirmed, the server locks the network for its entire lifetime; changing a disabled browser control or calling the API directly cannot change it. Restart the application to choose another network.</p></div>
<div class="step"><span class="num">2</span><p><strong>Verify the card.</strong> Enter its outpoint and WIF. The tool checks that the UTXO exists, is confirmed and unspent, and that the private key matches its P2WPKH output. The WIF remains local and is erased after signing.</p></div>
<div class="step"><span class="num">3</span><p><strong>Connect Xverse.</strong> Approve the connection and carefully compare the displayed Ordinals address with Xverse. Tick the confirmation only after checking it visually.</p></div>
<div class="step"><span class="num">4</span><p><strong>Select funding.</strong> Enter a confirmed UTXO belonging to the displayed Xverse payment address. Check independently that it contains no inscription, rune, rare sat, or other asset you need to preserve.</p></div>
<div class="step"><span class="num">5</span><p><strong>Review the plan.</strong> Choose a fee rate and sign input 0 locally. Confirm that input 0 is the card, output 0 pays the Ordinals address, and both show the same complete card value. The fee must come entirely from input 1.</p></div>
<div class="step"><span class="num">6</span><p><strong>Sign with Xverse.</strong> Xverse is asked to sign input 1 only. Automatic broadcast is disabled. The returned PSBT is treated as untrusted and checked against the original plan before finalization.</p></div>
<div class="step"><span class="num">7</span><p><strong>Broadcast separately.</strong> Review or download the final transaction. Type <span class="mono">DIFFUSER</span> only when you are ready to send the exact verified bytes to Bitcoin. Confirm the resulting txid and wait for confirmation.</p></div></section>
<section><h2>Built-in safety boundaries</h2><ul><li>The local server processes state-changing operations one at a time. Concurrent browser requests cannot interleave the card, wallet, plan, PSBT, or network state.</li><li>The selected network is enforced by the server and remains locked even after sensitive session data expires or is erased.</li><li>The broadcast endpoint accepts only the exact transaction bytes produced by the immediately preceding successful verification.</li><li>The remote txid must match the txid calculated locally before the application reports a successful broadcast.</li></ul></section>
<section><h2>The four values that must match the plan</h2><ul><li><strong>Input 0:</strong> the card outpoint and its full value.</li><li><strong>Input 1:</strong> the confirmed Xverse payment UTXO.</li><li><strong>Output 0:</strong> the Xverse Ordinals address and the card’s exact full value.</li><li><strong>Output 1:</strong> the Xverse payment/change address and funding value minus fees.</li></ul></section>
<section><h2>After broadcast</h2><p>Wait for the transaction to confirm. Verify output 0 in a Bitcoin explorer and, when available, in an Ordinals-aware indexer. A confirmed Bitcoin transaction proves that the output exists; an Ordinals-aware check provides additional confirmation that the Rare Sat is present at the expected offset.</p><p class="muted">If any address, amount, network, signature request, or wallet account differs from what you expected, stop. Do not bypass a rejection or weaken a safety check.</p></section>
<a class="back" href="/?t=__TOKEN__">← Return to Pos Recovery</a></main></body></html>'''

def reset():
    with STATE_LOCK:
        n=STATE.get("network","mainnet"); locked=STATE.get("network_locked",False); STATE.clear(); STATE.update(network=n,network_locked=locked,ctx=None,wallet=None,plan=None,psbt=None,verified=None,touched=time.monotonic())
def touch():
    if time.monotonic()-STATE["touched"]>TTL: reset(); raise core.Refusal("Session expired and was erased.")
    STATE["touched"]=time.monotonic()
def setnet(n):
    if not STATE["network_locked"]: raise core.Refusal("Confirm and lock the network first.")
    if n!=STATE["network"]: raise core.Refusal("Network does not match the locked session.")
    core.set_network(n)

def run_route(f,b):
    """Serialize state and core network access for one complete API operation."""
    with STATE_LOCK:
        touch()
        return f(b)

class Handler(BaseHTTPRequestHandler):
    server_version="pos-recovery"
    def log_message(self,*_): pass
    def sendx(self,code,obj,ctype="application/json; charset=utf-8"):
        data=obj if isinstance(obj,bytes) else (obj.encode() if isinstance(obj,str) else json.dumps(obj).encode()); self.send_response(code)
        for k,v in (("Content-Type",ctype),("Content-Length",str(len(data))),("Cache-Control","no-store"),("Pragma","no-cache"),("Referrer-Policy","no-referrer"),("X-Content-Type-Options","nosniff"),("X-Frame-Options","DENY"),("Content-Security-Policy","default-src 'none'; script-src 'nonce-%s'; style-src 'nonce-%s'; img-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"%(NONCE,NONCE))): self.send_header(k,v)
        self.end_headers(); self.wfile.write(data)
    def hostok(self): return self.headers.get("Host","")=="127.0.0.1:%d"%self.server.server_port
    def do_GET(self):
        q=parse_qs(urlsplit(self.path).query)
        if self.client_address[0]!="127.0.0.1" or not self.hostok() or q.get("t",[""])[0]!=TOKEN:return self.sendx(403,"denied","text/plain")
        if urlsplit(self.path).path == "/img/raresatscards-logo.png":
            if not LOGO_PATH.is_file(): return self.sendx(404,"logo missing","text/plain")
            return self.sendx(200,LOGO_PATH.read_bytes(),"image/png")
        if urlsplit(self.path).path == "/guide":
            return self.sendx(200,GUIDE_PAGE.replace("__TOKEN__",TOKEN).replace("__NONCE__",NONCE),"text/html; charset=utf-8")
        self.sendx(200,PAGE.replace("__TOKEN__",TOKEN).replace("__NONCE__",NONCE),"text/html; charset=utf-8")
    def do_POST(self):
        origin="http://127.0.0.1:%d"%self.server.server_port
        if self.client_address[0]!="127.0.0.1" or not self.hostok() or self.headers.get("Origin")!=origin or self.headers.get("X-Session-Token")!=TOKEN:return self.sendx(403,{"error":"origin, host, or session token rejected"})
        try:
            n=int(self.headers.get("Content-Length","0"))
            if n<0 or n>MAX_BODY:return self.sendx(413,{"error":"request too large"})
            b=json.loads(self.rfile.read(n) or b"{}");f=ROUTES.get(urlsplit(self.path).path)
            if not f:return self.sendx(404,{"error":"unknown route"})
            self.sendx(200,run_route(f,b))
        except core.Refusal as e:self.sendx(400,{"error":"Rejected: %s"%e})
        except Exception as e:self.sendx(400,{"error":"Invalid data or unavailable service (%s)."%e.__class__.__name__})

def network(b):
    n=b.get("network");
    if n not in ("signet","mainnet"):raise core.Refusal("Unsupported network.")
    if STATE["network_locked"]:raise core.Refusal("Network is already locked for this server session.")
    reset();STATE["network"]=n;STATE["network_locked"]=True;core.set_network(n);return {"network":n}
def card(b):
    setnet(b.get("network"));tx,v=core.parse_outpoint(b.get("outpoint",""));u=core.fetch_utxo(core.NETWORKS[STATE["network"]]["api"],tx,v)
    if u["spent"] or u["value"]<=0 or not u["confirmed"]:raise core.Refusal("UTXO is spent, unconfirmed, or has an invalid value.")
    if core.spk_kind(bytes.fromhex(u["scriptpubkey"]))!="P2WPKH":raise core.Refusal("Card output is not P2WPKH.")
    ranges=None;ordurl=core.NETWORKS[STATE["network"]]["ord"]
    if ordurl:
        try:ranges=core.fetch_sat_ranges(ordurl,tx,v)
        except Exception:pass
    STATE["ctx"]={"network":STATE["network"],"card":dict(u,**({"sat_ranges":[list(x) for x in ranges]} if ranges else {}))};return {"value":u["value"],"kind":"P2WPKH","ranges":bool(ranges)}
def wallet(b):
    setnet(b.get("network"));o,p=b.get("ordinals",{}),b.get("payment",{})
    for x in (o,p):core.address_to_spk(x.get("address",""));bytes.fromhex(x.get("publicKey",""))
    if core.spk_kind(core.address_to_spk(o["address"]))!="P2TR" or core.spk_kind(core.address_to_spk(p["address"])) not in ("P2SH","P2WPKH"):raise core.Refusal("Unsupported Xverse address types.")
    STATE["wallet"]={"ordinals":o,"payment":p};return {"ok":True}
def funding(b):
    setnet(b.get("network"));tx,v=core.parse_outpoint(b.get("outpoint",""));u=core.fetch_utxo(core.NETWORKS[STATE["network"]]["api"],tx,v);p=STATE["wallet"]["payment"]
    if u["spent"] or not u["confirmed"] or u.get("address")!=p["address"]:raise core.Refusal("UTXO is spent, unconfirmed, or does not belong to Xverse.")
    u["public_key"]=p["publicKey"];STATE["ctx"]["funding"]=u;return {"value":u["value"],"kind":core.spk_kind(bytes.fromhex(u["scriptpubkey"]))}
def build(b):
    setnet(b.get("network"));w=str(b.get("wif","")).strip()
    try:
        priv,compressed=core.wif_decode(w);pub=core.compress_point(core.privkey_to_point(priv));card_spk=bytes.fromhex(STATE["ctx"]["card"]["scriptpubkey"])
        if not compressed or b"\x00\x14"+core.hash160(pub)!=card_spk:raise core.Refusal("The WIF does not match the card output script.")
        rate=float(str(b.get("feerate","")).replace(",","."));wa=STATE["wallet"];p=core.plan_recovery(STATE["ctx"],wa["ordinals"]["address"],rate,change_addr=wa["payment"]["address"]);psbt=core.create_card_signed_psbt(p,w,wa["payment"]["publicKey"])
    finally:w=None;b["wif"]=""
    STATE.update(plan=p,psbt=psbt,verified=None);pred="unknown" if not p["prediction"] else "output 0, offset %d"%p["prediction"]["offset"]
    s="Input 0 CARD: %s — %d sats\nInput 1 XVERSE: %s — %d sats\nOutput 0 ORDINALS: %s — %d sats\nOutput 1 CHANGE: %s — %d sats\nFee: %d sats, entirely paid by the funding input\nEstimated rate: %.2f sat/vB\nTarget sat: %s\nAll %d card sats remain together."%(p["card_outpoint"],p["card_value"],p["fund_outpoint"],p["tx"].vin[1].value,p["dest_address"],p["card_value"],p["change_address"],p["change_value"],p["fee"],p["feerate_effective"],pred,p["card_value"]);return {"psbt":psbt,"summary":s}
def verify(b):
    setnet(b.get("network"));w=STATE["wallet"]
    if b.get("paymentAddress")!=w["payment"]["address"] or b.get("ordinalsAddress")!=w["ordinals"]["address"]:raise core.Refusal("Xverse account changed.")
    r=core.verify_xverse_psbt(STATE["psbt"],b.get("psbt",""),STATE["plan"],w["payment"]["publicKey"]);STATE["verified"]=r;return r
def broadcast(b):
    setnet(b.get("network"));v=STATE.get("verified")
    if b.get("confirmation")!="DIFFUSER" or not v or b.get("hex")!=v["hex"]:raise core.Refusal("Confirmation missing or transaction bytes were not verified.")
    p=core.parse_tx(bytes.fromhex(v["hex"]));
    if p["version"]!=2 or p["locktime"]!=0 or len(p["vin"])!=2 or len(p["vout"])!=2:raise core.Refusal("Final verification failed.")
    got=core._http_post(core.NETWORKS[STATE["network"]]["api"]+"/tx",v["hex"]).strip()
    if got.lower()!=v["txid"].lower():raise core.Refusal("Remote txid does not match the locally calculated txid.")
    txid=v["txid"];reset();return {"txid":txid}
ROUTES={"/api/network":network,"/api/card":card,"/api/wallet":wallet,"/api/funding":funding,"/api/build":build,"/api/verify":verify,"/api/broadcast":broadcast}
def main():
    p=argparse.ArgumentParser();p.add_argument("--port",type=int,default=0);p.add_argument("--no-browser",action="store_true");a=p.parse_args();srv=ThreadingHTTPServer(("127.0.0.1",a.port),Handler);url="http://127.0.0.1:%d/?t=%s"%(srv.server_port,TOKEN);print("Local interface (Mainnet by default):",url)
    if not a.no_browser:threading.Timer(.4,lambda:webbrowser.open(url)).start()
    try:srv.serve_forever()
    except KeyboardInterrupt:pass
    finally:reset();srv.server_close()
    return 0
if __name__=="__main__":sys.exit(main())
