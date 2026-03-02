const XerisTx=(()=>{
const A='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58d(s){let b=[0];for(let i=0;i<s.length;i++){let c=A.indexOf(s[i]),j=0;if(c<0)throw new Error('Bad b58');let carry=c;for(;j<b.length;j++){carry+=b[j]*58;b[j]=carry&255;carry>>=8;}while(carry>0){b.push(carry&255);carry>>=8;}}for(let i=0;i<s.length&&s[i]==='1';i++)b.push(0);return new Uint8Array(b.reverse());}
function b58e(b){let d=[0];for(let i=0;i<b.length;i++){let carry=b[i],j=0;for(;j<d.length;j++){carry+=d[j]<<8;d[j]=carry%58;carry=Math.floor(carry/58);}while(carry>0){d.push(carry%58);carry=Math.floor(carry/58);}}let r='';for(let i=0;i<b.length&&b[i]===0;i++)r+='1';for(let i=d.length-1;i>=0;i--)r+=A[d[i]];return r;}
function toB64(b){let s='';for(let i=0;i<b.length;i++)s+=String.fromCharCode(b[i]);return btoa(s);}
function frB64(s){const b=atob(s),r=new Uint8Array(b.length);for(let i=0;i<b.length;i++)r[i]=b.charCodeAt(i);return r;}
function cat(a){let t=0;for(const x of a)t+=x.length;const r=new Uint8Array(t);let o=0;for(const x of a){r.set(x,o);o+=x.length;}return r;}
function u8(v){return new Uint8Array([v&255]);}
function u32(v){const b=new Uint8Array(4);b[0]=v&255;b[1]=(v>>8)&255;b[2]=(v>>16)&255;b[3]=(v>>24)&255;return b;}
function u64(v){const n=BigInt(v),b=new Uint8Array(8);for(let i=0;i<8;i++)b[i]=Number((n>>BigInt(i*8))&255n);return b;}
function eStr(s){const e=new TextEncoder().encode(s);return cat([u64(e.length),e]);}
function cu16(v){const o=[];let x=v;while(x>=128){o.push((x&127)|128);x>>=7;}o.push(x&127);return new Uint8Array(o);}
function encNT(f,t,a){return cat([u32(11),eStr(f),eStr(t),u64(a)]);}
function encTT(id,f,t,a){return cat([u32(1),eStr(id),eStr(f),eStr(t),u64(a)]);}
function encTC(id,n,sym,dec,sup,auth){return cat([u32(3),eStr(id),eStr(n),eStr(sym),u8(dec),u64(sup),eStr(auth)]);}
function encTM(id,to,a){return cat([u32(0),eStr(id),eStr(to),u64(a)]);}
function decPub(s){const r=b58d(s);if(r.length===32)return r;const p=new Uint8Array(32);p.set(r,32-r.length);return p;}
async function fetchBH(){const r=await fetch('/api/xeris/blockhash');if(!r.ok)throw new Error('BH fail '+r.status);const d=await r.json();if(d.format==='hex'&&typeof d.blockhash==='string'){const b=new Uint8Array(32);for(let i=0;i<32;i++)b[i]=parseInt(d.blockhash.substr(i*2,2),16);return b;}if(Array.isArray(d.blockhash)&&d.blockhash.length===32)return new Uint8Array(d.blockhash);throw new Error('Bad BH format');}
function buildMsg(pub,data,bh){const prog=new Uint8Array(32);return cat([new Uint8Array([1,0,1]),cu16(2),pub,prog,bh,cu16(1),new Uint8Array([1]),cu16(1),new Uint8Array([0]),cu16(data.length),data]);}
function buildUTx(msg){return cat([cu16(1),new Uint8Array(64),msg]);}
function asmSTx(sig,msg){if(sig.length!==64)throw new Error('Sig must be 64 bytes');return cat([cu16(1),sig,msg]);}
function exSigBytes(b){if(b[0]===1){const isBc=b[1]===0&&b[2]===0&&b[3]===0&&b[4]===0&&b[5]===0&&b[6]===0&&b[7]===0;if(isBc&&b.length>=72)return b.slice(8,72);return b.slice(1,65);}let o=0,c=b[o]&127;if(b[o]&128){o++;c|=(b[o]&127)<<7;}o++;if(c>=1&&o+64<=b.length)return b.slice(o,o+64);throw new Error('Cannot extract sig');}
function exSig(w){if(w&&typeof w==='object'&&!ArrayBuffer.isView(w)&&!Array.isArray(w)){if(w.signature){const s=w.signature instanceof Uint8Array?w.signature:new Uint8Array(w.signature);if(s.length===64)return s;}if(w.signedTransaction){const t=typeof w.signedTransaction==='string'?frB64(w.signedTransaction):new Uint8Array(w.signedTransaction);return exSigBytes(t);}}if(typeof w==='string')return exSigBytes(frB64(w));const b=w instanceof Uint8Array?w:new Uint8Array(w);if(b.length===64)return b;if(b.length>64)return exSigBytes(b);throw new Error('Bad wallet response: '+b.length+' bytes');}
function resolve(w,msg){return toB64(asmSTx(exSig(w),msg));}
async function submit(tx){const r=await fetch('/api/xeris/submit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tx_base64:tx})});const d=await r.json();if(!r.ok||d.error)throw new Error(d.error||'TX failed');return d;}
async function signSubmit(idata,addr){const bh=await fetchBH();const pub=decPub(addr);const msg=buildMsg(pub,idata,bh);const utx=buildUTx(msg);if(!window.xeris)throw new Error('No Xeris wallet');const wr=await window.xeris.signTransaction(utx);const tx=resolve(wr,msg);return await submit(tx);}
async function connectWallet(){if(!window.xeris)throw new Error('Not in Xeris Wallet Browser');const r=await window.xeris.connect();let a;if(typeof r==='string')a=r;else if(r&&r.publicKey)a=r.publicKey.toString();else if(r&&r.address)a=r.address;else if(window.xeris.publicKey)a=window.xeris.publicKey.toString();else if(window.xeris.address)a=window.xeris.address;if(!a)throw new Error('No address');return a;}
async function silentConnect(){if(!window.xeris)return null;try{const r=await window.xeris.connect({onlyIfTrusted:true});let a;if(typeof r==='string')a=r;else if(r&&r.publicKey)a=r.publicKey.toString();else if(r&&r.address)a=r.address;else if(window.xeris.publicKey)a=window.xeris.publicKey.toString();return a||null;}catch(e){return null;}}
async function sendXRS(from,to,xrs){const lamps=BigInt(Math.round(xrs*1e9));return await signSubmit(encNT(from,to,lamps),from);}
return {b58d,b58e,toB64,frB64,cat,u8,u32,u64,eStr,cu16,encNT,encTT,encTC,encTM,decPub,fetchBH,buildMsg,buildUTx,asmSTx,exSig,resolve,submit,signSubmit,connectWallet,silentConnect,sendXRS,encodeNativeTransfer:encNT,encodeTokenTransfer:encTT,encodeTokenCreate:encTC,encodeTokenMint:encTM,base58DecodePubkey:decPub,fetchRecentBlockhash:fetchBH,buildMessage:buildMsg,buildUnsignedTx:buildUTx,assembleSignedTx:asmSTx,extractSignature:exSig,resolveSignedTx:resolve,submitTransaction:submit,signAndSubmit:signSubmit};
})();
window.XerisTx=XerisTx;