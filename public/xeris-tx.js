// XERIS TX BUILDER — Browser-side (shared by lottery + casino)
const TREASURY_ADDRESS = '6G4GroMrVsGjd3xhywxfzXDg7vPn1V2Mky4B3qsXVGHo';

const XerisTx = (() => {
  const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  const BASE_MAP = new Uint8Array(256).fill(255);
  for (let i = 0; i < ALPHABET.length; i++) BASE_MAP[ALPHABET.charCodeAt(i)] = i;

  function base58Decode(str) {
    if (!str.length) return new Uint8Array(0);
    const bytes = [0];
    for (let i = 0; i < str.length; i++) {
      const c = BASE_MAP[str.charCodeAt(i)]; if (c === 255) throw new Error('Invalid base58');
      let carry = c; for (let j = 0; j < bytes.length; j++) { carry += bytes[j]*58; bytes[j]=carry&0xff; carry>>=8; }
      while (carry>0) { bytes.push(carry&0xff); carry>>=8; }
    }
    for (let i = 0; i < str.length && str[i]==='1'; i++) bytes.push(0);
    return new Uint8Array(bytes.reverse());
  }

  function base58Encode(bytes) {
    const digits = [0];
    for (let i = 0; i < bytes.length; i++) {
      let carry = bytes[i]; for (let j = 0; j < digits.length; j++) { carry+=digits[j]<<8; digits[j]=carry%58; carry=(carry/58)|0; }
      while (carry>0) { digits.push(carry%58); carry=(carry/58)|0; }
    }
    let out = ''; for (let i = 0; i < bytes.length && bytes[i]===0; i++) out += '1';
    for (let i = digits.length-1; i >= 0; i--) out += ALPHABET[digits[i]];
    return out;
  }

  function u32LE(v) { const b=new Uint8Array(4); b[0]=v&0xff;b[1]=(v>>8)&0xff;b[2]=(v>>16)&0xff;b[3]=(v>>24)&0xff; return b; }
  function u64LE(v) { const big=BigInt(v),b=new Uint8Array(8); for(let i=0;i<8;i++)b[i]=Number((big>>BigInt(i*8))&0xFFn); return b; }
  function encodeString(str) { const e=new TextEncoder().encode(str); return concat([u64LE(e.length),e]); }
  function encodeCompactU16(v) { const o=[]; let x=v; while(x>=0x80){o.push((x&0x7f)|0x80);x>>=7;} o.push(x&0x7f); return new Uint8Array(o); }
  function concat(arrays) { const len=arrays.reduce((s,a)=>s+a.length,0),r=new Uint8Array(len); let off=0; for(const a of arrays){r.set(a,off);off+=a.length;} return r; }

  function decodePubkey(str) { const raw=base58Decode(str); if(raw.length===32)return raw; const p=new Uint8Array(32); p.set(raw,32-raw.length); return p; }
  function encodeNativeTransfer(from,to,amt) { return concat([u32LE(11),encodeString(from),encodeString(to),u64LE(amt)]); }

  function buildMessage(signerPubkey, instructionData, blockhash) {
    return concat([
      new Uint8Array([1,0,1]), encodeCompactU16(2),
      signerPubkey, new Uint8Array(32), blockhash,
      encodeCompactU16(1), new Uint8Array([1]),
      encodeCompactU16(1), new Uint8Array([0]),
      encodeCompactU16(instructionData.length), instructionData,
    ]);
  }

  function buildUnsignedTx(messageBytes) { return concat([encodeCompactU16(1), new Uint8Array(64), messageBytes]); }
  function extractSignature(signedTxBytes) { return signedTxBytes.slice(1, 65); }

  async function fetchRecentBlockhash() {
    const res = await fetch('/api/xeris/blockhash'); const data = await res.json();
    const bh = data?.result?.value?.blockhash || data?.result?.blockhash;
    if (typeof bh==='string' && bh.length>=64) { const b=new Uint8Array(32); for(let i=0;i<32;i++)b[i]=parseInt(bh.substr(i*2,2),16); return b; }
    const blocks = Array.isArray(data)?data:data?.blocks||[];
    if (blocks.length>0 && Array.isArray(blocks[0].hash) && blocks[0].hash.length===32) return new Uint8Array(blocks[0].hash);
    throw new Error('Could not fetch blockhash');
  }

  async function buildBetTx(fromAddress, amountXRS) {
    const amountLamports = BigInt(Math.floor(amountXRS*1e9));
    const blockhash = await fetchRecentBlockhash();
    const signerPubkey = decodePubkey(fromAddress);
    const instructionData = encodeNativeTransfer(fromAddress, TREASURY_ADDRESS, amountLamports);
    const messageBytes = buildMessage(signerPubkey, instructionData, blockhash);
    return { unsignedTx: buildUnsignedTx(messageBytes), messageBytes };
  }

  return { base58Decode, base58Encode, decodePubkey, encodeNativeTransfer, buildMessage, buildUnsignedTx, extractSignature, fetchRecentBlockhash, buildBetTx, concat, encodeCompactU16 };
})();
