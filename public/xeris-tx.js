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
      const c = BASE_MAP[str.charCodeAt(i)];
      if (c === 255) throw new Error('Invalid base58 character "' + str[i] + '" at position ' + i + ' in: ' + str.slice(0, 20) + (str.length > 20 ? '...' : ''));
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

  // Extract 64-byte Ed25519 signature from signed tx bytes
  // Handles both Solana wire format and bincode format (wallet may use either)
  function extractSigFromTxBytes(bytes) {
    if (bytes[0] === 1) {
      // Both formats start with 1, but bincode has 7 more zero bytes (u64 LE count)
      const isBincode = bytes[1]===0 && bytes[2]===0 && bytes[3]===0
                     && bytes[4]===0 && bytes[5]===0 && bytes[6]===0 && bytes[7]===0;
      if (isBincode && bytes.length >= 72) return bytes.slice(8, 72);
      return bytes.slice(1, 65);  // Solana wire format
    }
    // Fallback: read compact-u16 count, skip to sig
    let offset = 0;
    let count = bytes[offset] & 0x7f;
    if (bytes[offset] & 0x80) { offset++; count |= (bytes[offset] & 0x7f) << 7; }
    offset++;
    if (count >= 1 && offset + 64 <= bytes.length) return bytes.slice(offset, offset + 64);
    throw new Error('Could not extract signature from ' + bytes.length + ' bytes');
  }

  // Legacy alias
  function extractSignature(signedTxBytes) { return extractSigFromTxBytes(signedTxBytes); }

  // Decode base64 string to Uint8Array
  function fromBase64(str) {
    const bin = atob(str);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  // Handle all wallet return formats: extract sig, reassemble signed tx
  // Returns { signature: Uint8Array(64), signedTx: Uint8Array, txSignature: string }
  function resolveSignedTx(walletResult, messageBytes) {
    let sig;

    // Object with explicit .signature (Uint8Array)
    if (walletResult && typeof walletResult === 'object'
        && !ArrayBuffer.isView(walletResult) && !Array.isArray(walletResult)) {
      if (walletResult.signature) {
        const s = walletResult.signature instanceof Uint8Array
          ? walletResult.signature : new Uint8Array(walletResult.signature);
        if (s.length === 64) { sig = s; }
      }
      if (!sig && walletResult.signedTransaction) {
        const txBytes = typeof walletResult.signedTransaction === 'string'
          ? fromBase64(walletResult.signedTransaction)
          : new Uint8Array(walletResult.signedTransaction);
        sig = extractSigFromTxBytes(txBytes);
      }
      if (!sig) {
        // Try .transaction or .data
        const txBytes = walletResult.transaction || walletResult.data;
        if (txBytes instanceof Uint8Array || Array.isArray(txBytes)) {
          sig = extractSigFromTxBytes(new Uint8Array(txBytes));
        }
      }
    }

    // Base64 string → decode → extract sig
    if (!sig && typeof walletResult === 'string') {
      sig = extractSigFromTxBytes(fromBase64(walletResult));
    }

    // Raw bytes
    if (!sig) {
      const bytes = walletResult instanceof Uint8Array
        ? walletResult : new Uint8Array(walletResult);
      if (bytes.length === 64) sig = bytes;
      else if (bytes.length > 64) sig = extractSigFromTxBytes(bytes);
    }

    if (!sig || sig.length !== 64) throw new Error('Could not extract 64-byte signature from wallet');

    // Re-assemble in Solana wire format (don't trust wallet's format)
    const signedTx = concat([encodeCompactU16(1), sig, messageBytes]);
    const txSignature = base58Encode(sig);

    return { signature: sig, signedTx, txSignature };
  }

  async function fetchRecentBlockhash() {
    const res = await fetch('/api/xeris/blockhash'); const data = await res.json();
    const bh = data?.result?.value?.blockhash || data?.result?.blockhash;
    if (typeof bh === 'string') {
      // Hex-encoded blockhash (64 hex chars = 32 bytes)
      if (bh.length >= 64 && /^[0-9a-fA-F]+$/.test(bh)) {
        const b = new Uint8Array(32); for (let i = 0; i < 32; i++) b[i] = parseInt(bh.substr(i * 2, 2), 16); return b;
      }
      // Base58-encoded blockhash (32-44 chars)
      if (bh.length >= 32 && bh.length <= 44) {
        try { return decodePubkey(bh); } catch {}
      }
    }
    const blocks = Array.isArray(data) ? data : data?.blocks || [];
    if (blocks.length > 0 && Array.isArray(blocks[0].hash) && blocks[0].hash.length === 32) return new Uint8Array(blocks[0].hash);
    throw new Error('Could not fetch blockhash (got: ' + JSON.stringify(bh || data).slice(0, 100) + ')');
  }

  async function buildBetTx(fromAddress, amountXRS) {
    const addr = (fromAddress || '').trim();
    if (!addr) throw new Error('No wallet address provided');
    const amountLamports = BigInt(Math.floor(amountXRS*1e9));
    const blockhash = await fetchRecentBlockhash();
    let signerPubkey;
    try { signerPubkey = decodePubkey(addr); }
    catch (e) { throw new Error('Cannot decode wallet address: ' + e.message); }
    const instructionData = encodeNativeTransfer(addr, TREASURY_ADDRESS, amountLamports);
    const messageBytes = buildMessage(signerPubkey, instructionData, blockhash);
    return { unsignedTx: buildUnsignedTx(messageBytes), messageBytes };
  }

  return { base58Decode, base58Encode, decodePubkey, encodeNativeTransfer, buildMessage, buildUnsignedTx, extractSignature, extractSigFromTxBytes, fromBase64, resolveSignedTx, fetchRecentBlockhash, buildBetTx, concat, encodeCompactU16 };
})();
