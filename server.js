const express = require('express');
const path = require('path');
const crypto = require('crypto');
const nacl = require('tweetnacl');
const bs58 = require('bs58');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Xeris Network Config ─────────────────────────────────────────────────────
const XERIS_RPC = process.env.XERIS_RPC || 'http://138.197.116.81:50008';
const XERIS_NET = process.env.XERIS_NET || 'http://138.197.116.81:56001';
const TREASURY_ADDRESS = process.env.TREASURY_ADDRESS || '6G4GroMrVsGjd3xhywxfzXDg7vPn1V2Mky4B3qsXVGHo';

// ── Lottery Config ───────────────────────────────────────────────────────────
const TICKET_PRICE_LAMPORTS = 10_000_000_000;  // 10 XRS
const DRAW_INTERVAL_MS = 5 * 60 * 1000;        // 5 minutes
const MAX_TICKETS_PER_BUY = 100;

// ── Treasury Keypair ─────────────────────────────────────────────────────────
let treasuryKeypair = null;
if (process.env.TREASURY_PRIVATE_KEY) {
  try {
    const secretKey = bs58.decode(process.env.TREASURY_PRIVATE_KEY);
    treasuryKeypair = nacl.sign.keyPair.fromSecretKey(secretKey);
    console.log('Treasury keypair loaded');
  } catch (e) {
    console.error('Failed to load treasury keypair:', e.message);
  }
} else {
  console.warn('TREASURY_PRIVATE_KEY not set — payouts disabled');
}

// ── Optional Postgres ────────────────────────────────────────────────────────
let db = null;
let hasDB = false;
if (process.env.DATABASE_URL) {
  try {
    const { Pool } = require('pg');
    db = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
    hasDB = true;
  } catch (e) {
    console.warn('pg module not available — running without persistence');
  }
} else {
  console.warn('DATABASE_URL not set — running without persistence');
}

async function dbQuery(text, params) {
  if (!hasDB) return { rows: [] };
  return db.query(text, params);
}

async function initDatabase() {
  if (!hasDB) return;
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS lottery_rounds (
        id SERIAL PRIMARY KEY,
        started_at BIGINT DEFAULT (EXTRACT(EPOCH FROM NOW())*1000)::BIGINT,
        draw_at BIGINT,
        winner_address TEXT,
        prize_pool BIGINT DEFAULT 0,
        seed TEXT,
        drawn_at BIGINT,
        status TEXT DEFAULT 'active'
      );
      CREATE TABLE IF NOT EXISTS lottery_tickets (
        id SERIAL PRIMARY KEY,
        round_id INT REFERENCES lottery_rounds(id),
        address TEXT NOT NULL,
        tickets INT NOT NULL,
        tx_signature TEXT UNIQUE NOT NULL,
        created_at BIGINT DEFAULT (EXTRACT(EPOCH FROM NOW())*1000)::BIGINT
      );
      CREATE TABLE IF NOT EXISTS lottery_payouts (
        id SERIAL PRIMARY KEY,
        round_id INT REFERENCES lottery_rounds(id),
        address TEXT NOT NULL,
        amount BIGINT NOT NULL,
        payout_tx TEXT,
        created_at BIGINT DEFAULT (EXTRACT(EPOCH FROM NOW())*1000)::BIGINT
      );
      CREATE TABLE IF NOT EXISTS casino_bets (
        id SERIAL PRIMARY KEY,
        address TEXT NOT NULL,
        game TEXT NOT NULL,
        bet_type TEXT,
        bet_value TEXT,
        bet_amount BIGINT NOT NULL,
        bet_tx_signature TEXT UNIQUE NOT NULL,
        won BOOLEAN DEFAULT FALSE,
        multiplier REAL DEFAULT 0,
        payout_amount BIGINT DEFAULT 0,
        payout_tx TEXT,
        result_json JSONB,
        created_at BIGINT DEFAULT (EXTRACT(EPOCH FROM NOW())*1000)::BIGINT
      );
    `);
    console.log('Database tables initialized');
  } catch (e) {
    console.error('DB init error:', e.message);
    hasDB = false;
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  XERIS TX BUILDER (server-side)
// ══════════════════════════════════════════════════════════════════════════════
const XerisTx = (() => {
  function u32LE(v) { const b = Buffer.alloc(4); b.writeUInt32LE(v); return b; }
  function u64LE(v) { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(v)); return b; }
  function encodeString(str) { const e = Buffer.from(str, 'utf8'); return Buffer.concat([u64LE(e.length), e]); }
  function encodeCompactU16(value) {
    const out = []; let v = value;
    while (v >= 0x80) { out.push((v & 0x7f) | 0x80); v >>= 7; }
    out.push(v & 0x7f); return Buffer.from(out);
  }
  function base58DecodePubkey(str) {
    const raw = bs58.decode(str);
    if (raw.length === 32) return Buffer.from(raw);
    const padded = Buffer.alloc(32);
    Buffer.from(raw).copy(padded, 32 - raw.length);
    return padded;
  }
  function encodeNativeTransfer(from, to, amount) {
    return Buffer.concat([u32LE(11), encodeString(from), encodeString(to), u64LE(amount)]);
  }
  function buildMessage(signerPubkey, instructionData, blockhash) {
    const programId = Buffer.alloc(32);
    return Buffer.concat([
      Buffer.from([1, 0, 1]), encodeCompactU16(2),
      signerPubkey, programId, blockhash,
      encodeCompactU16(1), Buffer.from([1]),
      encodeCompactU16(1), Buffer.from([0]),
      encodeCompactU16(instructionData.length), instructionData,
    ]);
  }
  function assembleSignedTx(signature, messageBytes) {
    return Buffer.concat([encodeCompactU16(1), signature, messageBytes]);
  }
  return { u32LE, u64LE, encodeString, encodeCompactU16, base58DecodePubkey, encodeNativeTransfer, buildMessage, assembleSignedTx };
})();

// ── Crypto-secure random ─────────────────────────────────────────────────────
function secureRandom() {
  return crypto.randomBytes(4).readUInt32BE(0) / 0x100000000;
}
function secureRandomInt(min, max) {
  return min + Math.floor(secureRandom() * (max - min + 1));
}

// ── Fetch blockhash (correct path: / not /rpc) ──────────────────────────────
async function fetchBlockhash() {
  try {
    const res = await fetch(`${XERIS_RPC}/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getRecentBlockhash', params: [] }),
    });
    const data = await res.json();
    const bh = data?.result?.value?.blockhash || data?.result?.blockhash;
    if (typeof bh === 'string') {
      // Hex-encoded blockhash (64 hex chars = 32 bytes)
      if (bh.length >= 64 && /^[0-9a-fA-F]+$/.test(bh)) {
        const bytes = Buffer.alloc(32);
        for (let i = 0; i < 32; i++) bytes[i] = parseInt(bh.substr(i * 2, 2), 16);
        return bytes;
      }
      // Base58-encoded blockhash (32-44 chars)
      if (bh.length >= 32 && bh.length <= 44) {
        try { return XerisTx.base58DecodePubkey(bh); } catch {}
      }
    }
  } catch {}
  try {
    const res = await fetch(`${XERIS_NET}/blocks?limit=1`);
    const data = await res.json();
    const blocks = Array.isArray(data) ? data : data?.blocks || [];
    if (blocks.length > 0 && Array.isArray(blocks[0].hash) && blocks[0].hash.length === 32) {
      return Buffer.from(blocks[0].hash);
    }
  } catch {}
  throw new Error('Could not fetch blockhash');
}

// ── Build + sign a payout from treasury ──────────────────────────────────────
async function buildAndSignPayout(toAddress, amountLamports) {
  if (!treasuryKeypair) throw new Error('Treasury keypair not configured');
  const blockhash = await fetchBlockhash();
  const signerPubkey = XerisTx.base58DecodePubkey(TREASURY_ADDRESS);
  const instructionData = XerisTx.encodeNativeTransfer(TREASURY_ADDRESS, toAddress, amountLamports);
  const messageBytes = XerisTx.buildMessage(signerPubkey, instructionData, blockhash);
  const signature = nacl.sign.detached(messageBytes, treasuryKeypair.secretKey);
  const signedTx = XerisTx.assembleSignedTx(Buffer.from(signature), messageBytes);
  return signedTx.toString('base64');
}

// ── Submit tx to node ────────────────────────────────────────────────────────
async function submitToNode(txBase64) {
  const bodyStr = JSON.stringify({ tx_base64: txBase64 });
  const res = await fetch(`${XERIS_NET}/submit`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(bodyStr).toString() },
    body: bodyStr,
  });
  const data = await res.json();
  if (data.error) throw new Error(data.error);
  return data;
}

// ── Verify tx on-chain (8-try poll, NO bypass) ──────────────────────────────
async function verifyTxOnChain(txSignature) {
  for (let i = 0; i < 8; i++) {
    try {
      const r = await fetch(`${XERIS_RPC}/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getTransaction', params: [txSignature] }),
      });
      const data = await r.json();
      if (data?.result) return true;
    } catch {}
    if (i < 7) await new Promise(r => setTimeout(r, 2000));
  }
  return false;
}

// ── Async error wrapper ──────────────────────────────────────────────────────
function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

// ── Input validation ─────────────────────────────────────────────────────────
const BASE58_RE = /^[1-9A-HJ-NP-Za-km-z]{20,50}$/;
const VALID_GAMES = new Set(['dice', 'crash', 'roulette', 'blackjack']);
const MIN_BET_XRS = 0.01;
const MAX_BET_XRS = 10000;

// ══════════════════════════════════════════════════════════════════════════════
//  CASINO GAME LOGIC (crypto-secure random)
// ══════════════════════════════════════════════════════════════════════════════
const bjStates = new Map();
const RED_NUMS = new Set([1,3,5,7,9,12,14,16,18,19,21,23,25,27,30,32,34,36]);

function resolveDice(betType, betValue) {
  const roll = secureRandomInt(1, 100);
  const target = parseInt(betValue) || 50;
  let won = false, multiplier = 1;
  if (betType === 'exact') { won = roll === target; multiplier = 99; }
  else if (betType === 'over') { won = roll > target; multiplier = +(99 / Math.max(1, 100 - target)).toFixed(2); }
  else { won = roll < target; multiplier = +(99 / Math.max(1, target - 1)).toFixed(2); }
  return { result: { roll }, won, multiplier: won ? multiplier : 0 };
}

function resolveCrash(target) {
  const r = secureRandom();
  const crashPoint = Math.max(1.00, +(1 / (1 - r * 0.99)).toFixed(2));
  const t = parseFloat(target) || 2.00;
  const won = crashPoint >= t;
  return { result: { crashPoint }, won, multiplier: won ? t : 0 };
}

function resolveRoulette(betType, betValue) {
  const number = secureRandomInt(0, 36);
  const color = number === 0 ? 'green' : RED_NUMS.has(number) ? 'red' : 'black';
  let won = false, multiplier = 0;
  switch (betType) {
    case 'red': won = color === 'red'; multiplier = 2; break;
    case 'black': won = color === 'black'; multiplier = 2; break;
    case 'green': won = number === 0; multiplier = 36; break;
    case 'even': won = number > 0 && number % 2 === 0; multiplier = 2; break;
    case 'odd': won = number % 2 === 1; multiplier = 2; break;
    case 'number': won = number === parseInt(betValue); multiplier = 35; break;
  }
  return { result: { number, color }, won, multiplier: won ? multiplier : 0 };
}

function newDeck() {
  const suits = ['H','D','C','S'], vals = ['2','3','4','5','6','7','8','9','10','J','Q','K','A'];
  const deck = [];
  for (const s of suits) for (const v of vals) deck.push(v + s);
  for (let i = deck.length - 1; i > 0; i--) {
    const j = secureRandomInt(0, i);
    [deck[i], deck[j]] = [deck[j], deck[i]];
  }
  return deck;
}

function bjHandValue(hand) {
  let total = 0, aces = 0;
  for (const c of hand) {
    const v = c.slice(0, -1);
    if (['J','Q','K'].includes(v)) total += 10;
    else if (v === 'A') { total += 11; aces++; }
    else total += parseInt(v);
  }
  while (total > 21 && aces > 0) { total -= 10; aces--; }
  return total;
}

function resolveBlackjack(betType, existingState) {
  if (betType === 'deal') {
    const deck = newDeck();
    const playerHand = [deck.pop(), deck.pop()];
    const dealerHand = [deck.pop(), deck.pop()];
    const pScore = bjHandValue(playerHand);
    const dScore = bjHandValue(dealerHand);
    if (pScore === 21 && dScore === 21)
      return { result: { playerHand, dealerHand, playerScore: pScore, dealerScore: dScore, status: 'push' }, won: false, multiplier: 1, gameOver: true, deck };
    if (pScore === 21)
      return { result: { playerHand, dealerHand, playerScore: pScore, dealerScore: dScore, status: 'blackjack' }, won: true, multiplier: 2.5, gameOver: true, deck };
    if (dScore === 21)
      return { result: { playerHand, dealerHand, playerScore: pScore, dealerScore: dScore, status: 'dealer_blackjack' }, won: false, multiplier: 0, gameOver: true, deck };
    return { result: { playerHand, dealerHand, playerScore: pScore, dealerScore: dScore, status: 'playing' }, won: false, multiplier: 0, gameOver: false, deck };
  }
  if (!existingState) return { error: 'No active game' };
  let { playerHand, dealerHand, deck } = existingState;
  if (betType === 'hit') {
    playerHand.push(deck.pop());
    const pScore = bjHandValue(playerHand);
    if (pScore > 21)
      return { result: { playerHand, dealerHand, playerScore: pScore, dealerScore: bjHandValue(dealerHand), status: 'bust' }, won: false, multiplier: 0, gameOver: true, deck };
    return { result: { playerHand, dealerHand, playerScore: pScore, dealerScore: bjHandValue(dealerHand), status: 'playing' }, won: false, multiplier: 0, gameOver: false, deck };
  }
  let doubled = false;
  if (betType === 'double') {
    playerHand.push(deck.pop());
    doubled = true;
    const pScore = bjHandValue(playerHand);
    if (pScore > 21)
      return { result: { playerHand, dealerHand, playerScore: pScore, dealerScore: bjHandValue(dealerHand), status: 'bust' }, won: false, multiplier: 0, gameOver: true, deck, doubled };
  }
  while (bjHandValue(dealerHand) < 17) dealerHand.push(deck.pop());
  const pScore = bjHandValue(playerHand);
  const dScore = bjHandValue(dealerHand);
  let status, won, multiplier;
  if (dScore > 21)        { status = 'dealer_bust'; won = true;  multiplier = doubled ? 4 : 2; }
  else if (pScore > dScore) { status = 'win';       won = true;  multiplier = doubled ? 4 : 2; }
  else if (pScore === dScore) { status = 'push';    won = false; multiplier = 1; }
  else                    { status = 'lose';         won = false; multiplier = 0; }
  return { result: { playerHand, dealerHand, playerScore: pScore, dealerScore: dScore, status }, won, multiplier, gameOver: true, deck, doubled };
}

// ══════════════════════════════════════════════════════════════════════════════
//  LOTTERY STATE (in-memory fallback)
// ══════════════════════════════════════════════════════════════════════════════
const lottery = {
  currentRound: { id: 1, players: [], startedAt: Date.now(), drawAt: Date.now() + DRAW_INTERVAL_MS },
  pastRounds: [],
};

function totalTickets() { return lottery.currentRound.players.reduce((s, p) => s + p.tickets, 0); }
function prizePoolLamports() { return BigInt(totalTickets()) * BigInt(TICKET_PRICE_LAMPORTS); }

// ── Draw Logic (auto-payout 95% to winner) ───────────────────────────────────
async function runDraw() {
  const round = lottery.currentRound;
  const total = totalTickets();
  if (total === 0) { round.drawAt = Date.now() + DRAW_INTERVAL_MS; return; }

  let seed;
  try { const bh = await fetchBlockhash(); seed = bh.toString('hex'); } catch { seed = crypto.randomBytes(32).toString('hex'); }

  const hashBuf = crypto.createHash('sha256').update(Buffer.from(seed, 'hex')).digest();
  const roll = hashBuf.readUInt32BE(0) % total;

  let cumulative = 0, winner = null;
  for (const p of round.players) { cumulative += p.tickets; if (roll < cumulative) { winner = p; break; } }
  if (!winner) winner = round.players[round.players.length - 1];

  const prizePool = Number(prizePoolLamports());
  const winnerPayout = Math.floor(prizePool * 0.95);

  console.log(`Round #${round.id} DRAW: ${total} tickets, Winner: ${winner.address} (${prizePool / 1e9} XRS, 95% = ${winnerPayout / 1e9} XRS)`);

  let payoutTx = null;
  if (treasuryKeypair && winnerPayout > 0) {
    try {
      const txBase64 = await buildAndSignPayout(winner.address, winnerPayout);
      const result = await submitToNode(txBase64);
      payoutTx = result.signature || result.txid || null;
      console.log(`Payout submitted: ${payoutTx}`);
    } catch (e) { console.error('Auto-payout failed:', e.message); }
  }

  if (hasDB) {
    try {
      await dbQuery(`UPDATE lottery_rounds SET winner_address=$1, prize_pool=$2, seed=$3, drawn_at=$4, status='drawn' WHERE id=$5`,
        [winner.address, prizePool, seed, Date.now(), round.id]);
      if (payoutTx) await dbQuery(`INSERT INTO lottery_payouts (round_id, address, amount, payout_tx) VALUES ($1,$2,$3,$4)`, [round.id, winner.address, winnerPayout, payoutTx]);
    } catch (e) { console.error('DB save draw error:', e.message); }
  }

  lottery.pastRounds.unshift({ id: round.id, winner: { address: winner.address, amount: winnerPayout, payoutTx }, prizePool, players: [...round.players], drawnAt: Date.now(), seed });
  if (lottery.pastRounds.length > 50) lottery.pastRounds.length = 50;

  const newDrawAt = Date.now() + DRAW_INTERVAL_MS;
  lottery.currentRound = { id: round.id + 1, players: [], startedAt: Date.now(), drawAt: newDrawAt };
  if (hasDB) {
    try {
      const r = await dbQuery(`INSERT INTO lottery_rounds (draw_at, status) VALUES ($1, 'active') RETURNING id`, [newDrawAt]);
      if (r.rows.length) lottery.currentRound.id = r.rows[0].id;
    } catch (e) { console.error('DB new round error:', e.message); }
  }
}

setInterval(() => { if (Date.now() >= lottery.currentRound.drawAt) runDraw().catch(e => console.error('Draw error:', e)); }, 5000);

// ══════════════════════════════════════════════════════════════════════════════
//  MIDDLEWARE
// ══════════════════════════════════════════════════════════════════════════════
app.use(express.json());
app.use(express.static(__dirname));
app.use(express.static(path.join(__dirname, 'public')));

const generalLimiter = rateLimit({ windowMs: 60000, max: 60, standardHeaders: true, legacyHeaders: false });
const betLimiter = rateLimit({ windowMs: 60000, max: 20, message: { error: 'Too many bets — slow down' } });
const faucetLimiter = rateLimit({ windowMs: 300000, max: 3, message: { error: 'Faucet rate limited' } });
app.use('/api/', generalLimiter);

// ── Xeris Proxies (inline — no external submit proxy) ────────────────────────
app.get('/api/xeris/blockhash', asyncHandler(async (req, res) => {
  try {
    const r = await fetch(`${XERIS_RPC}/`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getRecentBlockhash', params: [] }),
    });
    res.json(await r.json());
  } catch (e) {
    try { const r2 = await fetch(`${XERIS_NET}/blocks?limit=1`); res.json(await r2.json()); }
    catch (e2) { res.status(500).json({ error: e2.message }); }
  }
}));

app.post('/api/xeris/submit', asyncHandler(async (req, res) => {
  const { tx_base64 } = req.body;
  if (!tx_base64) return res.status(400).json({ error: 'Missing tx_base64' });
  const bodyStr = JSON.stringify({ tx_base64 });
  const r = await fetch(`${XERIS_NET}/submit`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(bodyStr).toString() }, body: bodyStr,
  });
  const data = await r.json();
  if (data.error) console.warn('Submit rejected by node:', data.error);
  res.json(data);
}));

app.get('/api/xeris/balance/:address', asyncHandler(async (req, res) => {
  const addr = req.params.address;
  if (!BASE58_RE.test(addr)) return res.status(400).json({ error: 'Invalid address' });
  const r = await fetch(`${XERIS_RPC}/`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getBalance', params: [addr] }),
  });
  const data = await r.json();
  res.json({ address: addr, balance: data?.result?.value ?? data?.result ?? 0 });
}));

app.get('/api/xeris/faucet/:address/:amount', faucetLimiter, asyncHandler(async (req, res) => {
  if (!BASE58_RE.test(req.params.address)) return res.status(400).json({ error: 'Invalid address' });
  const r = await fetch(`${XERIS_NET}/airdrop/${req.params.address}/${req.params.amount}`);
  res.json(await r.json());
}));

// ── Casino API (per-bet on-chain signing) ────────────────────────────────────
app.get('/api/stats', (req, res) => {
  if (hasDB) { dbQuery('SELECT COUNT(*) as count FROM casino_bets').then(r => res.json({ gamesPlayed: parseInt(r.rows[0]?.count || 0) })).catch(() => res.json({ gamesPlayed: 0 })); }
  else res.json({ gamesPlayed: 0 });
});

app.get('/api/treasury', asyncHandler(async (req, res) => {
  try {
    const r = await fetch(`${XERIS_RPC}/`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getBalance', params: [TREASURY_ADDRESS] }),
    });
    const data = await r.json();
    res.json({ address: TREASURY_ADDRESS, balance: data?.result?.value ?? data?.result ?? 0 });
  } catch { res.json({ address: TREASURY_ADDRESS, balance: 0 }); }
}));

app.post('/api/casino/bet', betLimiter, asyncHandler(async (req, res) => {
  const { game, betType, betValue, amount, playerAddress, txSignature } = req.body;
  if (!playerAddress || !BASE58_RE.test(playerAddress)) return res.status(400).json({ error: 'Invalid player address' });
  if (!game || !VALID_GAMES.has(game)) return res.status(400).json({ error: 'Invalid game' });
  if (!txSignature || typeof txSignature !== 'string' || txSignature.length < 20) return res.status(400).json({ error: 'Invalid transaction signature' });
  const betAmount = parseFloat(amount) || 0;
  if (betAmount < MIN_BET_XRS || betAmount > MAX_BET_XRS) return res.status(400).json({ error: `Bet must be between ${MIN_BET_XRS} and ${MAX_BET_XRS} XRS` });

  if (hasDB) { const dup = await dbQuery('SELECT id FROM casino_bets WHERE bet_tx_signature=$1', [txSignature]); if (dup.rows.length > 0) return res.status(400).json({ error: 'Transaction already used' }); }

  const confirmed = await verifyTxOnChain(txSignature);
  if (!confirmed) return res.status(400).json({ error: 'Transaction not confirmed on-chain. Try again.' });

  let resolved;
  if (game === 'dice') resolved = resolveDice(betType, betValue);
  else if (game === 'crash') resolved = resolveCrash(betValue);
  else if (game === 'roulette') resolved = resolveRoulette(betType, betValue);
  else if (game === 'blackjack') {
    resolved = resolveBlackjack('deal', null);
    if (!resolved.gameOver) {
      const seed = 'bj_' + Date.now() + '_' + crypto.randomBytes(4).toString('hex');
      bjStates.set(seed, { playerHand: resolved.result.playerHand, dealerHand: resolved.result.dealerHand, deck: resolved.deck, betAmount, playerAddress, txSignature });
      return res.json({ result: { ...resolved.result, dealerHand: [resolved.result.dealerHand[0], '??'] }, payout: 0, payoutAmount: '0', betAmount: betAmount.toFixed(4), txSignature, seed });
    }
  }

  const betLamports = Math.floor(betAmount * 1e9);
  const payout = resolved.multiplier * betAmount;
  const payoutLamports = Math.floor(payout * 1e9);

  let payoutTxSignature = null;
  if (payout > 0 && treasuryKeypair) {
    try {
      const sendAmount = payout > betAmount ? payoutLamports - betLamports : betLamports;
      if (sendAmount > 0) { const txBase64 = await buildAndSignPayout(playerAddress, sendAmount); const sr = await submitToNode(txBase64); payoutTxSignature = sr.signature || sr.txid || null; }
    } catch (e) { console.warn('Casino payout tx failed:', e.message); }
  }

  if (hasDB) { try { await dbQuery(`INSERT INTO casino_bets (address,game,bet_type,bet_value,bet_amount,bet_tx_signature,won,multiplier,payout_amount,payout_tx,result_json) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, [playerAddress, game, betType, betValue, betLamports, txSignature, resolved.won || payout > 0, resolved.multiplier, payoutLamports, payoutTxSignature, JSON.stringify(resolved.result)]); } catch (e) { console.warn('DB save bet error:', e.message); } }

  console.log(`Casino ${game}: ${playerAddress.slice(0,8)}… bet ${betAmount} → ${payout > 0 ? 'WIN +' + payout.toFixed(4) : 'LOSE'}`);
  res.json({ result: resolved.result, payout, payoutAmount: payout > 0 ? payout.toFixed(4) : '0', betAmount: betAmount.toFixed(4), txSignature, payoutTxSignature });
}));

app.post('/api/casino/bj-action', betLimiter, asyncHandler(async (req, res) => {
  const { action, seed, playerAddress, txSignature } = req.body;
  if (!seed || !bjStates.has(seed)) return res.status(400).json({ error: 'No active blackjack game' });
  if (!playerAddress || !BASE58_RE.test(playerAddress)) return res.status(400).json({ error: 'Invalid address' });
  if (!['hit', 'stand', 'double'].includes(action)) return res.status(400).json({ error: 'Invalid action' });
  const state = bjStates.get(seed);
  if (state.playerAddress !== playerAddress) return res.status(403).json({ error: 'Not your game' });

  if (action === 'double') {
    if (!txSignature || typeof txSignature !== 'string' || txSignature.length < 20) return res.status(400).json({ error: 'Double requires a new signed transaction' });
    if (hasDB) { const dup = await dbQuery('SELECT id FROM casino_bets WHERE bet_tx_signature=$1', [txSignature]); if (dup.rows.length > 0) return res.status(400).json({ error: 'Transaction already used' }); }
    const confirmed = await verifyTxOnChain(txSignature);
    if (!confirmed) return res.status(400).json({ error: 'Double transaction not confirmed' });
  }

  const extraBet = action === 'double' ? state.betAmount : 0;
  const resolved = resolveBlackjack(action, state);
  if (resolved.error) return res.status(400).json({ error: resolved.error });

  const totalBet = state.betAmount + extraBet;
  const payout = resolved.multiplier * totalBet;
  const totalBetLamports = Math.floor(totalBet * 1e9);
  const payoutLamports = Math.floor(payout * 1e9);

  let payoutTxSignature = null;
  if (resolved.gameOver) {
    if (payout > 0 && treasuryKeypair) {
      try {
        const sendAmount = payout > totalBet ? payoutLamports - totalBetLamports : totalBetLamports;
        if (sendAmount > 0) { const txBase64 = await buildAndSignPayout(playerAddress, sendAmount); const sr = await submitToNode(txBase64); payoutTxSignature = sr.signature || sr.txid || null; }
      } catch (e) { console.warn('BJ payout failed:', e.message); }
    }
    if (hasDB) { try { await dbQuery(`INSERT INTO casino_bets (address,game,bet_type,bet_value,bet_amount,bet_tx_signature,won,multiplier,payout_amount,payout_tx,result_json) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, [playerAddress, 'blackjack', action, '0', totalBetLamports, state.txSignature + '_' + action, resolved.won || payout > 0, resolved.multiplier, payoutLamports, payoutTxSignature, JSON.stringify(resolved.result)]); } catch (e) { console.warn('DB save bj error:', e.message); } }
    bjStates.delete(seed);
    console.log(`Casino blackjack: ${playerAddress.slice(0,8)}… bet ${totalBet} → ${payout > 0 ? 'WIN +' + payout.toFixed(4) : 'LOSE'} (${resolved.result.status})`);
  } else {
    state.playerHand = resolved.result.playerHand;
    state.dealerHand = resolved.result.dealerHand;
    state.deck = resolved.deck;
  }

  res.json({
    result: resolved.gameOver ? resolved.result : { ...resolved.result, dealerHand: [resolved.result.dealerHand[0], '??'] },
    payout: payout > 0 ? payout : 0, payoutAmount: payout > 0 ? payout.toFixed(4) : '0',
    betAmount: totalBet.toFixed(4), gameOver: resolved.gameOver, payoutTxSignature, seed,
  });
}));

app.get('/api/casino/history/:address', asyncHandler(async (req, res) => {
  if (!BASE58_RE.test(req.params.address)) return res.status(400).json({ error: 'Invalid address' });
  if (!hasDB) return res.json({ bets: [] });
  const r = await dbQuery('SELECT game, bet_amount, won, multiplier, payout_amount, payout_tx, result_json, created_at FROM casino_bets WHERE address=$1 ORDER BY created_at DESC LIMIT 50', [req.params.address]);
  res.json({ bets: r.rows.map(b => ({ ...b, bet_amount: Number(b.bet_amount) / 1e9, payout_amount: Number(b.payout_amount) / 1e9 })) });
}));

// ── Lottery API ──────────────────────────────────────────────────────────────
app.get('/api/lottery/status', (req, res) => {
  const round = lottery.currentRound;
  const pool = Number(prizePoolLamports());
  res.json({
    round: round.id, players: round.players.map(p => ({ address: p.address, tickets: p.tickets })),
    totalTickets: totalTickets(), prizePool: pool, prizePoolXRS: pool / 1e9,
    drawAt: round.drawAt, ticketPriceLamports: TICKET_PRICE_LAMPORTS, ticketPriceXRS: TICKET_PRICE_LAMPORTS / 1e9,
    pastWinners: lottery.pastRounds.slice(0, 10).map(r => ({
      round: r.id, address: r.winner.address, amount: r.winner.amount, amountXRS: r.winner.amount / 1e9,
      paid: !!r.winner.payoutTx, payoutTx: r.winner.payoutTx, drawnAt: r.drawnAt,
    })),
    treasuryAddress: TREASURY_ADDRESS, payoutsEnabled: !!treasuryKeypair,
  });
});

app.post('/api/lottery/buy', betLimiter, asyncHandler(async (req, res) => {
  const { address, tickets, txSignature } = req.body;
  if (!address || !BASE58_RE.test(address)) return res.status(400).json({ error: 'Invalid address' });
  if (!tickets || !txSignature) return res.status(400).json({ error: 'Missing tickets or txSignature' });
  const ticketCount = Math.min(Math.max(1, Math.floor(tickets)), MAX_TICKETS_PER_BUY);

  const isDuplicate = lottery.currentRound.players.some(p => p.txSignature === txSignature);
  if (isDuplicate) return res.status(400).json({ error: 'Transaction already registered' });
  if (hasDB) { const dup = await dbQuery('SELECT id FROM lottery_tickets WHERE tx_signature=$1', [txSignature]); if (dup.rows.length > 0) return res.status(400).json({ error: 'Transaction already registered' }); }

  const confirmed = await verifyTxOnChain(txSignature);
  if (!confirmed) return res.status(400).json({ error: 'Transaction not confirmed on-chain. Try again.' });

  const existing = lottery.currentRound.players.find(p => p.address === address);
  if (existing) { existing.tickets += ticketCount; existing.txSignature = txSignature; }
  else lottery.currentRound.players.push({ address, tickets: ticketCount, txSignature });

  if (hasDB) { try { await dbQuery('INSERT INTO lottery_tickets (round_id, address, tickets, tx_signature) VALUES ($1,$2,$3,$4)', [lottery.currentRound.id, address, ticketCount, txSignature]); } catch (e) { console.warn('DB save ticket error:', e.message); } }

  const pool = Number(prizePoolLamports());
  console.log(`Round #${lottery.currentRound.id}: ${address.slice(0,8)}… bought ${ticketCount} tickets (pool: ${pool / 1e9} XRS)`);
  res.json({ success: true, tickets: ticketCount, totalTickets: totalTickets(), prizePool: pool, round: lottery.currentRound.id });
}));

// ── Serve Frontend ───────────────────────────────────────────────────────────
app.get('/casino', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.use((err, req, res, next) => { console.error('Unhandled error:', err.message); res.status(500).json({ error: 'Internal server error' }); });

async function start() {
  await initDatabase();
  if (hasDB) {
    try {
      const r = await dbQuery(`SELECT id, draw_at FROM lottery_rounds WHERE status='active' ORDER BY id DESC LIMIT 1`);
      if (r.rows.length) { lottery.currentRound.id = r.rows[0].id; lottery.currentRound.drawAt = parseInt(r.rows[0].draw_at); }
      else { const newDrawAt = Date.now() + DRAW_INTERVAL_MS; const ins = await dbQuery(`INSERT INTO lottery_rounds (draw_at, status) VALUES ($1, 'active') RETURNING id`, [newDrawAt]); if (ins.rows.length) lottery.currentRound.id = ins.rows[0].id; lottery.currentRound.drawAt = newDrawAt; }
      const tickets = await dbQuery('SELECT address, tickets, tx_signature FROM lottery_tickets WHERE round_id=$1', [lottery.currentRound.id]);
      lottery.currentRound.players = tickets.rows.map(t => ({ address: t.address, tickets: t.tickets, txSignature: t.tx_signature }));
    } catch (e) { console.error('DB load error:', e.message); }
  }
  app.listen(PORT, () => {
    console.log(`XERIS.PLAY running on port ${PORT}`);
    console.log(`Treasury: ${TREASURY_ADDRESS}`);
    console.log(`Payouts: ${treasuryKeypair ? 'ENABLED' : 'DISABLED (set TREASURY_PRIVATE_KEY)'}`);
    console.log(`Draw interval: ${DRAW_INTERVAL_MS / 1000}s`);
    console.log(`Database: ${hasDB ? 'CONNECTED' : 'IN-MEMORY (no DATABASE_URL)'}`);
  });
}
start().catch(e => { console.error('Startup error:', e); process.exit(1); });
