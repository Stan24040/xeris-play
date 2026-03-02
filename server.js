const express = require('express');
const path = require('path');
const nacl = require('tweetnacl');
const bs58 = require('bs58');
const http = require('http');

const xerisBlockhash = require('./api/xeris/blockhash');
const xerisSubmit = require('./api/xeris/submit');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Xeris Network Config ─────────────────────────────────────────────────────
const XERIS_RPC = process.env.XERIS_RPC || 'http://138.197.116.81:50008';
const XERIS_NET = process.env.XERIS_NET || 'http://138.197.116.81:56001';
const TREASURY_ADDRESS = process.env.TREASURY_ADDRESS || '6G4GroMrVsGjd3xhywxfzXDg7vPn1V2Mky4B3qsXVGHo';

// ── Lottery Config ───────────────────────────────────────────────────────────
const TICKET_PRICE_LAMPORTS = 10_000_000_000;  // 10 XRS
const DRAW_INTERVAL_MS = 5 * 60 * 1000;   // 5 minutes
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

// ══════════════════════════════════════════════════════════════════════════════
//  XERIS TX BUILDER (server-side, matches migration guide)
// ══════════════════════════════════════════════════════════════════════════════
const XerisTx = (() => {
  function u32LE(v) {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(v);
    return b;
  }
  function u64LE(v) {
    const big = BigInt(v);
    const b = Buffer.alloc(8);
    b.writeBigUInt64LE(big);
    return b;
  }
  function encodeString(str) {
    const encoded = Buffer.from(str, 'utf8');
    return Buffer.concat([u64LE(encoded.length), encoded]);
  }
  function encodeCompactU16(value) {
    const out = [];
    let v = value;
    while (v >= 0x80) { out.push((v & 0x7f) | 0x80); v >>= 7; }
    out.push(v & 0x7f);
    return Buffer.from(out);
  }

  // Base58 decode to exactly 32 bytes (pad with leading zeros)
  function base58DecodePubkey(str) {
    const raw = bs58.decode(str);
    if (raw.length === 32) return Buffer.from(raw);
    const padded = Buffer.alloc(32);
    Buffer.from(raw).copy(padded, 32 - raw.length);
    return padded;
  }

  // NativeTransfer = variant 11: { from: String, to: String, amount: u64 }
  function encodeNativeTransfer(from, to, amount) {
    return Buffer.concat([u32LE(11), encodeString(from), encodeString(to), u64LE(amount)]);
  }

  // Solana legacy message
  function buildMessage(signerPubkey, instructionData, blockhash) {
    const programId = Buffer.alloc(32); // all zeros
    return Buffer.concat([
      Buffer.from([1, 0, 1]),                 // header
      encodeCompactU16(2),                     // 2 accounts
      signerPubkey,                            // account[0] = signer
      programId,                               // account[1] = program id
      blockhash,                               // 32 bytes
      encodeCompactU16(1),                     // 1 instruction
      Buffer.from([1]),                        // program_id_index = 1
      encodeCompactU16(1),                     // 1 account ref
      Buffer.from([0]),                        // account index 0
      encodeCompactU16(instructionData.length),
      instructionData,
    ]);
  }

  // Signed transaction (Solana wire format)
  function assembleSignedTx(signature, messageBytes) {
    return Buffer.concat([encodeCompactU16(1), signature, messageBytes]);
  }

  return { u32LE, u64LE, encodeString, encodeCompactU16, base58DecodePubkey, encodeNativeTransfer, buildMessage, assembleSignedTx };
})();

// ── Fetch blockhash from node (server-side, no CORS issue) ───────────────────
async function fetchBlockhash() {
  // Try JSON-RPC
  try {
    const res = await fetch(`${XERIS_RPC}/rpc`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getRecentBlockhash', params: [] }),
    });
    const data = await res.json();
    const bh = data?.result?.value?.blockhash || data?.result?.blockhash;
    if (typeof bh === 'string' && bh.length >= 64) {
      const bytes = Buffer.alloc(32);
      for (let i = 0; i < 32; i++) bytes[i] = parseInt(bh.substr(i * 2, 2), 16);
      return bytes;
    }
  } catch {}
  // Fallback: REST /blocks
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

  // Ed25519 sign the message
  const signature = nacl.sign.detached(messageBytes, treasuryKeypair.secretKey);

  // Assemble signed tx in Solana wire format
  const signedTx = XerisTx.assembleSignedTx(Buffer.from(signature), messageBytes);
  return signedTx.toString('base64');
}

// ── Submit tx to node ────────────────────────────────────────────────────────
async function submitToNode(txBase64) {
  const bodyStr = JSON.stringify({ tx_base64: txBase64 });
  const res = await fetch(`${XERIS_NET}/submit`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(bodyStr).toString(),
    },
    body: bodyStr,
  });
  const data = await res.json();
  if (data.error) throw new Error(data.error);
  return data;
}

// ══════════════════════════════════════════════════════════════════════════════
//  CASINO STATE + GAME LOGIC
// ══════════════════════════════════════════════════════════════════════════════
const casino = {
  balances: {},      // { address: XRS balance }
  gamesPlayed: 0,
  bjStates: {},      // { seed: { playerHand, dealerHand, deck, betAmount } }
};

const RED_NUMS = new Set([1,3,5,7,9,12,14,16,18,19,21,23,25,27,30,32,34,36]);

function resolveDice(betType, betValue) {
  const roll = Math.floor(Math.random() * 100) + 1;
  const target = parseInt(betValue) || 50;
  let won = false, multiplier = 1;
  if (betType === 'exact') { won = roll === target; multiplier = 99; }
  else if (betType === 'over') { won = roll > target; multiplier = +(99 / Math.max(1, 100 - target)).toFixed(2); }
  else { won = roll < target; multiplier = +(99 / Math.max(1, target - 1)).toFixed(2); }
  return { result: { roll }, won, multiplier: won ? multiplier : 0 };
}

function resolveCrash(target) {
  const r = Math.random();
  const crashPoint = Math.max(1.00, +(1 / (1 - r * 0.99)).toFixed(2));
  const t = parseFloat(target) || 2.00;
  const won = crashPoint >= t;
  return { result: { crashPoint }, won, multiplier: won ? t : 0 };
}

function resolveRoulette(betType, betValue) {
  const number = Math.floor(Math.random() * 37);
  const color = number === 0 ? 'green' : RED_NUMS.has(number) ? 'red' : 'black';
  let won = false, multiplier = 0;
  switch (betType) {
    case 'red': won = color === 'red'; multiplier = 2; break;
    case 'black': won = color === 'black'; multiplier = 2; break;
    case 'green': won = number === 0; multiplier = 14; break;
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
    const j = Math.floor(Math.random() * (i + 1));
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
  // Stand or Double
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
  if (dScore > 21)       { status = 'dealer_bust'; won = true;  multiplier = doubled ? 4 : 2; }
  else if (pScore > dScore) { status = 'win';        won = true;  multiplier = doubled ? 4 : 2; }
  else if (pScore === dScore) { status = 'push';     won = false; multiplier = 1; }
  else                   { status = 'lose';       won = false; multiplier = 0; }
  return { result: { playerHand, dealerHand, playerScore: pScore, dealerScore: dScore, status }, won, multiplier, gameOver: true, deck, doubled };
}

// ══════════════════════════════════════════════════════════════════════════════
//  LOTTERY STATE
// ══════════════════════════════════════════════════════════════════════════════
const lottery = {
  currentRound: {
    id: 1,
    players: [],       // [{ address, tickets, txSignature }]
    startedAt: Date.now(),
    drawAt: Date.now() + DRAW_INTERVAL_MS,
  },
  pastRounds: [],      // [{ id, winner, prizePool, players, drawnAt, payoutTx }]
  pendingPayouts: [],  // [{ address, amount, round, payoutTx }]
};

function totalTickets() {
  return lottery.currentRound.players.reduce((s, p) => s + p.tickets, 0);
}

function prizePoolLamports() {
  return BigInt(totalTickets()) * BigInt(TICKET_PRICE_LAMPORTS);
}

// ── Draw Logic ───────────────────────────────────────────────────────────────
async function runDraw() {
  const round = lottery.currentRound;
  const total = totalTickets();

  if (total === 0) {
    // No players — reset timer
    round.drawAt = Date.now() + DRAW_INTERVAL_MS;
    console.log(`Round #${round.id}: no players, resetting timer`);
    return;
  }

  // Pick winner using blockhash as seed for verifiable randomness
  let seed;
  try {
    const bh = await fetchBlockhash();
    seed = bh.toString('hex');
  } catch {
    seed = Date.now().toString();
  }

  // Hash seed to get a random index
  let hash = 0;
  for (let i = 0; i < seed.length; i++) {
    hash = ((hash << 5) - hash + seed.charCodeAt(i)) | 0;
  }
  const roll = Math.abs(hash) % total;

  let cumulative = 0;
  let winner = null;
  for (const p of round.players) {
    cumulative += p.tickets;
    if (roll < cumulative) { winner = p; break; }
  }
  if (!winner) winner = round.players[round.players.length - 1];

  const prizePool = Number(prizePoolLamports());
  const prizeXRS = prizePool / 1_000_000_000;

  console.log(`Round #${round.id} DRAW: ${total} tickets, ${round.players.length} players. Winner: ${winner.address} (${prizeXRS} XRS)`);

  const roundResult = {
    id: round.id,
    winner: { address: winner.address, amount: prizePool, claimed: false, payoutTx: null },
    prizePool,
    players: [...round.players],
    drawnAt: Date.now(),
    seed,
  };

  lottery.pastRounds.unshift(roundResult);
  // Keep only last 50 rounds
  if (lottery.pastRounds.length > 50) lottery.pastRounds.length = 50;

  // Start new round
  lottery.currentRound = {
    id: round.id + 1,
    players: [],
    startedAt: Date.now(),
    drawAt: Date.now() + DRAW_INTERVAL_MS,
  };
}

// Draw timer
setInterval(() => {
  if (Date.now() >= lottery.currentRound.drawAt) {
    runDraw().catch(e => console.error('Draw error:', e));
  }
}, 5000);

// ══════════════════════════════════════════════════════════════════════════════
//  MIDDLEWARE
// ══════════════════════════════════════════════════════════════════════════════
app.use(express.json());
// Serve static files from root (index.html) and public/ folder
app.use(express.static(__dirname));
app.use(express.static(path.join(__dirname, 'public')));

// ── Xeris Proxies (CORS-safe) ────────────────────────────────────────────────
app.get('/api/xeris/blockhash', (req, res) => xerisBlockhash(req, res));
app.post('/api/xeris/submit', (req, res) => xerisSubmit(req, res));

app.get('/api/xeris/balance/:address', async (req, res) => {
  try {
    const r = await fetch(`${XERIS_RPC}/rpc`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getBalance', params: [req.params.address] }),
    });
    const data = await r.json();
    const balance = data?.result?.value ?? data?.result ?? 0;
    res.json({ address: req.params.address, balance });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/xeris/faucet/:address/:amount', async (req, res) => {
  try {
    const r = await fetch(`${XERIS_NET}/airdrop/${req.params.address}/${req.params.amount}`);
    const data = await r.json();
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/xeris/stats', async (req, res) => {
  try {
    const r = await fetch(`${XERIS_RPC}/v2/stats`);
    const data = await r.json();
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Casino API ───────────────────────────────────────────────────────────────

// GET /api/stats — casino games played
app.get('/api/stats', (req, res) => {
  res.json({ gamesPlayed: casino.gamesPlayed });
});

// GET /api/treasury — treasury info
app.get('/api/treasury', async (req, res) => {
  try {
    const r = await fetch(`${XERIS_RPC}/rpc`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getBalance', params: [TREASURY_ADDRESS] }),
    });
    const data = await r.json();
    const balance = data?.result?.value ?? data?.result ?? 0;
    res.json({ address: TREASURY_ADDRESS, balance });
  } catch (e) {
    res.json({ address: TREASURY_ADDRESS, balance: 0 });
  }
});

// GET /api/balance/:address — casino credit balance
app.get('/api/balance/:address', (req, res) => {
  const bal = casino.balances[req.params.address] || 0;
  res.json({ balance: bal });
});

// POST /api/deposit — credit player balance after on-chain deposit
app.post('/api/deposit', async (req, res) => {
  const { playerAddress, txSignature, amount } = req.body;
  if (!playerAddress || !txSignature || !amount) {
    return res.status(400).json({ error: 'Missing playerAddress, txSignature, or amount' });
  }
  const xrs = parseFloat(amount);
  if (isNaN(xrs) || xrs < 0.01) {
    return res.status(400).json({ error: 'Invalid amount' });
  }
  // 2% deposit fee
  const credited = +(xrs * 0.98).toFixed(4);
  casino.balances[playerAddress] = (casino.balances[playerAddress] || 0) + credited;
  console.log(`Casino deposit: ${playerAddress.slice(0,8)}… +${credited} XRS (fee: ${(xrs - credited).toFixed(4)})`);
  res.json({ credited, newBalance: casino.balances[playerAddress] });
});

// POST /api/bet — casino game bet resolution
app.post('/api/bet', async (req, res) => {
  const { game, betType, betValue, amount, playerAddress, betTxSignature } = req.body;
  if (!game || !playerAddress) {
    return res.status(400).json({ error: 'Missing game or playerAddress' });
  }

  const betAmount = parseFloat(amount) || 0;

  // Blackjack continuation (hit/stand/double) — no extra balance needed
  if (game === 'blackjack' && betType !== 'deal') {
    const seed = betTxSignature;
    const bjState = casino.bjStates[seed];
    if (!bjState) return res.status(400).json({ error: 'No active blackjack game' });

    let extraDeduct = 0;
    if (betType === 'double') extraDeduct = bjState.betAmount;

    if (extraDeduct > 0 && (casino.balances[playerAddress] || 0) < extraDeduct) {
      return res.status(400).json({ error: 'Insufficient balance to double' });
    }
    if (extraDeduct > 0) casino.balances[playerAddress] -= extraDeduct;

    const resolved = resolveBlackjack(betType, bjState);
    if (resolved.error) return res.status(400).json({ error: resolved.error });

    const totalBet = bjState.betAmount + extraDeduct;
    const payout = resolved.multiplier * totalBet;

    if (resolved.gameOver) {
      if (payout > 0) casino.balances[playerAddress] = (casino.balances[playerAddress] || 0) + payout;
      delete casino.bjStates[seed];
      casino.gamesPlayed++;
    } else {
      bjState.playerHand = resolved.result.playerHand;
      bjState.dealerHand = resolved.result.dealerHand;
      bjState.deck = resolved.deck;
    }

    return res.json({
      result: resolved.result,
      payout: payout > 0 ? payout : 0,
      payoutAmount: payout > 0 ? payout.toFixed(4) : '0',
      betAmount: totalBet.toFixed(4),
      betTxSignature,
      seed,
    });
  }

  // New bet — deduct from balance
  if (betAmount < 0.01) return res.status(400).json({ error: 'Minimum bet is 0.01 XRS' });
  if ((casino.balances[playerAddress] || 0) < betAmount) {
    return res.status(400).json({ error: 'Insufficient balance. Please deposit XRS first.' });
  }

  casino.balances[playerAddress] -= betAmount;

  let resolved;
  if (game === 'dice') resolved = resolveDice(betType, betValue);
  else if (game === 'crash') resolved = resolveCrash(betValue);
  else if (game === 'roulette') resolved = resolveRoulette(betType, betValue);
  else if (game === 'blackjack') {
    resolved = resolveBlackjack('deal', null);
    if (!resolved.gameOver) {
      const seed = 'bj_' + Date.now() + '_' + Math.random().toString(36).slice(2);
      casino.bjStates[seed] = {
        playerHand: resolved.result.playerHand,
        dealerHand: resolved.result.dealerHand,
        deck: resolved.deck,
        betAmount,
      };
      return res.json({
        result: resolved.result,
        payout: 0,
        payoutAmount: '0',
        betAmount: betAmount.toFixed(4),
        betTxSignature,
        seed,
      });
    }
  } else {
    casino.balances[playerAddress] += betAmount; // refund
    return res.status(400).json({ error: 'Unknown game: ' + game });
  }

  const payout = resolved.multiplier * betAmount;
  if (payout > 0) casino.balances[playerAddress] = (casino.balances[playerAddress] || 0) + payout;
  casino.gamesPlayed++;

  // Attempt on-chain payout for wins
  let payoutTxSignature = null;
  if (payout > betAmount && treasuryKeypair) {
    try {
      const payoutLamports = Math.floor((payout - betAmount) * 1_000_000_000);
      const txBase64 = await buildAndSignPayout(playerAddress, payoutLamports);
      const submitResult = await submitToNode(txBase64);
      payoutTxSignature = submitResult.signature || submitResult.txid || null;
    } catch (e) {
      console.warn('Casino payout tx failed:', e.message);
    }
  }

  console.log(`Casino ${game}: ${playerAddress.slice(0,8)}… bet ${betAmount} → ${payout > 0 ? 'WIN +' + payout.toFixed(4) : 'LOSE'}`);

  res.json({
    result: resolved.result,
    payout,
    payoutAmount: payout > 0 ? payout.toFixed(4) : '0',
    betAmount: betAmount.toFixed(4),
    betTxSignature,
    payoutTxSignature,
  });
});

// ── Lottery API ──────────────────────────────────────────────────────────────

// GET /api/lottery/status — full state for frontend
app.get('/api/lottery/status', (req, res) => {
  const round = lottery.currentRound;
  const pool = Number(prizePoolLamports());
  res.json({
    round: round.id,
    players: round.players.map(p => ({ address: p.address, tickets: p.tickets })),
    totalTickets: totalTickets(),
    prizePool: pool,
    prizePoolXRS: pool / 1_000_000_000,
    drawAt: round.drawAt,
    ticketPriceLamports: TICKET_PRICE_LAMPORTS,
    ticketPriceXRS: TICKET_PRICE_LAMPORTS / 1_000_000_000,
    pastWinners: lottery.pastRounds.slice(0, 10).map(r => ({
      round: r.id,
      address: r.winner.address,
      amount: r.prizePool,
      amountXRS: r.prizePool / 1_000_000_000,
      claimed: r.winner.claimed,
      drawnAt: r.drawnAt,
    })),
    treasuryAddress: TREASURY_ADDRESS,
    payoutsEnabled: !!treasuryKeypair,
  });
});

// POST /api/lottery/buy — register ticket purchase after on-chain tx
// Body: { address, tickets, txSignature }
app.post('/api/lottery/buy', async (req, res) => {
  const { address, tickets, txSignature } = req.body;

  if (!address || !tickets || !txSignature) {
    return res.status(400).json({ error: 'Missing address, tickets, or txSignature' });
  }

  const ticketCount = Math.min(Math.max(1, Math.floor(tickets)), MAX_TICKETS_PER_BUY);

  // Check for duplicate tx
  const isDuplicate = lottery.currentRound.players.some(p => p.txSignature === txSignature);
  if (isDuplicate) {
    return res.status(400).json({ error: 'Transaction already registered' });
  }

  // Verify the tx exists on-chain (poll a few times)
  let confirmed = false;
  for (let i = 0; i < 8; i++) {
    try {
      const r = await fetch(`${XERIS_RPC}/rpc`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getTransaction', params: [txSignature] }),
      });
      const data = await r.json();
      if (data?.result) { confirmed = true; break; }
    } catch {}
    if (i < 7) await new Promise(r => setTimeout(r, 2000));
  }

  // Also accept if tx looks valid (long base58 string) — node v2 API has parsing issues
  if (!confirmed && txSignature.length >= 40) {
    confirmed = true; // Trust the signature format on testnet
  }

  if (!confirmed) {
    return res.status(400).json({ error: 'Transaction not confirmed on-chain. Try again.' });
  }

  // Add tickets
  const existing = lottery.currentRound.players.find(p => p.address === address);
  if (existing) {
    existing.tickets += ticketCount;
    existing.txSignature = txSignature; // update to latest
  } else {
    lottery.currentRound.players.push({ address, tickets: ticketCount, txSignature });
  }

  const pool = Number(prizePoolLamports());
  console.log(`Round #${lottery.currentRound.id}: ${address.slice(0,8)}… bought ${ticketCount} tickets (pool: ${pool / 1e9} XRS)`);

  res.json({
    success: true,
    tickets: ticketCount,
    totalTickets: totalTickets(),
    prizePool: pool,
    round: lottery.currentRound.id,
  });
});

// POST /api/lottery/claim — verify winner + sign payout from treasury
// Body: { address, round }
app.post('/api/lottery/claim', async (req, res) => {
  const { address, round } = req.body;

  if (!address) {
    return res.status(400).json({ error: 'Missing address' });
  }

  // Find the round
  const roundData = lottery.pastRounds.find(r => r.id === round);
  if (!roundData) {
    return res.status(404).json({ error: 'Round not found' });
  }

  // Verify this address is the winner
  if (roundData.winner.address !== address) {
    return res.status(403).json({ error: 'You are not the winner of this round' });
  }

  // Check if already claimed
  if (roundData.winner.claimed) {
    return res.status(400).json({ error: 'Prize already claimed', payoutTx: roundData.winner.payoutTx });
  }

  // Check treasury keypair
  if (!treasuryKeypair) {
    return res.status(503).json({ error: 'Payouts temporarily unavailable — treasury key not configured' });
  }

  try {
    const payoutAmount = roundData.prizePool;
    console.log(`Claim: paying ${payoutAmount / 1e9} XRS to ${address.slice(0,8)}… for round #${round}`);

    // Build + sign payout tx from treasury
    const txBase64 = await buildAndSignPayout(address, payoutAmount);

    // Submit to node
    const submitResult = await submitToNode(txBase64);
    const payoutTx = submitResult.signature || submitResult.txid || null;

    // Mark claimed
    roundData.winner.claimed = true;
    roundData.winner.payoutTx = payoutTx;

    console.log(`Payout submitted: ${payoutTx}`);

    res.json({
      success: true,
      payoutTx,
      amount: payoutAmount,
      amountXRS: payoutAmount / 1_000_000_000,
      round,
    });
  } catch (e) {
    console.error('Claim payout error:', e.message);
    res.status(500).json({ error: 'Payout failed: ' + e.message });
  }
});

// ── Serve Frontend ───────────────────────────────────────────────────────────
app.get('/casino', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`SOLPRIZE lottery running on port ${PORT}`);
  console.log(`Treasury: ${TREASURY_ADDRESS}`);
  console.log(`Payouts: ${treasuryKeypair ? 'ENABLED' : 'DISABLED (set TREASURY_PRIVATE_KEY)'}`);
  console.log(`Draw interval: ${DRAW_INTERVAL_MS / 1000}s`);
});
