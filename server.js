const express = require('express');
const path = require('path');
const nacl = require('tweetnacl');
const bs58 = require('bs58');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Xeris Network Config ─────────────────────────────────────────────────────
const XERIS_API  = 'http://138.197.116.81:50008';
const XERIS_NET  = 'http://138.197.116.81:56001';
const EXPLORER   = 'http://138.197.116.81:50008';

// Treasury address (public key) — set TREASURY_PRIVATE_KEY in Railway env vars
const TREASURY_ADDRESS = process.env.TREASURY_ADDRESS || '6G4GroMrVsGjd3xhywxfzXDg7vPn1V2Mky4B3qsXVGHo';

// Load treasury keypair from env (base58-encoded secret key)
let treasuryKeypair = null;
if (process.env.TREASURY_PRIVATE_KEY) {
  try {
    const secretKey = bs58.decode(process.env.TREASURY_PRIVATE_KEY);
    treasuryKeypair = nacl.sign.keyPair.fromSecretKey(secretKey);
    console.log('Treasury keypair loaded ✓');
  } catch (e) {
    console.error('Failed to load treasury keypair:', e.message);
  }
} else {
  console.warn('TREASURY_PRIVATE_KEY not set — payouts disabled');
}

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Xeris Client Helpers ─────────────────────────────────────────────────────
async function xerisRPC(method, params = []) {
  const res = await fetch(`${XERIS_API}/rpc`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params })
  });
  const data = await res.json();
  return data.result;
}

async function getBalance(address) {
  const result = await xerisRPC('getBalance', [address]);
  return result?.value ?? result ?? 0;
}

async function getLatestBlockhash() {
  return await xerisRPC('getLatestBlockhash');
}

async function getTransaction(signature) {
  return await xerisRPC('getTransaction', [signature]);
}

async function submitTransaction(txBase64) {
  const res = await fetch(`${XERIS_NET}/submit`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ tx_base64: txBase64 })
  });
  return res.json();
}

// Build and sign a transfer transaction from treasury
async function buildPayoutTx(toAddress, amountLamports) {
  if (!treasuryKeypair) throw new Error('Treasury keypair not configured');

  const blockhashResult = await getLatestBlockhash();
  const blockhash = blockhashResult?.blockhash ?? blockhashResult;

  const transaction = {
    recentBlockhash: blockhash,
    instructions: [{
      from: TREASURY_ADDRESS,
      to: toAddress,
      amount: amountLamports
    }]
  };

  const message = Buffer.from(JSON.stringify(transaction));
  const signature = nacl.sign.detached(message, treasuryKeypair.secretKey);
  const txBase64 = Buffer.from(JSON.stringify({
    ...transaction,
    signature: Buffer.from(signature).toString('base64'),
    publicKey: bs58.encode(treasuryKeypair.publicKey)
  })).toString('base64');

  return txBase64;
}

// ── Provably Fair Randomness ─────────────────────────────────────────────────
// Uses the blockhash from the bet tx as the seed — fully verifiable on-chain
function seededRandom(seed, index = 0) {
  // Simple hash of seed string + index → float 0-1
  let hash = 0;
  const str = seed + index.toString();
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash + str.charCodeAt(i)) | 0;
  }
  return (Math.abs(hash) % 1000000) / 1000000;
}

// ── Game Logic ───────────────────────────────────────────────────────────────
function resolveDice(seed, betType, betValue) {
  const roll = Math.floor(seededRandom(seed) * 6) + 1;
  let win = false;
  let multiplier = 0;

  if (betType === 'exact' && roll === betValue) {
    win = true; multiplier = 5;
  } else if (betType === 'high' && roll >= 4) {
    win = true; multiplier = 1.9;
  } else if (betType === 'low' && roll <= 3) {
    win = true; multiplier = 1.9;
  } else if (betType === 'odd' && roll % 2 !== 0) {
    win = true; multiplier = 1.9;
  } else if (betType === 'even' && roll % 2 === 0) {
    win = true; multiplier = 1.9;
  }

  return { roll, win, multiplier, payout: win ? Math.floor(multiplier) : 0 };
}

function resolveCrash(seed) {
  const r = seededRandom(seed);
  // House edge ~2%: crash point formula
  const crashPoint = Math.max(1.0, (1 / (1 - r * 0.98)));
  return Math.round(crashPoint * 100) / 100;
}

function resolveRoulette(seed, betType, betValue) {
  const roll = Math.floor(seededRandom(seed) * 37); // 0-36
  const RED = [1,3,5,7,9,12,14,16,18,19,21,23,25,27,30,32,34,36];
  let win = false;
  let multiplier = 0;

  if (betType === 'number' && roll === betValue) { win = true; multiplier = 35; }
  else if (betType === 'red' && RED.includes(roll)) { win = true; multiplier = 1; }
  else if (betType === 'black' && roll !== 0 && !RED.includes(roll)) { win = true; multiplier = 1; }
  else if (betType === 'even' && roll !== 0 && roll % 2 === 0) { win = true; multiplier = 1; }
  else if (betType === 'odd' && roll % 2 !== 0) { win = true; multiplier = 1; }
  else if (betType === 'low' && roll >= 1 && roll <= 18) { win = true; multiplier = 1; }
  else if (betType === 'high' && roll >= 19) { win = true; multiplier = 1; }

  return { roll, win, multiplier, payout: win ? multiplier + 1 : 0 };
}

function resolveBlackjack(seed) {
  const suits = ['♠','♥','♦','♣'];
  const values = ['2','3','4','5','6','7','8','9','10','J','Q','K','A'];
  const deck = suits.flatMap(s => values.map(v => ({ suit: s, value: v })));

  // Shuffle using seed
  for (let i = deck.length - 1; i > 0; i--) {
    const j = Math.floor(seededRandom(seed, i) * (i + 1));
    [deck[i], deck[j]] = [deck[j], deck[i]];
  }

  const cardValue = (card) => {
    if (['J','Q','K'].includes(card.value)) return 10;
    if (card.value === 'A') return 11;
    return parseInt(card.value);
  };

  const playerHand = [deck[0], deck[2]];
  const dealerHand = [deck[1], deck[3]];
  const playerScore = playerHand.reduce((sum, c) => sum + cardValue(c), 0);
  const dealerScore = dealerHand.reduce((sum, c) => sum + cardValue(c), 0);

  let result = 'lose';
  let multiplier = 0;
  if (playerScore === 21) { result = 'blackjack'; multiplier = 2.5; }
  else if (playerScore > dealerScore || dealerScore > 21) { result = 'win'; multiplier = 2; }
  else if (playerScore === dealerScore) { result = 'push'; multiplier = 1; }

  return { playerHand, dealerHand, playerScore, dealerScore, result, multiplier };
}

// ── API Routes ────────────────────────────────────────────────────────────────

// GET treasury address & balance
app.get('/api/treasury', async (req, res) => {
  try {
    const balance = await getBalance(TREASURY_ADDRESS);
    res.json({
      address: TREASURY_ADDRESS,
      balance,
      explorerUrl: `${EXPLORER}/v2/account/${TREASURY_ADDRESS}`
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET wallet balance
app.get('/api/balance/:address', async (req, res) => {
  try {
    const balance = await getBalance(req.params.address);
    res.json({ address: req.params.address, balance });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST place a bet — verify tx on-chain, run game, pay out if win
// Body: { playerAddress, betTxSignature, betAmount, game, betType, betValue }
app.post('/api/bet', async (req, res) => {
  const { playerAddress, betTxSignature, betAmount, game, betType, betValue } = req.body;

  if (!playerAddress || !betTxSignature || !betAmount || !game) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    // 1. Verify bet transaction on-chain
    let txData = null;
    let attempts = 0;
    while (!txData && attempts < 15) {
      txData = await getTransaction(betTxSignature);
      if (!txData) await new Promise(r => setTimeout(r, 2000));
      attempts++;
    }

    if (!txData) {
      return res.status(400).json({ error: 'Bet transaction not confirmed on chain. Please try again.' });
    }

    // 2. Use the tx blockhash as provably fair seed
    const seed = betTxSignature; // The tx signature itself is the randomness seed

    // 3. Run game
    let result;
    switch (game) {
      case 'dice':
        result = resolveDice(seed, betType, parseInt(betValue));
        break;
      case 'crash':
        result = { crashPoint: resolveCrash(seed) };
        break;
      case 'roulette':
        result = resolveRoulette(seed, betType, parseInt(betValue));
        break;
      case 'blackjack':
        result = resolveBlackjack(seed);
        break;
      default:
        return res.status(400).json({ error: 'Unknown game' });
    }

    // 4. Pay out if win
    let payoutTxSignature = null;
    const payout = result.payout ?? result.multiplier ?? 0;

    if (payout > 0 && treasuryKeypair) {
      const payoutLamports = Math.floor(betAmount * payout);
      try {
        const txBase64 = await buildPayoutTx(playerAddress, payoutLamports);
        const submitResult = await submitTransaction(txBase64);
        payoutTxSignature = submitResult?.signature ?? submitResult?.result ?? null;
      } catch (payoutErr) {
        console.error('Payout failed:', payoutErr.message);
      }
    }

    // 5. Return result
    res.json({
      success: true,
      game,
      seed, // Player can verify: same seed + same game = same result
      result,
      payout,
      betAmount,
      payoutAmount: payout > 0 ? Math.floor(betAmount * payout) : 0,
      betTxSignature,
      payoutTxSignature,
      explorerBase: `${EXPLORER}/v2/tx`,
      verifyUrl: payoutTxSignature
        ? `${EXPLORER}/v2/tx/${payoutTxSignature}`
        : null
    });

  } catch (e) {
    console.error('Bet error:', e);
    res.status(500).json({ error: e.message });
  }
});

// POST faucet request (testnet only)
app.post('/api/faucet', async (req, res) => {
  const { address, amount = 10 } = req.body;
  if (!address) return res.status(400).json({ error: 'Address required' });
  try {
    const fetchRes = await fetch(`${XERIS_NET}/airdrop/${address}/${amount}`);
    const data = await fetchRes.json();
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET network stats
app.get('/api/stats', async (req, res) => {
  try {
    const fetchRes = await fetch(`${XERIS_API}/v2/stats`);
    const data = await fetchRes.json();
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Serve frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`XERIS.PLAY casino running on port ${PORT}`);
  console.log(`Treasury: ${TREASURY_ADDRESS}`);
});
