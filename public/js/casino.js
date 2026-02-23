/**
 * XERIS.PLAY — Browser Wallet
 * Supports BIP39 seed phrase import (same as Xeris Wallet app)
 * Derivation: m/44'/501'/0'/0' (Solana standard)
 */

const XERIS_API = 'http://138.197.116.81:50008';
const XERIS_NET = 'http://138.197.116.81:56001';
const LAMPORTS_PER_XRS = 1_000_000_000;

const XerisWallet = {
  keypair: null,

  async fromSeedPhrase(mnemonic) {
    const words = mnemonic.trim().toLowerCase().split(/\s+/);
    if (words.length !== 12 && words.length !== 24) {
      throw new Error('Seed phrase must be 12 or 24 words');
    }
    const seed = await bip39.mnemonicToSeed(mnemonic.trim());
    const derived = ed25519.derivePath("m/44'/501'/0'/0'", seed.toString('hex'));
    const kp = nacl.sign.keyPair.fromSeed(derived.key);
    this.keypair = kp;
    this._saveToSession(kp);
    return kp;
  },

  generateKeypair() {
    const kp = nacl.sign.keyPair();
    this.keypair = kp;
    this._saveToSession(kp);
    return kp;
  },

  loadFromSession() {
    try {
      const stored = sessionStorage.getItem('xrs_wallet');
      if (!stored) return null;
      const { secretKey } = JSON.parse(stored);
      const sk = new Uint8Array(secretKey);
      const kp = nacl.sign.keyPair.fromSecretKey(sk);
      this.keypair = kp;
      return kp;
    } catch { return null; }
  },

  _saveToSession(kp) {
    sessionStorage.setItem('xrs_wallet', JSON.stringify({
      secretKey: Array.from(kp.secretKey)
    }));
  },

  getAddress() {
    if (!this.keypair) return null;
    return bs58.encode(this.keypair.publicKey);
  },

  disconnect() {
    this.keypair = null;
    sessionStorage.removeItem('xrs_wallet');
  },

  async getBalance(address) {
    const addr = address || this.getAddress();
    if (!addr) return 0;
    try {
      const res = await fetch('/api/balance/' + addr);
      const data = await res.json();
      return data.balance || 0;
    } catch { return 0; }
  },

  toXRS(lamports) { return (lamports / LAMPORTS_PER_XRS).toFixed(4); },
  toLamports(xrs) { return Math.floor(parseFloat(xrs) * LAMPORTS_PER_XRS); },

  async buildSignedTx(toAddress, amountLamports) {
    if (!this.keypair) throw new Error('Wallet not connected');
    const rpcRes = await fetch(XERIS_API + '/rpc', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getLatestBlockhash', params: [] })
    });
    const rpcData = await rpcRes.json();
    const blockhash = rpcData.result?.blockhash ?? rpcData.result;
    const transaction = {
      recentBlockhash: blockhash,
      instructions: [{ from: this.getAddress(), to: toAddress, amount: amountLamports }]
    };
    const message = new TextEncoder().encode(JSON.stringify(transaction));
    const signature = nacl.sign.detached(message, this.keypair.secretKey);
    const txPayload = {
      ...transaction,
      signature: btoa(String.fromCharCode(...signature)),
      publicKey: this.getAddress()
    };
    return btoa(JSON.stringify(txPayload));
  },

  async sendToTreasury(treasuryAddress, amountXRS) {
    const amountLamports = this.toLamports(amountXRS);
    const txBase64 = await this.buildSignedTx(treasuryAddress, amountLamports);
    const res = await fetch(XERIS_NET + '/submit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tx_base64: txBase64 })
    });
    const result = await res.json();
    const sig = result?.signature ?? result?.result ?? result?.id ?? null;
    if (!sig) throw new Error('Transaction failed: ' + JSON.stringify(result));
    return sig;
  },

  async requestFaucet(amount = 10) {
    const address = this.getAddress();
    if (!address) throw new Error('No wallet connected');
    const res = await fetch('/api/faucet', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ address, amount })
    });
    return res.json();
  }
};

const WalletUI = {
  async init(onConnect) {
    this.onConnect = onConnect;
    const kp = XerisWallet.loadFromSession();
    if (kp) { await this.onWalletReady(); return; }
    this.renderConnectModal();
  },

  renderConnectModal() {
    document.getElementById('wallet-modal')?.remove();
    const modal = document.createElement('div');
    modal.id = 'wallet-modal';
    modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.9);z-index:9999;display:flex;align-items:center;justify-content:center;padding:16px;';
    modal.innerHTML = `
      <div style="background:#0d0d1a;border:1px solid #c8ff00;border-radius:16px;padding:28px;max-width:440px;width:100%;color:#fff;font-family:inherit;">
        <h2 style="color:#c8ff00;margin:0 0 6px;font-size:22px;">Connect Wallet</h2>
        <p style="color:#888;margin:0 0 20px;font-size:13px;">Enter your Xeris Wallet seed phrase to connect and play.</p>
        <p style="color:#aaa;font-size:13px;margin:0 0 8px;">🔑 12 or 24-word seed phrase:</p>
        <textarea id="seed-input" rows="4" placeholder="word1 word2 word3 ..."
          style="width:100%;padding:12px;background:#111;border:1px solid #333;border-radius:8px;color:#fff;font-size:13px;resize:none;box-sizing:border-box;font-family:monospace;margin-bottom:8px;"></textarea>
        <button id="btn-seed" style="width:100%;padding:14px;background:#c8ff00;color:#000;border:none;border-radius:8px;font-weight:700;font-size:15px;cursor:pointer;margin-bottom:16px;">
          Connect with Seed Phrase
        </button>
        <div style="border-top:1px solid #1a1a2e;padding-top:16px;">
          <p style="color:#555;font-size:12px;margin:0 0 10px;">Or generate a fresh wallet (for testing only):</p>
          <button id="btn-generate" style="width:100%;padding:11px;background:#0a0a18;color:#c8ff00;border:1px solid #c8ff00;border-radius:8px;font-weight:600;cursor:pointer;font-size:14px;">
            ⚡ Generate New Wallet
          </button>
        </div>
        <p style="color:#444;font-size:11px;margin:16px 0 0;text-align:center;">Your seed phrase is processed locally and never sent to any server.</p>
        <div id="wallet-error" style="color:#ff4444;font-size:13px;margin-top:8px;display:none;"></div>
      </div>
    `;
    document.body.appendChild(modal);

    document.getElementById('btn-seed').onclick = async () => {
      const mnemonic = document.getElementById('seed-input').value.trim();
      const errEl = document.getElementById('wallet-error');
      const btn = document.getElementById('btn-seed');
      if (!mnemonic) return;
      btn.disabled = true; btn.textContent = 'Deriving keys...'; errEl.style.display = 'none';
      try {
        await XerisWallet.fromSeedPhrase(mnemonic);
        modal.remove();
        await this.onWalletReady();
      } catch (e) {
        errEl.textContent = '❌ ' + e.message;
        errEl.style.display = 'block';
        btn.disabled = false; btn.textContent = 'Connect with Seed Phrase';
      }
    };

    document.getElementById('btn-generate').onclick = async () => {
      XerisWallet.generateKeypair();
      modal.remove();
      await this.onWalletReady();
    };
  },

  async onWalletReady() {
    const address = XerisWallet.getAddress();
    const balance = await XerisWallet.getBalance();
    this.renderWalletBar(address, balance);
    if (this.onConnect) this.onConnect({ address, balance });
  },

  renderWalletBar(address, balance) {
    let bar = document.getElementById('wallet-bar');
    if (!bar) {
      bar = document.createElement('div');
      bar.id = 'wallet-bar';
      bar.style.cssText = 'position:fixed;top:0;left:0;right:0;background:#07070f;border-bottom:1px solid #1a1a2e;padding:8px 16px;display:flex;align-items:center;justify-content:space-between;z-index:1000;font-size:13px;font-family:inherit;';
      document.body.style.paddingTop = '48px';
      document.body.prepend(bar);
    }
    const short = address ? address.slice(0,6) + '...' + address.slice(-4) : '';
    bar.innerHTML = `
      <span style="color:#c8ff00;font-weight:700;font-size:14px;">XERIS.PLAY</span>
      <div style="display:flex;gap:10px;align-items:center;">
        <span id="wallet-balance" style="color:#aaa;">${XerisWallet.toXRS(balance)} XRS</span>
        <span style="background:#111;border:1px solid #2a2a3a;padding:5px 12px;border-radius:20px;color:#fff;cursor:pointer;font-size:12px;" title="${address}" onclick="WalletUI.showWalletDetails()">${short}</span>
        <button onclick="WalletUI.showFaucet()" style="background:transparent;border:1px solid #c8ff00;color:#c8ff00;padding:5px 10px;border-radius:20px;cursor:pointer;font-size:11px;">Faucet</button>
      </div>
    `;
  },

  async refreshBalance() {
    const balance = await XerisWallet.getBalance();
    const el = document.getElementById('wallet-balance');
    if (el) el.textContent = XerisWallet.toXRS(balance) + ' XRS';
    return balance;
  },

  showWalletDetails() {
    const address = XerisWallet.getAddress();
    const modal = document.createElement('div');
    modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.85);z-index:9999;display:flex;align-items:center;justify-content:center;padding:16px;';
    modal.innerHTML = `
      <div style="background:#0d0d1a;border:1px solid #333;border-radius:16px;padding:24px;max-width:400px;width:100%;color:#fff;">
        <h3 style="color:#c8ff00;margin:0 0 16px;">Your Wallet</h3>
        <p style="font-size:11px;color:#888;margin:0 0 4px;">Address:</p>
        <p style="font-size:12px;word-break:break-all;background:#111;padding:10px;border-radius:8px;cursor:pointer;margin:0 0 12px;" onclick="navigator.clipboard.writeText('${address}').then(()=>alert('Copied!'))">${address} 📋</p>
        <a href="http://138.197.116.81:50008/v2/account/${address}" target="_blank" style="display:block;color:#c8ff00;font-size:13px;margin-bottom:16px;">🔍 View on Explorer →</a>
        <div style="display:flex;gap:8px;">
          <button onclick="this.closest('div[style]').remove()" style="flex:1;padding:10px;background:#111;border:1px solid #333;color:#fff;border-radius:8px;cursor:pointer;">Close</button>
          <button onclick="XerisWallet.disconnect();sessionStorage.clear();location.reload()" style="flex:1;padding:10px;background:#1a0a0a;border:1px solid #ff4444;color:#ff4444;border-radius:8px;cursor:pointer;">Disconnect</button>
        </div>
      </div>
    `;
    document.body.appendChild(modal);
    modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
  },

  async showFaucet() {
    if (!confirm('Request 10 XRS from the testnet faucet?')) return;
    try {
      const result = await XerisWallet.requestFaucet(10);
      alert('Faucet: ' + JSON.stringify(result));
      await this.refreshBalance();
    } catch (e) { alert('Error: ' + e.message); }
  }
};

const Casino = {
  treasury: null,

  async init() {
    try {
      const res = await fetch('/api/treasury');
      this.treasury = await res.json();
    } catch (e) { console.error('Treasury load failed:', e); }
  },

  async placeBet({ game, betAmountXRS, betType, betValue }) {
    if (!XerisWallet.keypair) throw new Error('Wallet not connected');
    if (!this.treasury?.address) throw new Error('Treasury not configured');
    const amountLamports = XerisWallet.toLamports(betAmountXRS);
    const balance = await XerisWallet.getBalance();
    if (balance < amountLamports) throw new Error('Insufficient balance. You have ' + XerisWallet.toXRS(balance) + ' XRS, need ' + betAmountXRS + ' XRS');
    const betTxSignature = await XerisWallet.sendToTreasury(this.treasury.address, betAmountXRS);
    const res = await fetch('/api/bet', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ playerAddress: XerisWallet.getAddress(), betTxSignature, betAmount: amountLamports, game, betType, betValue })
    });
    const result = await res.json();
    if (!result.success) throw new Error(result.error || 'Bet resolution failed');
    await WalletUI.refreshBalance();
    return result;
  },

  txLinksHTML(betSig, payoutSig) {
    const base = 'http://138.197.116.81:50008/v2/tx/';
    return `
      <div style="margin-top:12px;padding:10px;background:#0a0a18;border-radius:8px;border:1px solid #1a1a2e;font-size:12px;">
        <p style="color:#888;margin:0 0 6px;">🔗 On-chain proof:</p>
        <a href="${base}${betSig}" target="_blank" style="display:block;color:#c8ff00;margin-bottom:4px;">↗ Bet Transaction</a>
        ${payoutSig ? '<a href="' + base + payoutSig + '" target="_blank" style="display:block;color:#00ff88;">↗ Payout Transaction</a>' : ''}
      </div>
    `;
  }
};
