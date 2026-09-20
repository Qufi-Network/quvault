import {
  accountFrom, accountsFrom, checkAuthorization, clearRecord, decryptMnemonic, encryptMnemonic, fromBase64,
  jitterFrom, loadRecord, makeMnemonic, planDigest, saveRecord, signPlan,
} from '/vendor/wallet.js';

const $ = id => document.getElementById(id);

const VIEWS = ['loading', 'setup', 'signin', 'create', 'wallet'];
const TABS = ['dashboard', 'send', 'receive', 'settings'];
const RANGES = [
  { key: 'day', label: 'Day', seconds: 86_400 },
  { key: 'week', label: 'Week', seconds: 7 * 86_400 },
  { key: 'month', label: 'Month', seconds: 30 * 86_400 },
  { key: 'max', label: '3M', seconds: 120 * 86_400 },
];

const state = { config: null, data: null, price: null, range: 'week', loginNonce: null, draft: null, account: 'bitcoin' };

// A letter for each network, so an account is recognisable before its name is read.
const MARKS = { bitcoin: '₿', ethereum: 'Ξ', tron: 'T', solana: '◎', stellar: '✦' };
let active = null; // the approval currently shown in the sheet

/* ------------------------------------------------------------ helpers */

async function api(path, body) {
  const response = await fetch(path, {
    method: body === undefined ? 'GET' : 'POST',
    headers: body === undefined ? {} : { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const out = await response.json().catch(() => ({}));
  if (!response.ok) throw Object.assign(new Error(out.error || 'Something went wrong.'), { status: response.status });
  return out;
}

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value == null || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
    // Through the style object, not a style attribute, which the page's security policy blocks.
    else if (key === 'style') Object.assign(node.style, value);
    else node.setAttribute(key, value);
  }
  node.append(...children.flat().filter(child => child != null && child !== false));
  return node;
}

const button = (label, className, onClick) => el('button', { type: 'button', class: className, onclick: onClick }, label);
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
const btc = sats => (sats / 1e8).toFixed(8);
const fmtSats = sats => Number(sats).toLocaleString('en-US');
const usd = value => `$${Math.round(value).toLocaleString('en-US')}`;
const shortId = id => `${id.slice(0, 10)}…${id.slice(-6)}`;
const when = seconds => new Date(seconds * 1000).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });

function friendly(error) {
  if (error?.code === 'popup_blocked') return 'Your browser blocked the Veyns window. Allow pop-ups for this site, then try again.';
  if (error instanceof SyntaxError) return `Veyns refused this site. Register ${location.origin} exactly as a website origin in the Veyns console.`;
  return error?.message || 'Something went wrong.';
}

let toastTimer;
function toast(message) {
  const node = $('toast');
  node.textContent = message;
  node.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { node.hidden = true; }, 6000);
}

function show(view) {
  for (const name of VIEWS) $(`view-${name}`).hidden = name !== view;
  $('who').hidden = view !== 'wallet' && view !== 'create';
}

let sdkPromise = null;
function loadSdk() {
  sdkPromise ??= new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = `${state.config.issuer}/veyns.js`;
    script.onload = () => (window.veyns ? resolve(window.veyns) : reject(new Error('Veyns did not load.')));
    script.onerror = () => {
      sdkPromise = null;
      script.remove();
      reject(new Error('Could not reach Veyns. Check your connection and try again.'));
    };
    document.head.append(script);
  });
  return sdkPromise;
}

/* --------------------------------------------------------------- boot */

async function boot() {
  show('loading');
  $('loading-text').textContent = 'Loading…';
  $('retry').hidden = true;
  try {
    state.config = await api('/api/config');
    $('network-chip').textContent = state.config.network;
    $('pitch-network').textContent = state.config.network;
    if (!state.config.configured || !state.config.vaultReady || !state.config.palmEnabled) return showSetup();
    loadSdk().catch(() => {});
    let redirectError = '';
    try {
      await finishRedirectSignIn();
    } catch (error) {
      redirectError = friendly(error);
    }
    await refresh();
    if (redirectError) $('signin-error').textContent = redirectError;
  } catch (error) {
    $('loading-text').textContent = friendly(error);
    $('retry').hidden = false;
  }
}

async function refresh() {
  let data;
  try {
    data = await api('/api/wallet');
  } catch (error) {
    if (error.status === 401) return showSignin();
    throw error;
  }
  state.data = data;
  await device.load();
  if (!data.wallet) {
    $('my-code').textContent = data.me.code;
    renderRequests($('create-pending'), data.pending);
    show('create');
    return;
  }
  renderWallet(data);
  show('wallet');
  setTab(location.hash.slice(1) || 'dashboard', { remember: false });
}

function showSetup() {
  const { configured, vaultReady, palmEnabled } = state.config;
  const missing = [
    !configured && ['A Veyns application', 'Register this app in the Veyns console and set ', 'VEYNS_CLIENT_ID'],
    !palmEnabled && ['A Veyns backend credential', 'Palm approvals need ', 'VEYNS_BACKEND_SECRET'],
    !vaultReady && ['A vault seed', 'Run npm run keygen and set ', 'WALLET_SEED'],
  ].filter(Boolean);
  $('setup-steps').replaceChildren(...missing.map(([title, text, code]) =>
    el('li', {}, el('b', {}, title), ': ', text, el('code', {}, code))));
  show('setup');
}

/* ------------------------------------------------------- dashboard tabs */

function setTab(name, { remember = true } = {}) {
  const tab = TABS.includes(name) ? name : 'dashboard';
  for (const pane of document.querySelectorAll('.pane')) pane.hidden = pane.dataset.pane !== tab;
  for (const node of document.querySelectorAll('.side .tab')) {
    const active = node.dataset.tab === tab;
    node.classList.toggle('active', active);
    node.setAttribute('aria-current', active ? 'page' : 'false');
  }
  if (tab === 'dashboard') loadPrice();
  if (remember && location.hash.slice(1) !== tab) history.replaceState(null, '', `#${tab}`);
}

for (const node of document.querySelectorAll('.side .tab')) {
  node.addEventListener('click', () => setTab(node.dataset.tab));
}
addEventListener('hashchange', () => setTab(location.hash.slice(1), { remember: false }));

/* ------------------------------------------------------ sign-in */

async function showSignin() {
  show('signin');
  $('signin-browser').hidden = state.config.requirePalmSignin;
  $('signin-browser').disabled = $('signin-palm').disabled = true;
  try {
    const [{ nonce }] = await Promise.all([api('/api/login/start', {}), loadSdk()]);
    state.loginNonce = nonce;
    $('signin-browser').disabled = $('signin-palm').disabled = false;
  } catch (error) {
    $('signin-error').textContent = friendly(error);
  }
}

async function signIn(method) {
  const nonce = state.loginNonce;
  if (!nonce || !window.veyns) return;
  state.loginNonce = null;
  $('signin-error').textContent = '';
  $('signin-browser').disabled = $('signin-palm').disabled = true;
  try {
    const { token } = await window.veyns.signin({
      clientId: state.config.clientId,
      nonce,
      ...(method === 'palm' ? { method: 'palm' } : {}),
    });
    await api('/api/login/finish', { token });
    await refresh();
  } catch (error) {
    if (error.code === 'popup_blocked') {
      try {
        $('signin-error').textContent = 'Opening Veyns in this tab…';
        await signInWithRedirect(method, nonce);
        return;
      } catch (redirectError) {
        $('signin-error').textContent = friendly(redirectError);
      }
    } else if (error.code !== 'cancelled') {
      $('signin-error').textContent = friendly(error);
    }
    await showSignin();
  }
}

$('signin-browser').addEventListener('click', () => signIn('browser'));
$('signin-palm').addEventListener('click', () => signIn('palm'));
$('signout').addEventListener('click', async () => {
  await api('/api/logout', {}).catch(() => {});
  state.data = null;
  await showSignin();
});

/* ------------------------------------------- sign-in without a pop-up */

const REDIRECT_KEY = 'quvault.veyns-redirect';

function randomToken(bytes) {
  const buffer = crypto.getRandomValues(new Uint8Array(bytes));
  return btoa(String.fromCharCode(...buffer)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function sha256Base64Url(text) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)));
  return btoa(String.fromCharCode(...digest)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function signInWithRedirect(method, nonce) {
  const { issuer, clientId, redirectUri } = state.config;
  const verifier = randomToken(48);
  const flowState = randomToken(16);
  try {
    sessionStorage.setItem(REDIRECT_KEY, JSON.stringify({ state: flowState, verifier }));
  } catch {
    throw new Error('This browser blocks both pop-ups and storage. Open the site in Chrome, Edge or Safari.');
  }
  const response = await fetch(`${issuer}/v1/authorize/prepare`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      response_type: 'code', response_mode: 'query', client_id: clientId, redirect_uri: redirectUri,
      scope: 'openid login', intent: 'login', state: flowState, nonce,
      code_challenge: await sha256Base64Url(verifier), code_challenge_method: 'S256',
      ...(method === 'palm' ? { required_method: 'palm' } : {}),
    }),
  });
  const prepared = await response.json();
  if (!response.ok) throw new Error(prepared.error_description || 'Veyns could not start sign-in.');
  const target = new URL(prepared.authorization_url);
  if (target.origin !== new URL(issuer).origin || target.pathname !== '/authorize') throw new Error('Veyns returned an unexpected sign-in address.');
  location.assign(target.href);
}

async function finishRedirectSignIn() {
  const params = new URLSearchParams(location.search);
  if (!params.has('state') || !(params.has('code') || params.has('error'))) return;
  history.replaceState(null, '', location.pathname);

  let saved = null;
  try {
    saved = JSON.parse(sessionStorage.getItem(REDIRECT_KEY));
    sessionStorage.removeItem(REDIRECT_KEY);
  } catch {
    // Handled below.
  }
  if (!saved || saved.state !== params.get('state')) throw new Error('That sign-in did not start in this tab. Please try again.');
  if (params.has('error')) {
    throw new Error(params.get('error') === 'access_denied' ? 'Sign-in was cancelled.' : params.get('error_description') || 'Veyns could not sign you in.');
  }

  const { issuer, clientId, redirectUri } = state.config;
  const discovery = await (await fetch(`${issuer}/.well-known/openid-configuration`)).json();
  if (new URL(discovery.token_endpoint).origin !== new URL(issuer).origin) throw new Error('Veyns returned an unexpected token address.');
  const response = await fetch(discovery.token_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code', code: params.get('code'), client_id: clientId,
      redirect_uri: redirectUri, code_verifier: saved.verifier,
    }),
  });
  const tokens = await response.json();
  if (!response.ok) throw new Error(tokens.error_description || 'Veyns could not finish sign-in. Please try again.');
  await api('/api/login/finish', { token: tokens.id_token });
}

/* ------------------------------------------------- the key, on this device */

/**
 * Everything that touches key material happens here, in the browser. The server only ever
 * sees an address, a public key, and a signed transaction it can check against the plan.
 */
const device = {
  record: null,

  async load() {
    try {
      this.record = (await loadRecord()) ?? null;
    } catch {
      this.record = null;
    }
    return this.record;
  },

  /** True when this browser holds the key for the wallet the server knows about. */
  holdsKeyFor(wallet) {
    return Boolean(this.record && wallet && this.record.address === wallet.address);
  },

  async unlockFor(operationId) {
    return api(`/api/operations/${operationId}/unlock`, {});
  },

  /** Makes the phrase and stores it encrypted, here and nowhere else. */
  async makeKey(operation) {
    const [{ random }, unlocked] = await Promise.all([api('/api/random'), this.unlockFor(operation.id)]);
    const mnemonic = makeMnemonic({
      serverRandom: fromBase64(random),
      jitter: jitterFrom([operation.id, unlocked.salt, screen.width, screen.height]),
    });
    const account = accountFrom(mnemonic);
    const blob = await encryptMnemonic(mnemonic, unlocked.unlock, unlocked.salt);
    await saveRecord({ blob, salt: unlocked.salt, address: account.address, publicKey: toHex(account.publicKey), createdAt: Date.now() });
    this.record = await loadRecord();
    return account;
  },

  /** A new vault: the server is told only the address and the public key. */
  async create(operation) {
    const account = await this.makeKey(operation);
    await api('/api/wallet/register', {
      operationId: operation.id,
      address: account.address,
      publicKey: toHex(account.publicKey),
    });
    return account;
  },

  /**
   * A vault made before keys lived here: this browser makes and saves the new key first,
   * then the server sweeps the old address and retires the key it was holding.
   */
  async moveIn(operation) {
    const account = await this.makeKey(operation);
    const result = await api('/api/wallet/upgrade', {
      operationId: operation.id,
      address: account.address,
      publicKey: toHex(account.publicKey),
    });
    return { ...result, account };
  },

  /**
   * Signs an approved withdrawal and hands the raw transaction back for broadcasting.
   * The plan is re-hashed here and compared with the digest the palm approved, so a plan
   * altered after the approval is refused by the device that holds the key.
   */
  async send(operation) {
    if (!this.record) throw new Error('This browser does not hold the key for this wallet.');
    const unlocked = await this.unlockFor(operation.id);
    const mnemonic = await decryptMnemonic(this.record.blob, unlocked.unlock, this.record.salt);
    const signed = signPlan(mnemonic, unlocked.plan, this.record.address, {
      transactionHash: unlocked.transactionHash,
      network: state.config.network,
    });
    const sent = await api(`/api/operations/${operation.id}/broadcast`, { hex: signed.hex });
    return { ...sent, receipt: await readReceipt(operation.id) };
  },

  /** Derives the address for a newly approved network and reports only the public part. */
  async addAccount(operation) {
    if (!this.record) throw new Error('This browser does not hold the key for this wallet.');
    const unlocked = await this.unlockFor(operation.id);
    const mnemonic = await decryptMnemonic(this.record.blob, unlocked.unlock, this.record.salt);
    const derived = accountsFrom(mnemonic);
    if (derived.bitcoin.address !== this.record.address) throw new Error('That phrase belongs to a different wallet.');
    const account = derived[operation.network];
    if (!account) throw new Error('This vault does not know that network.');
    await api('/api/accounts/register', {
      operationId: operation.id,
      address: account.address,
      publicKey: account.publicKey,
    });
    return account;
  },

  /** Erases the vault on the server and takes the key off this device with it. */
  async reset(operation) {
    const result = await api('/api/wallet/reset', { operationId: operation.id, ...(state.resetChoice ?? {}) });
    try {
      await clearRecord();
    } catch {
      // A browser that will not let go of its storage does not stop the vault being gone.
    }
    this.record = null;
    state.resetChoice = null;
    return result;
  },

  async phrase(operation) {
    if (!this.record) throw new Error('This browser does not hold the key for this wallet.');
    const unlocked = await this.unlockFor(operation.id);
    return decryptMnemonic(this.record.blob, unlocked.unlock, this.record.salt);
  },

  /** Puts an existing phrase back on this device, after the two-scan ceremony. */
  async restore(operation, mnemonic, expectedAddress) {
    const account = accountFrom(mnemonic);
    if (account.address !== expectedAddress) throw new Error('Those words belong to a different wallet.');
    const unlocked = await this.unlockFor(operation.id);
    const blob = await encryptMnemonic(mnemonic, unlocked.unlock, unlocked.salt);
    await saveRecord({ blob, salt: unlocked.salt, address: account.address, publicKey: toHex(account.publicKey), createdAt: Date.now() });
    this.record = await loadRecord();
  },
};

const toHex = bytes => [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');

/**
 * Fetches the authorisation receipt and checks its ML-DSA-65 signature here, in the page,
 * against the key the server published. A receipt this page cannot verify is reported as
 * unverified rather than shown as proof of anything.
 */
async function readReceipt(operationId) {
  try {
    const receipt = await api(`/api/operations/${operationId}/receipt`);
    const key = state.config.attestation?.publicKey;
    const checked = key
      ? checkAuthorization(receipt.authorization, key, { transactionHash: receipt.authorization.record.transactionHash })
      : { ok: false, reason: 'this page was not given a key to check it with' };
    return { ...receipt, checked };
  } catch (error) {
    return { error: friendly(error) };
  }
}

/* -------------------------------------------------------- the wallet */

$('create-wallet').addEventListener('click', async () => {
  $('create-error').textContent = '';
  $('create-wallet').disabled = true;
  try {
    const { operation } = await api('/api/wallet/approval', { label: $('create-label').value });
    openApproval(operation, 'Creating the vault…');
  } catch (error) {
    $('create-error').textContent = friendly(error);
  } finally {
    $('create-wallet').disabled = false;
  }
});

function renderWallet(data) {
  const { wallet, balance, spendable, coins, chainHistory, feeRate, chainError, policy, members, me } = data;
  const total = balance ? balance.confirmed + balance.pending : 0;
  const myName = members.find(m => m.id === me.id)?.label || 'there';
  const hour = new Date().getHours();
  $('greeting').textContent = `Good ${hour < 12 ? 'morning' : hour < 18 ? 'afternoon' : 'evening'}, ${myName}.`;
  const count = (data.accounts || []).length;
  $('greeting-note').textContent = `Here is the summary of your ${count} account${count === 1 ? '' : 's'}.`;

  // Totals
  $('balance').textContent = btc(total);
  const notes = [];
  if (balance?.pending) notes.push(`${fmtSats(balance.pending)} sats still unconfirmed`);
  if (coins) notes.push(`${coins} spendable coin${coins === 1 ? '' : 's'} (${fmtSats(spendable)} sats)`);
  else if (balance && !balance.txCount) notes.push('No coins yet — open Receive funds for your address.');
  notes.push(device.holdsKeyFor(wallet) ? 'Key held in this browser only' : 'Key not on this device — restore it in Settings');
  $('balance-note').textContent = notes.join(' · ');
  $('chain-error').textContent = chainError || '';
  $('fee-note').textContent = feeRate ? `Network suggests ${feeRate} sat/vB` : '';

  const spending = (data.accounts || []).find(account => account.network === 'bitcoin');
  $('send-rule-note').textContent = spending ? `Your thresholds: ${spending.rulesText}.` : '';
  $('accounts-note').textContent = `${members.length} signer${members.length === 1 ? '' : 's'} across this vault`;

  renderAccounts(data);
  renderSettings(data);
  renderAccountPanes(data);
  $('legacy-lane').hidden = wallet.custody === 'client';
  renderRequests($('pending'), data.pending);
  renderRequests($('send-pending'), data.pending.filter(op => op.kind === 'withdraw'));
  $('pending-lane').hidden = data.pending.length === 0;
  renderHistory(chainHistory || [], data.history || []);
  paintFiat();
}

/** The sidebar list and the account cards: one per network, all from the same phrase. */
function renderAccounts(data) {
  const accounts = data.accounts || [];
  if (!accounts.some(account => account.network === state.account)) {
    state.account = accounts[0]?.network || 'bitcoin';
  }

  $('account-list').replaceChildren(...accounts.map(account => el('button', {
    class: `account${account.network === state.account ? ' active' : ''}`,
    type: 'button',
    onclick: () => selectAccount(account.network),
  },
    el('span', { class: 'account-mark' }, MARKS[account.network] || account.symbol.slice(0, 1)),
    el('span', { class: 'account-text' }, el('b', {}, account.label), el('small', {}, account.chain)),
    el('span', { class: 'account-amount' }, account.formatted ?? '—'))));

  $('accounts').replaceChildren(
    ...accounts.map(account => accountCard(account, data)),
    el('button', { class: 'account-card muted add', type: 'button', onclick: openNewAccount },
      el('header', {},
        el('span', { class: 'account-mark big ghost' }, '+'),
        el('div', {}, el('b', {}, 'Add an account'), el('small', {}, 'new network'))),
      el('p', { class: 'quiet small' }, 'Ethereum, Tron, Solana or Stellar, from this same phrase and the same palm rules.')),
  );
}

function accountCard(account, data) {
  const { coins } = data;
  const bitcoin = account.network === 'bitcoin';
  return el('article', { class: `account-card${account.network === state.account ? ' active' : ''}` },
    el('header', {},
      el('span', { class: 'account-mark big' }, MARKS[account.network] || account.symbol.slice(0, 1)),
      el('div', {}, el('b', {}, `${account.label} account`), el('small', {}, account.chain)),
      el('span', { class: 'chip soft' }, bitcoin
        ? (coins ? `${coins} coin${coins === 1 ? '' : 's'}` : 'empty')
        : (account.canSend ? 'send and receive' : 'receive only'))),
    el('p', { class: 'account-balance' }, account.formatted ?? '—', el('span', { class: 'unit' }, account.symbol)),
    bitcoin ? el('p', { class: 'quiet small', id: 'account-fiat' }, '') : null,
    el('p', { class: 'quiet small' }, `${account.rulesText}`),
    el('p', { class: 'account-address' }, account.address),
    el('div', { class: 'row' },
      account.canSend ? button('Send', 'btn brand small', () => { selectAccount(account.network); setTab('send'); }) : null,
      button('Receive', 'btn ghost small', () => { selectAccount(account.network); setTab('receive'); })));
}

/** Points Send, Receive and the account details at one account. */
function selectAccount(networkId) {
  state.account = networkId;
  if (!state.data) return;
  renderAccounts(state.data);
  renderAccountPanes(state.data);
  renderSettings(state.data); // its signers and threshold are its own
}

function renderAccountPanes(data) {
  const accounts = data.accounts || [];
  const account = accounts.find(item => item.network === state.account) || accounts[0];
  if (!account) return;
  for (const node of document.querySelectorAll('.account-name')) node.textContent = `${account.label} account`;

  $('address').textContent = account.address;
  $('explorer-link').href = account.explorer;
  $('qr').innerHTML = account.qr || ''; // A QR code this server generated; no external content.
  $('receive-hint').textContent = account.network === 'bitcoin'
    ? 'Send test coins here from a testnet4 faucet. They appear after one confirmation, and receiving never needs a palm scan.'
    : `Send ${account.chain} ${account.symbol} here. The address comes from your phrase, and receiving never needs a palm scan.`;
  $('receive-note').textContent = account.network === 'bitcoin'
    ? (data.balance?.txCount ? `${data.balance.txCount} transaction${data.balance.txCount === 1 ? '' : 's'} so far.` : '')
    : `Balance ${account.formatted ?? 'unknown'} ${account.symbol}.`;

  $('send-form').hidden = !account.canSend;
  $('send-rule-note').hidden = !account.canSend;
  $('send-soon').hidden = account.canSend;
  $('send-soon').textContent = account.canSend ? ''
    : `Signing for ${account.label} is the next step. This account receives and shows its balance today; the Bitcoin account can already spend under your palm rules.`;

  $('settings-network').textContent = `${account.label} · ${account.chain}`;
  $('settings-address').textContent = account.address;
}

/* --------------------------------------------------- adding an account */

const WIZARD_STEPS = ['Network', 'Signers', 'Threshold', 'Review'];

function openNewAccount() {
  if (!state.data) return;
  $('new-account-error').textContent = '';
  // A vault that still signs on the server has no phrase for another network to come from.
  if (state.data.wallet?.custody !== 'client') {
    $('wizard-steps').replaceChildren();
    $('wizard').replaceChildren(
      el('p', { class: 'quiet' }, 'This vault was made before keys lived in the browser, so it has no recovery phrase for other networks to come from. Move it into this browser and the other accounts become available.'),
      button('Move this vault into this browser', 'btn brand wide', () => startMove($('new-account-error'))));
    $('wizard-back').hidden = true;
    $('wizard-next').hidden = true;
    $('new-account').showModal();
    return;
  }

  const me = state.data.members.find(member => member.id === state.data.me.id);
  state.wizard = {
    step: 0,
    network: null,
    signers: [{ id: state.data.me.id, label: me?.label || 'You', owner: true, palmId: me?.palmId || null }],
    approvals: 1,
  };
  drawWizard();
  $('new-account').showModal();
}

function drawWizard() {
  const wizard = state.wizard;
  const have = new Set((state.data.accounts || []).map(account => account.network));
  const choices = (state.data.networks || []).filter(network => !have.has(network.id));
  $('new-account-error').textContent = '';
  $('wizard-back').hidden = wizard.step === 0;
  $('wizard-next').hidden = wizard.step === 0;
  $('wizard-next').textContent = wizard.step === 3 ? 'Create with a palm scan' : 'Continue';

  $('wizard-steps').replaceChildren(...WIZARD_STEPS.map((label, index) => el('li', {
    class: `wizard-step${index === wizard.step ? ' on' : ''}${index < wizard.step ? ' done' : ''}`,
  }, label)));

  if (wizard.step === 0) return drawNetworkStep(choices);
  if (wizard.step === 1) return drawSignerStep();
  if (wizard.step === 2) return drawThresholdStep();
  return drawReviewStep();
}

function drawNetworkStep(choices) {
  $('wizard').replaceChildren(
    el('p', { class: 'fine' }, 'The address is derived in this browser from the same recovery phrase, on that network\'s standard path.'),
    choices.length
      ? el('div', { class: 'network-list' }, ...choices.map(network => el('button', {
        class: 'network-choice', type: 'button', onclick: () => { state.wizard.network = network; state.wizard.step = 1; drawWizard(); },
      },
        el('span', { class: 'account-mark' }, MARKS[network.id] || network.symbol.slice(0, 1)),
        el('span', { class: 'account-text' }, el('b', {}, network.label), el('small', {}, network.chain)),
        el('span', { class: 'chip soft' }, network.canSend ? 'send and receive' : 'receive'))))
      : el('p', { class: 'quiet' }, 'This vault already has an account on every network QuVault supports.'));
}

function drawSignerStep() {
  const wizard = state.wizard;
  const chosen = new Set(wizard.signers.map(signer => signer.id));
  const others = (state.data.members || []).filter(member => !chosen.has(member.id));

  const code = el('input', { placeholder: 'their approver code', autocomplete: 'off', spellcheck: 'false' });
  const label = el('input', { placeholder: 'their name', maxlength: '40' });

  // replaceChildren keeps a null as the text "null", unlike el(), so the list is filtered.
  $('wizard').replaceChildren(...[
    el('p', { class: 'fine' }, 'Everyone here can approve for this account with their palm. Each of them gets a palm ID in this vault the first time they scan.'),
    el('div', { class: 'member-rows' }, ...wizard.signers.map(signer => el('div', { class: 'member-row' },
      el('span', {},
        signer.label,
        signer.owner ? el('small', {}, 'you') : null,
        el('small', { class: 'palm-id' }, signer.palmId || 'palm id on first scan')),
      signer.owner ? el('span', { class: 'quiet small' }, 'always a signer') : button('Remove', 'link', () => {
        wizard.signers = wizard.signers.filter(s => s.id !== signer.id);
        wizard.approvals = Math.min(wizard.approvals, wizard.signers.length);
        drawWizard();
      })))),
    others.length ? el('div', { class: 'row' }, el('span', { class: 'quiet small' }, 'Already in this vault:'),
      ...others.map(member => button(`+ ${member.label}`, 'chip pick', () => {
        wizard.signers.push({ id: member.id, label: member.label, owner: false, palmId: member.palmId, existing: true });
        drawWizard();
      }))) : null,
    el('div', { class: 'two' }, el('div', {}, el('label', {}, 'Add by approver code'), code), el('div', {}, el('label', {}, 'Their name'), label)),
    button('Add signer', 'btn ghost small', () => {
      const id = code.value.trim();
      const name = label.value.trim();
      if (!id || !name) {
        $('new-account-error').textContent = 'Enter both the approver code and a name.';
        return;
      }
      wizard.signers.push({ id, label: name, owner: false, palmId: null, isNew: true });
      drawWizard();
    }),
  ].filter(Boolean));
}

function drawThresholdStep() {
  const wizard = state.wizard;
  const count = wizard.signers.length;
  wizard.approvals = Math.min(Math.max(1, wizard.approvals), count);
  $('wizard').replaceChildren(
    el('p', { class: 'fine' }, 'How many of those palms have to approve before anything moves from this account — and before these settings can be changed again.'),
    el('div', { class: 'presets' }, ...Array.from({ length: count }, (_, i) => i + 1).map(m =>
      button(`${m} of ${count}`, `chip pick${wizard.approvals === m ? ' on' : ''}`, () => { wizard.approvals = m; drawWizard(); }))),
    el('p', { class: 'quiet small' }, count === 1
      ? 'One palm: yours. You can add signers later, and that change will need your palm.'
      : `${wizard.approvals} of ${count} palms. Changing this afterwards will need ${wizard.approvals} of them.`),
    el('p', { class: 'fine' }, 'Different thresholds for larger amounts can be set in Settings once the account exists.'));
}

function drawReviewStep() {
  const wizard = state.wizard;
  const count = wizard.signers.length;
  $('wizard').replaceChildren(
    el('dl', { class: 'details' },
      el('div', {}, el('dt', {}, 'Network'), el('dd', {}, `${wizard.network.label} ${wizard.network.chain}`)),
      el('div', {}, el('dt', {}, 'Address from'), el('dd', {}, 'the same recovery phrase')),
      el('div', {}, el('dt', {}, 'Signers'), el('dd', {}, wizard.signers.map(s => s.label).join(', '))),
      el('div', {}, el('dt', {}, 'Threshold'), el('dd', {}, `${wizard.approvals} of ${count}`)),
      el('div', {}, el('dt', {}, 'Sending'), el('dd', {}, wizard.network.canSend ? 'live' : 'receive and balances today'))),
    el('p', { class: 'fine' }, 'Creating the account takes a palm approval from the signers who guard this vault today.'));
}

$('wizard-back').addEventListener('click', () => {
  state.wizard.step = Math.max(0, state.wizard.step - 1);
  drawWizard();
});

$('wizard-next').addEventListener('click', async () => {
  const wizard = state.wizard;
  if (wizard.step < 3) {
    wizard.step += 1;
    drawWizard();
    return;
  }
  $('new-account-error').textContent = '';
  $('wizard-next').disabled = true;
  try {
    const { operation } = await api('/api/accounts/approval', {
      network: wizard.network.id,
      add: wizard.signers.filter(s => s.isNew).map(s => ({ code: s.id, label: s.label })),
      signers: wizard.signers.filter(s => s.existing).map(s => s.id),
      rules: [{ upToSats: null, approvals: wizard.approvals }],
    });
    $('new-account').close();
    openApproval(operation, `Adding the ${wizard.network.label} account…`);
  } catch (error) {
    $('new-account-error').textContent = friendly(error);
  } finally {
    $('wizard-next').disabled = false;
  }
});

$('add-account').addEventListener('click', openNewAccount);
$('new-account-cancel').addEventListener('click', () => $('new-account').close());

/* ------------------------------------------- moving an older vault in */

async function startMove(errorNode) {
  errorNode.textContent = '';
  try {
    const { operation } = await api('/api/wallet/upgrade/approval', {});
    $('new-account').close();
    openApproval(operation, 'Moving the vault into this browser…');
  } catch (error) {
    errorNode.textContent = friendly(error);
  }
}

$('legacy-move').addEventListener('click', () => startMove($('legacy-error')));

/* ------------------------------------------------------- starting over */

function openReset() {
  const data = state.data;
  if (!data?.wallet) return;
  const account = (data.accounts || []).find(item => item.network === 'bitcoin');
  const holding = Number(account?.amount ?? 0);
  const server = data.wallet.custody !== 'client';

  $('reset-error').textContent = '';
  $('reset-dialog-error').textContent = '';
  $('reset-to').value = '';
  $('reset-accept').checked = false;
  $('reset-details').replaceChildren(...detailRows({
    address: data.wallet.address,
    holds: `${account?.formatted ?? '0.00000000'} tBTC`,
    accounts: (data.accounts || []).map(item => item.label).join(', '),
    signers: data.members.map(member => member.label).join(', '),
    erases: server
      ? 'the key held for this vault, its accounts, signers and history'
      : 'the key in this browser, its accounts, signers and history',
  }));
  // Only a vault the server can still sign for can sweep its coins on the way out.
  $('reset-coins').hidden = holding <= 0;
  $('reset-to').hidden = !server;
  $('reset-to').previousElementSibling?.toggleAttribute('hidden', !server);
  $('reset').showModal();
}

$('reset-vault').addEventListener('click', openReset);
$('reset-cancel').addEventListener('click', () => $('reset').close());

$('reset-form').addEventListener('submit', async event => {
  event.preventDefault();
  $('reset-dialog-error').textContent = '';
  const sweepTo = $('reset-to').hidden ? '' : $('reset-to').value.trim();
  const accept = $('reset-accept').checked;
  if (!$('reset-coins').hidden && !sweepTo && !accept) {
    $('reset-dialog-error').textContent = 'Give an address for the coins, or tick the box to let them go.';
    return;
  }
  state.resetChoice = { ...(sweepTo ? { sweepTo } : {}), ...(accept ? { acceptLoss: true } : {}) };
  try {
    const { operation } = await api('/api/wallet/reset/approval', {});
    $('reset').close();
    openApproval(operation, 'Erasing the vault…');
  } catch (error) {
    $('reset-dialog-error').textContent = friendly(error);
  }
});
$('move-vault').addEventListener('click', () => startMove($('device-error')));

function renderRequests(container, requests) {
  const { me, labels = {} } = state.data;
  container.replaceChildren(...requests.map(op => {
    const done = op.approvedBy.length;
    const mine = op.mine;
    const actions = el('div', { class: 'row' });
    if (op.status === 'collecting' && (!mine || mine.status !== 'approved')) {
      actions.append(button('Approve with palm', 'btn brand small', () => openApproval(op, busyText(op))));
    } else if (mine?.status === 'approved') {
      actions.append(el('span', { class: 'quiet' }, 'You approved. Waiting for the others.'));
    }
    if (op.startedBy === me.id || op.walletOwner === me.id) {
      actions.append(button('Cancel', 'btn ghost small', () => cancelRequest(op)));
    }
    return el('article', { class: 'request' },
      el('p', { class: 'request-what' }, op.statement),
      el('p', { class: 'quiet small' }, [
        `${done} of ${op.required} approval${op.required === 1 ? '' : 's'}`,
        done ? `by ${op.approvedBy.map(id => labels[id] || 'someone').join(', ')}` : null,
        op.status === 'running' ? 'running' : null,
      ].filter(Boolean).join(' · ')),
      el('div', { class: 'meter', 'aria-hidden': 'true' }, el('span', { style: { width: `${Math.min(100, (done / op.required) * 100)}%` } })),
      actions);
  }));
}

const BUSY = {
  create: 'Creating the vault…', withdraw: 'Sending…', policy: 'Applying the new settings…',
  account: 'Adding the account…', recovery: 'Opening your phrase…', upgrade: 'Moving the vault into this browser…',
  reset: 'Erasing the vault…',
};
const busyText = op => BUSY[op.kind] || 'Working…';

function renderHistory(chain, operations) {
  const rows = operations.filter(op => op.kind !== 'create').map(op => el('li', {},
    el('span', { class: 'what' },
      op.statement,
      el('small', {}, op.error || (op.txid ? shortId(op.txid) : op.status)),
      op.humanVerified
        ? button('Human verified · receipt', 'link small', async () => {
          const receipt = await readReceipt(op.id);
          if (receipt.error) return toast(receipt.error);
          showReceipt(receipt, op.txid);
        })
        : null),
    el('time', {}, when(op.createdAt)),
    el('span', { class: `amt ${op.status === 'done' ? '' : 'failed'}` }, op.status === 'done' ? 'approved' : op.status)));

  const received = chain.map(tx => el('li', {},
    el('span', { class: 'what' }, tx.deltaSats > 0 ? 'Received' : 'Sent',
      el('small', {}, shortId(tx.txid), tx.confirmed ? '' : ' · waiting for confirmation')),
    el('time', {}, tx.at ? when(tx.at) : 'pending'),
    el('a', { class: `amt ${tx.deltaSats > 0 ? 'plus' : 'minus'}`, href: tx.explorer, target: '_blank', rel: 'noopener' },
      `${tx.deltaSats > 0 ? '+' : '−'}${btc(Math.abs(tx.deltaSats))}`)));

  const all = [...rows, ...received];
  $('history').replaceChildren(...(all.length ? all : [el('li', { class: 'empty' }, 'Nothing yet.')]));
}

$('copy-address').addEventListener('click', () => copy($('address').textContent, 'Address copied.'));
$('copy-code').addEventListener('click', () => copy($('my-code').textContent, 'Approver code copied.'));

async function copy(text, message) {
  try {
    await navigator.clipboard.writeText(text);
    toast(message);
  } catch {
    toast('Select it and copy manually.');
  }
}

/* ----------------------------------------------------------- settings */

/** The editable copy of one account's signers and thresholds, rebuilt from the server view. */
function renderSettings(data) {
  const { me, wallet } = data;
  const account = (data.accounts || []).find(item => item.network === state.account) || data.accounts?.[0];
  $('my-code').textContent = me.code;
  $('settings-protection').textContent = wallet.protection;

  const legacy = wallet.custody !== 'client';
  const holds = device.holdsKeyFor(wallet);
  $('device-state').textContent = legacy
    ? 'This vault was made before keys lived in the browser: its key is sealed on the server, so there is no recovery phrase and no other-network accounts.'
    : holds
      ? 'This browser holds the key for this wallet. The server has never seen it.'
      : 'This browser does not hold the key. Restore it here with your twelve words, or use the browser that made the wallet.';
  $('show-phrase').hidden = legacy || !holds;
  $('restore-device').hidden = legacy || holds;
  $('move-vault').hidden = !legacy;
  $('reset-note').textContent = legacy
    ? `Erasing destroys the key this server holds for ${wallet.address}. Anything left at that address goes with it, so sweep it somewhere on the way out.`
    : `Erasing removes the vault here and the key in this browser. Your twelve words are the only way back to ${wallet.address}, so send the coins on or write the words down first.`;

  if (!account) return;
  state.draft = {
    network: account.network,
    rules: account.policy.rules.map(rule => ({ ...rule })),
    members: account.signers.map(signer => ({ ...signer })),
    removed: [],
  };
  $('signers-note').textContent = `Everyone who can approve for the ${account.label} account with their palm.`;
  $('settings-required').textContent = `Changes here need ${account.changeRequired} palm approval${account.changeRequired === 1 ? '' : 's'} from its signers`;
  drawSettings();
}

function drawSettings() {
  const draft = state.draft;
  if (!draft) return;
  const count = draft.members.length;

  $('signer-rows').replaceChildren(...draft.members.map(member => el('div', { class: 'member-row' },
    el('span', {},
      member.label,
      member.owner ? el('small', {}, 'owner') : null,
      member.id === state.data.me.id ? el('small', {}, 'you') : null,
      el('small', { class: 'palm-id' }, member.palmId || (member.isNew ? 'palm id on approval' : 'no palm yet'))),
    member.owner ? el('span', { class: 'quiet small' }, 'cannot be removed') : button('Remove', 'link', () => {
      if (!member.isNew) draft.removed.push(member.id);
      draft.members = draft.members.filter(m => m.id !== member.id);
      for (const rule of draft.rules) rule.approvals = Math.min(rule.approvals, draft.members.length);
      drawSettings();
    }))));

  // Quick pick: the common "M of N" choices for every amount.
  $('presets').replaceChildren(
    el('span', { class: 'quiet small' }, 'Every amount:'),
    ...Array.from({ length: count }, (_, i) => i + 1).map(m =>
      button(`${m} of ${count}`, `chip pick${draft.rules.length === 1 && draft.rules[0].approvals === m ? ' on' : ''}`, () => {
        draft.rules = [{ upToSats: null, approvals: m }];
        drawSettings();
      })));

  $('rule-rows').replaceChildren(...draft.rules.map((rule, index) => {
    const last = index === draft.rules.length - 1;
    const select = el('select', {
      onchange: event => { rule.approvals = Number(event.target.value); drawSettings(); },
    }, ...Array.from({ length: count }, (_, i) => el('option', { value: String(i + 1), selected: rule.approvals === i + 1 }, `${i + 1} of ${count}`)));
    return el('div', { class: 'rule-row' },
      el('span', { class: 'quiet small' }, last ? 'Any larger amount' : 'Amounts up to'),
      last ? el('span', { class: 'quiet small' }, '') : el('input', {
        inputmode: 'numeric', value: rule.upToSats === null ? '' : String(rule.upToSats), placeholder: 'sats',
        oninput: event => { rule.upToSats = event.target.value === '' ? null : Number(event.target.value); },
      }),
      select,
      draft.rules.length > 1 ? button('Remove', 'link', () => {
        draft.rules.splice(index, 1);
        draft.rules.at(-1).upToSats = null;
        drawSettings();
      }) : el('span', {}));
  }));

  const account = (state.data.accounts || []).find(item => item.network === draft.network);
  const same = JSON.stringify(draft.rules) === JSON.stringify(account?.policy.rules)
    && draft.removed.length === 0
    && draft.members.length === (account?.signers.length ?? 0);
  $('save-settings').disabled = same;
  $('change-cost').textContent = same
    ? 'Nothing changed yet.'
    : `Proposing this asks ${account?.changeRequired ?? 1} of the current signers for a palm scan.`;
}

$('add-rule').addEventListener('click', () => {
  const draft = state.draft;
  const last = draft.rules.at(-1);
  draft.rules.splice(draft.rules.length - 1, 0, { upToSats: 100_000, approvals: Math.min(last.approvals, draft.members.length) });
  drawSettings();
});

$('add-member').addEventListener('click', () => {
  const code = $('new-member-code').value.trim();
  const label = $('new-member-label').value.trim();
  $('rules-error').textContent = '';
  if (!code || !label) {
    $('rules-error').textContent = 'Enter both the approver code and a name.';
    return;
  }
  state.draft.members.push({ id: code, label, owner: false, isNew: true });
  $('new-member-code').value = '';
  $('new-member-label').value = '';
  drawSettings();
});

$('save-settings').addEventListener('click', async () => {
  $('rules-error').textContent = '';
  const draft = state.draft;
  const add = draft.members.filter(m => m.isNew).map(m => ({ code: m.id, label: m.label }));
  try {
    const { operation } = await api('/api/policy', {
      network: draft.network, rules: draft.rules, add, remove: draft.removed,
    });
    openApproval(operation, 'Applying the new settings…');
  } catch (error) {
    $('rules-error').textContent = friendly(error);
  }
});

/* ------------------------------------------------- phrase and restore */

async function showPhrase(operation) {
  const mnemonic = await device.phrase(operation);
  $('phrase-words').replaceChildren(...mnemonic.split(' ').map(word => el('li', {}, word)));
  $('phrase').showModal();
}

$('phrase-done').addEventListener('click', () => {
  $('phrase-words').replaceChildren(); // do not leave the words sitting in the page
  $('phrase').close();
});

async function showRestore(operation) {
  state.restoreOperation = operation;
  $('restore-error').textContent = '';
  $('restore-words').value = '';
  $('restore').showModal();
}

$('restore-cancel').addEventListener('click', () => $('restore').close());

$('restore-form').addEventListener('submit', async event => {
  event.preventDefault();
  $('restore-error').textContent = '';
  const words = $('restore-words').value.trim().replace(/\s+/g, ' ').toLowerCase();
  try {
    await device.restore(state.restoreOperation, words, state.data.wallet.address);
    $('restore-words').value = '';
    $('restore').close();
    toast('This device holds the key again.');
    refresh().catch(() => {});
  } catch (error) {
    $('restore-error').textContent = friendly(error);
  }
});

$('show-phrase').addEventListener('click', () => startRecovery('show'));
$('restore-device').addEventListener('click', () => startRecovery('restore'));

async function startRecovery(intent) {
  $('device-error').textContent = '';
  state.recoveryIntent = intent;
  try {
    const { operation } = await api('/api/recovery', {});
    openApproval(operation, intent === 'restore' ? 'Getting ready to restore…' : 'Opening your phrase…');
  } catch (error) {
    $('device-error').textContent = friendly(error);
  }
}

/* -------------------------------------------------------------- price */

let priceLoaded = false;
async function loadPrice({ force = false } = {}) {
  if (priceLoaded && !force) return;
  priceLoaded = true;
  try {
    const price = await api('/api/price');
    if (price.error || !price.series?.length) {
      $('chart-note').textContent = price.error || 'No price data right now.';
      return;
    }
    state.price = price;
    paintPrice();
  } catch (error) {
    priceLoaded = false;
    $('chart-note').textContent = friendly(error);
  }
}

function paintPrice() {
  const price = state.price;
  if (!price) return;
  $('price-now').textContent = usd(price.usd);
  const change = price.change24h;
  $('price-change').textContent = change === null ? '—' : `${change >= 0 ? '+' : ''}${change.toFixed(2)}% in 24h`;
  $('price-change').className = change >= 0 ? 'up' : 'down';
  $('chart-note').textContent = `Bitcoin price from mempool.space, fetched by this server. Updated ${when(price.at)}.`;
  drawRanges();
  drawChart();
  paintFiat();
}

/** Test coins are worth nothing; the figure is what the same amount of real bitcoin would be. */
function paintFiat() {
  const price = state.price;
  const data = state.data;
  if (!price || !data?.balance) return;
  const total = data.balance.confirmed + data.balance.pending;
  const value = (total / 1e8) * price.usd;
  const text = `${usd(value)} if these were real coins`;
  $('balance-fiat').textContent = text;
  const card = $('account-fiat');
  if (card) card.textContent = text;
}

function drawRanges() {
  $('ranges').replaceChildren(...RANGES.map(range => button(range.label, `chip pick${state.range === range.key ? ' on' : ''}`, () => {
    state.range = range.key;
    drawRanges();
    drawChart();
  })));
}

function drawChart() {
  const price = state.price;
  if (!price?.series?.length) return;
  const range = RANGES.find(r => r.key === state.range) ?? RANGES[1];
  const latest = price.series.at(-1).t;
  const points = price.series.filter(point => point.t >= latest - range.seconds);
  if (points.length < 2) return;

  const NS = 'http://www.w3.org/2000/svg';
  const width = 960;
  const height = 280;
  const pad = { top: 16, right: 64, bottom: 24, left: 8 };
  const low = Math.min(...points.map(p => p.usd));
  const high = Math.max(...points.map(p => p.usd));
  const span = high - low || 1;
  const x = i => pad.left + (i / (points.length - 1)) * (width - pad.left - pad.right);
  const y = value => pad.top + (1 - (value - low) / span) * (height - pad.top - pad.bottom);

  const line = points.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(p.usd).toFixed(1)}`).join(' ');
  const area = `${line} L${x(points.length - 1).toFixed(1)},${height - pad.bottom} L${x(0).toFixed(1)},${height - pad.bottom} Z`;

  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
  svg.setAttribute('class', 'price-chart');
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', `Bitcoin price, ${range.label.toLowerCase()}, between ${Math.round(low)} and ${Math.round(high)} US dollars`);

  const gradient = document.createElementNS(NS, 'linearGradient');
  gradient.setAttribute('id', 'priceFade');
  gradient.setAttribute('x1', '0'); gradient.setAttribute('y1', '0');
  gradient.setAttribute('x2', '0'); gradient.setAttribute('y2', '1');
  for (const [offset, opacity] of [['0', '.42'], ['1', '0']]) {
    const stop = document.createElementNS(NS, 'stop');
    stop.setAttribute('offset', offset);
    stop.setAttribute('stop-color', '#1769ff');
    stop.setAttribute('stop-opacity', opacity);
    gradient.append(stop);
  }
  const defs = document.createElementNS(NS, 'defs');
  defs.append(gradient);
  svg.append(defs);

  for (let i = 0; i <= 3; i++) {
    const value = low + (span * i) / 3;
    const gy = y(value);
    const guide = document.createElementNS(NS, 'line');
    guide.setAttribute('x1', pad.left); guide.setAttribute('x2', width - pad.right);
    guide.setAttribute('y1', gy); guide.setAttribute('y2', gy);
    guide.setAttribute('class', 'chart-guide');
    const label = document.createElementNS(NS, 'text');
    label.setAttribute('x', width - pad.right + 8);
    label.setAttribute('y', gy + 4);
    label.setAttribute('class', 'chart-label');
    label.textContent = usd(value);
    svg.append(guide, label);
  }

  for (const [d, className] of [[area, 'chart-area'], [line, 'chart-line']]) {
    const path = document.createElementNS(NS, 'path');
    path.setAttribute('d', d);
    path.setAttribute('class', className);
    svg.append(path);
  }

  const dot = document.createElementNS(NS, 'circle');
  dot.setAttribute('cx', x(points.length - 1));
  dot.setAttribute('cy', y(points.at(-1).usd));
  dot.setAttribute('r', '4');
  dot.setAttribute('class', 'chart-dot');
  svg.append(dot);

  const first = new Date(points[0].t * 1000).toLocaleDateString([], { month: 'short', day: 'numeric' });
  const lastDay = new Date(points.at(-1).t * 1000).toLocaleDateString([], { month: 'short', day: 'numeric' });
  $('chart').replaceChildren(svg, el('p', { class: 'chart-axis' }, el('span', {}, first), el('span', {}, lastDay)));
}

/* ------------------------------------------------------------ sending */

$('send-max').addEventListener('change', event => {
  $('send-amount').disabled = event.target.checked;
  if (event.target.checked) $('send-amount').value = '';
});

$('send-form').addEventListener('submit', async event => {
  event.preventDefault();
  $('send-error').textContent = '';
  const submit = event.submitter;
  if (submit) submit.disabled = true;
  try {
    const max = $('send-max').checked;
    const { operation } = await api('/api/withdrawals', {
      to: $('send-to').value.trim(),
      amount: max ? 'max' : Number($('send-amount').value),
      ...($('send-fee').value ? { feeRate: Number($('send-fee').value) } : {}),
    });
    openApproval(operation, 'Sending…');
  } catch (error) {
    $('send-error').textContent = friendly(error);
  } finally {
    if (submit) submit.disabled = false;
  }
});

async function cancelRequest(op) {
  if (!confirm(`Cancel this request?\n\n${op.statement}`)) return;
  await api(`/api/operations/${op.id}/cancel`, {}).catch(error => toast(friendly(error)));
  refresh().catch(() => {});
}

/* ------------------------------------------------------------ receipt */

function showReceipt(receipt, txid) {
  if (!receipt || receipt.error) return;
  const record = receipt.authorization.record;
  const checked = receipt.checked?.ok;
  $('receipt-headline').textContent = 'Transaction authorised.';
  $('receipt-ticks').replaceChildren(
    el('li', {}, 'A palm approval was verified for this exact transaction'),
    el('li', {}, `Authorisation signed with ${receipt.algorithm}`),
    el('li', { class: checked ? '' : 'unchecked' },
      checked ? 'Signature checked in this browser' : `Not checked here: ${receipt.checked?.reason ?? 'unknown'}`),
    el('li', {}, txid ? 'Broadcast to the network' : 'Ready to broadcast'),
  );
  $('receipt-details').replaceChildren(...detailRows({
    vault: record.vaultId,
    transaction_hash: record.transactionHash,
    approvals: record.approvals,
    method: record.approvalMethod,
    approved_at: when(record.approvedAt),
    key: `${receipt.algorithm} · ${receipt.keyId}`,
    ...(txid ? { txid } : {}),
  }));
  state.receipt = receipt;
  $('receipt').showModal();
}

$('receipt-done').addEventListener('click', () => $('receipt').close());
$('receipt-copy').addEventListener('click', () => {
  if (state.receipt) copy(JSON.stringify(state.receipt.authorization, null, 2), 'Authorisation record copied.');
});

/* ----------------------------------------------------------- approval */

const DETAIL_LABELS = {
  action: 'Action', network: 'Network', to: 'To', amount_sats: 'Amount', fee_sats: 'Fee', fee_rate: 'Fee rate',
  change_sats: 'Change back', spends: 'Coins spent', approvals_required: 'Approvals', rules: 'New settings',
  approvers: 'Signers', spending_rule: 'Rule', owner_label: 'Your name', derived_from: 'Address from',
  transaction_hash: 'Transaction hash',
};

function detailRows(details) {
  const known = Object.keys(DETAIL_LABELS).filter(key => key in details);
  const rest = Object.keys(details).filter(key => !(key in DETAIL_LABELS));
  return [...known, ...rest].map(key => {
    const raw = details[key];
    const value = key.endsWith('_sats') ? `${fmtSats(raw)} sats (${btc(raw)} tBTC)`
      : key === 'transaction_hash' ? `${String(raw).slice(0, 16)}…${String(raw).slice(-8)}`
      : String(raw);
    return el('div', {}, el('dt', {}, DETAIL_LABELS[key] || key), el('dd', {}, value));
  });
}

async function openApproval(operation, busy) {
  active = { operation, busyText: busy };
  const kinds = {
    create: 'Palm approval · new vault', withdraw: 'Palm approval · withdrawal', policy: 'Palm approval · settings',
    account: 'Palm approval · new account', recovery: 'Palm approval · recovery phrase',
    upgrade: 'Palm approval · moving the vault',
    reset: 'Palm approval · erasing the vault',
  };
  $('approval-kind').textContent = kinds[operation.kind] || 'Palm approval';
  $('approval-statement').textContent = operation.statement;
  $('approval-details').replaceChildren(...detailRows(operation.details));
  $('approval-quorum').textContent = operation.required > 1
    ? `This needs ${operation.required} approvals. ${operation.approvedBy.length} so far.` : '';
  $('approval-error').textContent = '';
  $('approval-wait').hidden = false;
  $('approval-wait-text').textContent = 'Sending the request to your Veyns app…';
  $('approval-open').hidden = true;
  $('approval-cancel').textContent = 'Cancel';
  $('approval').showModal();

  try {
    const { approval } = await api(`/api/operations/${operation.id}/approval`, {});
    if (active?.operation.id !== operation.id) return;
    active.approval = approval;
    const started = await api(`/api/approvals/${approval.id}/palm`, {});
    if (active?.operation.id !== operation.id) return;
    active.approval = started.approval;
    $('approval-wait-text').textContent = 'Open Veyns on your phone, check the request and scan your palm.';
    $('approval-open').hidden = !started.approval.approvalUrl;
    pollApproval(active);
  } catch (error) {
    if (active?.operation.id === operation.id) closedWith(friendly(error));
  }
}

function closedWith(message) {
  $('approval-error').textContent = message;
  $('approval-wait').hidden = true;
  $('approval-cancel').textContent = 'Close';
}

$('approval-open').addEventListener('click', () => {
  if (active?.approval?.approvalUrl) window.open(active.approval.approvalUrl, 'veyns-approval', 'popup=yes,width=420,height=640,noopener');
});

async function pollApproval(current) {
  const deadline = Date.now() + 330_000;
  while (active === current && Date.now() < deadline) {
    await wait(2500);
    if (active !== current) return;
    try {
      const { approval, operation } = await api(`/api/approvals/${current.approval.id}`);
      if (active !== current) return;
      if (approval.status === 'approved') {
        $('approval-wait-text').textContent = current.busyText;
        return settled(current, operation);
      }
      if (approval.status === 'failed') return closedWith(approval.error || 'The approval failed.');
      if (approval.status !== 'open') return closedWith('The approval ended.');
      if (approval.remoteStatus === 'verifying') $('approval-wait-text').textContent = 'Checking your palm…';
    } catch (error) {
      if (error.status === 401) return location.reload();
      // Network blips: keep waiting until the deadline.
    }
  }
  if (active === current) {
    await api(`/api/approvals/${current.approval.id}/cancel`, {}).catch(() => {});
    closedWith('The palm request timed out.');
  }
}

async function settled(current, operation) {
  if (active !== current) return;
  active = null;
  $('approval').close();
  $('approval-wait').hidden = false;

  if (operation.status === 'failed') {
    toast(operation.error || 'The action failed.');
    return refresh().catch(() => {});
  }

  // The recovery ceremony takes two scans: open the sheet again for the other hand.
  if (operation.kind === 'recovery' && operation.status === 'collecting') {
    toast('First hand done. Now the other hand.');
    return openApproval(operation, 'Opening your phrase…');
  }

  if (operation.status !== 'done' && operation.status !== 'running') {
    const left = operation.required - operation.approvedBy.length;
    toast(`Approved. Waiting for ${left} more palm approval${left === 1 ? '' : 's'}.`);
    return refresh().catch(() => {});
  }

  try {
    if (operation.kind === 'create') {
      toast('Making your key in this browser…');
      const account = await device.create(operation);
      toast(`Wallet ready: ${account.address.slice(0, 12)}…`);
    } else if (operation.kind === 'withdraw') {
      // The quorum is complete; this browser is the only place that can sign it.
      toast('Human verified. Signing on this device…');
      const { txid, receipt } = await device.send(operation);
      toast(`Sent. Transaction ${shortId(txid)} is on the network.`);
      showReceipt(receipt, txid);
      $('send-form').reset();
      $('send-amount').disabled = false;
    } else if (operation.kind === 'recovery') {
      if (state.recoveryIntent === 'restore') await showRestore(operation);
      else await showPhrase(operation);
    } else if (operation.kind === 'reset') {
      const { txid, sweptSats } = await device.reset(operation);
      toast(txid
        ? `Vault erased. ${fmtSats(sweptSats)} sats were sent on first (${shortId(txid)}).`
        : 'Vault erased. Create a new one whenever you are ready.');
    } else if (operation.kind === 'upgrade') {
      toast('Making your key in this browser…');
      const { txid, sweptSats } = await device.moveIn(operation);
      toast(txid
        ? `Vault moved. ${fmtSats(sweptSats)} sats are on their way to the new address (${shortId(txid)}).`
        : 'Vault moved. The key is in this browser now — write the phrase down in Settings.');
    } else if (operation.kind === 'account') {
      toast('Deriving the address in this browser…');
      const account = await device.addAccount(operation);
      state.account = operation.network;
      toast(`Account ready: ${account.address.slice(0, 12)}…`);
    } else if (operation.kind === 'policy') {
      toast('New settings are in force.');
    }
  } catch (error) {
    toast(friendly(error));
  }
  refresh().catch(() => {});
}

async function dismissApproval() {
  const current = active;
  active = null;
  $('approval').close();
  $('approval-wait').hidden = false;
  if (current?.approval) await api(`/api/approvals/${current.approval.id}/cancel`, {}).catch(() => {});
  refresh().catch(() => {});
}

$('approval-cancel').addEventListener('click', dismissApproval);
$('approval').addEventListener('cancel', event => {
  event.preventDefault();
  dismissApproval();
});

/* -------------------------------------------------------------- start */

$('retry').addEventListener('click', boot);

// Coins arrive, and other people approve, without telling us: check every 15 seconds.
setInterval(() => {
  if (state.data && !active && !document.hidden) refresh().catch(() => {});
}, 15_000);
setInterval(() => {
  if (state.data && !document.hidden) loadPrice({ force: true }).catch(() => {});
}, 120_000);

boot();
