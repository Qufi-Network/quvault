import {
  accountFrom, accountsFrom, attest, attestationKeys, checkAuthorization, checkChain, clearRecord,
  decryptMnemonic, encryptMnemonic, fromBase64, jitterFrom, loadRecord, makeMnemonic, planDigest,
  cosignerFrom, registerKey, saveRecord, signPlan, signQuorum,
} from '/vendor/wallet.js';

const $ = id => document.getElementById(id);

const VIEWS = ['loading', 'setup', 'signin', 'about', 'create', 'wallet'];
const VAULT_PANES = ['dashboard', 'security'];
const ACCOUNT_TABS = [
  { key: 'overview', label: 'Overview' },
  { key: 'send', label: 'Send' },
  { key: 'receive', label: 'Receive' },
  { key: 'rules', label: 'Signers and rules' },
];
const RANGES = [
  { key: 'day', label: 'Day', seconds: 86_400 },
  { key: 'week', label: 'Week', seconds: 7 * 86_400 },
  { key: 'month', label: 'Month', seconds: 30 * 86_400 },
  { key: 'max', label: '3M', seconds: 120 * 86_400 },
];

const state = {
  config: null, data: null, price: null, range: 'week', loginNonce: null, draft: null,
  account: 'bitcoin', // which account is open
  tab: 'overview',    // which of its tabs
  pane: 'dashboard',  // 'dashboard', 'security', or 'account'
};

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

/** The pages somebody sees before they are signed in, and the header they share. */
const MARKETING = ['signin', 'about'];

function show(view) {
  for (const name of VIEWS) $(`view-${name}`).hidden = name !== view;
  $('who').hidden = view !== 'wallet' && view !== 'create';
  // Those pages carry their own header, so the app's one steps out of their way.
  const marketing = MARKETING.includes(view);
  document.querySelector('.top').hidden = marketing;
  $('marketing-top').hidden = !marketing;
  for (const link of $('marketing-nav').querySelectorAll('a')) {
    const here = (link.getAttribute('href') === '#about') === (view === 'about');
    link.classList.toggle('on', here && ['#about', '#home'].includes(link.getAttribute('href')));
  }
}

/*
 * Veyns is never loaded as a script here.
 *
 * Sign-in is the ordinary authorization-code redirect with PKCE: this page talks to the
 * issuer over fetch and hands the browser to it, and the issuer hands the browser back with
 * a code. Nothing of theirs executes on this origin, which matters because anything that did
 * could read the encrypted phrase out of IndexedDB and the unlock secret as it arrives. The
 * party that verifies a palm should not also be a party that could take the key.
 */

/* --------------------------------------------------------------- boot */

async function boot() {
  show('loading');
  $('loading-text').textContent = 'Loading…';
  $('retry').hidden = true;
  try {
    state.config = await api('/api/config');
    $('network-chip').textContent = state.config.network;
    if (!state.config.configured || !state.config.vaultReady || !state.config.palmEnabled) return showSetup();
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
    // Someone can sign for another vault without having one of their own: say so first.
    $('my-code').textContent = data.me.code;
    renderRequests($('create-pending'), data.pending);
    const waiting = (data.pending || []).filter(op => op.needsYou);
    $('signer-alert').hidden = waiting.length === 0;
    if (waiting.length) {
      $('signer-alert-title').textContent = waiting.length === 1
        ? 'Something needs your palm'
        : `${waiting.length} requests need your palm`;
      $('signer-alert-what').textContent = `${waiting[0].statement} — ${waiting[0].approvedBy.length} of ${waiting[0].required} approvals so far.`;
    }
    // One browser holds one phrase, so a second vault here would write over the first.
    const taken = Boolean(device.record);
    $('create-wallet').disabled = taken;
    if (taken) {
      $('create-error').textContent = 'This browser already holds the key for another vault. '
        + 'Making a second one here would write over it, so use a different browser or profile.';
    }
    show('create');
    return;
  }
  renderWallet(data);
  show('wallet');
  route(location.hash || '#dashboard', { remember: false });
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

/* ----------------------------------------------------------- routing */

/*
 * Two levels, and the address bar says which: the vault (#overview, #security) and one of its
 * accounts with its own tabs (#bitcoin, #bitcoin/send). Anything unrecognised lands on the
 * vault overview rather than on nothing.
 */
function route(hash, { remember = true } = {}) {
  const [first, second] = String(hash || '').replace(/^#/, '').split('/').filter(Boolean);
  const accounts = (state.data?.accounts || []).map(account => account.network);

  if (first === 'security') {
    state.pane = 'security';
  } else if (first && accounts.includes(first)) {
    state.pane = 'account';
    state.account = first;
    state.tab = ACCOUNT_TABS.some(tab => tab.key === second) ? second : 'overview';
  } else {
    state.pane = 'dashboard';
  }

  for (const pane of document.querySelectorAll('.pane')) pane.hidden = pane.dataset.pane !== state.pane;
  for (const node of document.querySelectorAll('.side .nav')) {
    const active = node.dataset.nav === state.pane;
    node.classList.toggle('active', active);
    node.setAttribute('aria-current', active ? 'page' : 'false');
  }
  if (state.data) {
    renderAccounts(state.data);
    if (state.pane === 'account') renderAccount(state.data);
  }
  if (state.pane === 'dashboard') loadPrice();
  const path = state.pane === 'account' ? `${state.account}${state.tab === 'overview' ? '' : `/${state.tab}`}` : state.pane;
  if (remember && location.hash.slice(1) !== path) history.replaceState(null, '', `#${path}`);
  window.scrollTo({ top: 0, behavior: 'instant' });
}

/** Opens an account, on a given tab. */
const openAccount = (network, tab = 'overview') => route(`${network}/${tab}`);

for (const node of document.querySelectorAll('.side .nav')) {
  node.addEventListener('click', () => route(node.dataset.nav));
}
addEventListener('hashchange', () => route(location.hash, { remember: false }));

/* ------------------------------------------------------ sign-in */

/** Every way in from the home page, and whether it asks Veyns for a palm or lets them choose. */
const SIGNIN_BUTTONS = [
  ['signin-top', 'browser'],
  ['signin-browser', 'browser'],
  ['signin-create', 'browser'],
  ['signin-palm', 'palm'],
  ['about-join', 'browser'],
  ['built-cta', 'browser'],
  ['join-cta', 'browser'],
];

/** Home or About, whichever the address bar asks for. Both can sign you in. */
async function showSignin() {
  show(location.hash === '#about' ? 'about' : 'signin');
  const ready = state => { for (const [id] of SIGNIN_BUTTONS) $(id).disabled = state; };
  /*
   * A vault that insists on a palm has nothing to offer the ordinary way in, so those routes
   * are taken off the page. The list is derived rather than written out, because writing it
   * out is how it came to name a button that no longer existed and stop the page booting.
   */
  for (const [id, method] of SIGNIN_BUTTONS) {
    if (method === 'browser') $(id).hidden = state.config.requirePalmSignin;
  }
  ready(true);
  try {
    const { nonce } = await api('/api/login/start', {});
    state.loginNonce = nonce;
    ready(false);
  } catch (error) {
    $('signin-error').textContent = friendly(error);
  }
}

/*
 * Moving between the pages somebody sees before signing in. A sign-in nonce is already in
 * hand by then, so switching page is only ever a matter of which one is on show.
 */
window.addEventListener('hashchange', () => {
  if (!MARKETING.includes(VIEWS.find(name => !$(`view-${name}`).hidden))) return;
  const wanted = location.hash === '#about' ? 'about' : 'signin';
  show(wanted);
  if (wanted === 'signin') window.scrollTo({ top: 0 });
});

async function signIn(method) {
  const nonce = state.loginNonce;
  if (!nonce) return;
  state.loginNonce = null;
  $('signin-error').textContent = '';
  for (const [id] of SIGNIN_BUTTONS) $(id).disabled = true;
  try {
    $('signin-error').textContent = 'Opening Veyns…';
    await signInWithRedirect(method, nonce);
  } catch (error) {
    $('signin-error').textContent = friendly(error);
    await showSignin();
  }
}

for (const [id, method] of SIGNIN_BUTTONS) $(id).addEventListener('click', () => signIn(method));

/* The small-screen menu, which closes itself once it has taken somebody somewhere. */
{
  const header = $('marketing-top');
  const toggle = $('nav-toggle');
  const shut = () => { header.classList.remove('open'); toggle.setAttribute('aria-expanded', 'false'); };
  toggle.addEventListener('click', () => {
    const open = header.classList.toggle('open');
    toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
  });
  $('marketing-nav').addEventListener('click', event => { if (event.target.closest('a')) shut(); });
}

/*
 * The newsletter sign-up. There is nowhere to send an address yet, so rather than pretend to
 * take one it says plainly that it is not connected — a form that silently swallows what
 * somebody typed is worse than one that admits it cannot help.
 */
$('foot-signup').addEventListener('submit', event => {
  event.preventDefault();
  const email = $('signup-email').value.trim();
  if (!email) return;
  $('signup-note').textContent = $('signup-consent').checked
    ? 'Updates are not connected yet — nothing has been sent or stored.'
    : 'Tick the box first, and note that updates are not connected yet.';
});

/*
 * The hand is a photograph the product ships with. If it is not there the page still reads,
 * because a broken image on the first screen somebody sees is worse than no image at all.
 */
{
  const image = $('hero-hand-image');
  const done = () => image.closest('.hand-frame').classList.add('has-image');
  if (image.complete && image.naturalWidth) done();
  image.addEventListener('load', done);
  image.addEventListener('error', () => { image.remove(); });
}

/*
 * The hand turns very slightly towards whoever is looking at it — three degrees at the edge of
 * the window, which is enough to sit in a room rather than on a page and little enough that
 * you would struggle to catch it doing so. Nothing moves for somebody who has asked for less
 * motion, and nothing moves on a touch screen, where there is no pointer to follow.
 */
{
  const frame = $('hand-frame');
  const still = window.matchMedia('(prefers-reduced-motion: reduce)');
  const coarse = window.matchMedia('(pointer: coarse)');
  const MAX = 3;
  let queued = false;
  let last = { x: 0, y: 0 };

  const apply = () => {
    queued = false;
    frame.style.setProperty('--tilt-x', `${last.x.toFixed(2)}deg`);
    frame.style.setProperty('--tilt-y', `${last.y.toFixed(2)}deg`);
  };

  window.addEventListener('pointermove', event => {
    if (still.matches || coarse.matches || $('view-signin').hidden) return;
    const box = frame.getBoundingClientRect();
    if (!box.width) return;
    frame.classList.remove('settling');
    const dx = (event.clientX - (box.left + box.width / 2)) / (window.innerWidth / 2);
    const dy = (event.clientY - (box.top + box.height / 2)) / (window.innerHeight / 2);
    last = {
      x: Math.max(-MAX, Math.min(MAX, dx * MAX)),
      y: Math.max(-MAX, Math.min(MAX, -dy * MAX)),
    };
    if (!queued) { queued = true; requestAnimationFrame(apply); }
  }, { passive: true });

  const rest = () => {
    frame.classList.add('settling');
    last = { x: 0, y: 0 };
    apply();
  };
  document.addEventListener('pointerleave', rest);
  window.addEventListener('blur', rest);
}

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

  /**
   * Makes the phrase and stores it encrypted, here and nowhere else.
   *
   * There is one phrase per browser, and it is the only copy of itself. A second vault made
   * here would write over the first, taking with it that vault's coins and any key derived
   * from the same words for a quorum somebody else is relying on. So it is refused rather
   * than done quietly.
   */
  async makeKey(operation) {
    if (this.record) {
      throw new Error('This browser already holds a vault key, and making another would write over it. '
        + 'Use a different browser or profile, or erase the vault here first.');
    }
    const [{ random }, unlocked] = await Promise.all([api('/api/random'), this.unlockFor(operation.id)]);
    const mnemonic = makeMnemonic({
      serverRandom: fromBase64(random),
      jitter: jitterFrom([operation.id, unlocked.salt, screen.width, screen.height]),
    });
    const account = accountFrom(mnemonic);
    const blob = await encryptMnemonic(mnemonic, unlocked.unlock, unlocked.salt);
    await saveRecord({
      blob,
      salt: unlocked.salt,
      address: account.address,
      publicKey: toHex(account.publicKey),
      // Pinned here so a server that rewrote its own record of the lineage is visible.
      attestationRootKeyId: attestationKeys(mnemonic, 1).keyId,
      createdAt: Date.now(),
    });
    this.record = await loadRecord();
    // The phrase goes back to the caller so the attestation key can be derived here, once,
    // without asking the server to unlock anything a second time.
    return { account, mnemonic };
  },

  /** A new vault: the server is told the address and two public keys, and no secret. */
  async create(operation) {
    const { account, mnemonic } = await this.makeKey(operation);
    await api('/api/wallet/register', {
      operationId: operation.id,
      address: account.address,
      publicKey: toHex(account.publicKey),
      attestationRegistration: registerKey(mnemonic, { vaultId: account.address, epoch: 1 }),
    });
    return account;
  },

  /**
   * A vault made before keys lived here: this browser makes and saves the new key first,
   * then the server sweeps the old address and retires the key it was holding.
   */
  async moveIn(operation) {
    const { account, mnemonic } = await this.makeKey(operation);
    const result = await api('/api/wallet/upgrade', {
      operationId: operation.id,
      address: account.address,
      publicKey: toHex(account.publicKey),
      attestationRegistration: registerKey(mnemonic, { vaultId: account.address, epoch: 1 }),
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
    // The authorisation is signed here, with a key the server does not have.
    const authorization = attest(mnemonic, {
      vaultId: this.record.address,
      accountId: 'bitcoin',
      transactionHash: unlocked.transactionHash,
      statementDigest: unlocked.statementDigest,
      approvalMethod: 'veyns:palm',
      approvals: unlocked.approvals,
      approvedBy: unlocked.approvedBy,
      decisionIds: unlocked.decisionIds,
      approvedAt: Math.floor(Date.now() / 1000),
    }, unlocked.attestationEpoch ?? 1);
    const sent = await api(`/api/operations/${operation.id}/broadcast`, { hex: signed.hex, authorization });
    return { ...sent, receipt: await readReceipt(operation.id) };
  },

  /**
   * The key this browser signs one vault's Bitcoin with. It comes from the same phrase as the
   * wallet here, on a branch of its own; the vault is told the public half and nothing else.
   */
  async makeSigningKey(operation) {
    if (!this.record) throw new Error('This browser does not hold the key for this wallet.');
    const unlocked = await this.unlockFor(operation.id);
    const mnemonic = await decryptMnemonic(this.record.blob, unlocked.unlock, this.record.salt);
    const { publicKey } = cosignerFrom(mnemonic, operation.details.branch);
    return api('/api/signing-key/register', { operationId: operation.id, publicKey: toHex(publicKey) });
  },

  /**
   * One signature towards a spend from an account the chain guards. The transaction is
   * re-checked against what the palm approved before anything is signed, and what leaves here
   * is the half-signed transaction with this browser's signature added to it.
   */
  async addSignature(operation) {
    if (!this.record) throw new Error('This browser does not hold the key for this wallet.');
    const unlocked = await this.unlockFor(operation.id);
    const mnemonic = await decryptMnemonic(this.record.blob, unlocked.unlock, this.record.salt);
    const { psbt } = signQuorum(mnemonic, {
      psbt: unlocked.psbt,
      plan: unlocked.plan,
      index: unlocked.keyIndex,
      address: unlocked.address,
      transactionHash: unlocked.transactionHash,
      network: state.config.network,
    });
    return api(`/api/operations/${operation.id}/signature`, { psbt });
  },

  /** The phrase, for an operation that has already been palm-approved. */
  async phraseFromRecord(operationId) {
    if (!this.record) throw new Error('This browser does not hold the key for this wallet.');
    const unlocked = await this.unlockFor(operationId);
    return decryptMnemonic(this.record.blob, unlocked.unlock, this.record.salt);
  },

  /**
   * Replaces the attestation key. The new epoch's registration is signed by the key it
   * replaces, so the server can see the lineage continue without being able to continue it.
   */
  async rotateAttestation(operation) {
    const mnemonic = await this.phraseFromRecord(operation.id);
    const current = state.data?.wallet?.attestation?.epoch ?? null;
    const registration = current === null
      // No lineage yet: start one at epoch 1, signed by itself.
      ? registerKey(mnemonic, { vaultId: this.record.address, epoch: 1 })
      : registerKey(mnemonic, { vaultId: this.record.address, epoch: current + 1, previous: current });
    const result = await api('/api/attestation/register', { operationId: operation.id, attestationRegistration: registration });
    // The device pins the root of whatever lineage it just started.
    if (current === null && this.record) {
      await saveRecord({ ...this.record, attestationRootKeyId: result.attestation.rootKeyId });
      this.record = await loadRecord();
    }
    return result;
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
    // The lineage is walked here, from the vault's own root, before the record is believed.
    const vaultId = state.data?.wallet?.address;
    const chain = checkChain(receipt.attestationChain, { vaultId });
    const pinned = device.record?.attestationRootKeyId ?? null;
    const checked = !chain.ok ? { ok: false, reason: chain.reason }
      : pinned && chain.rootKeyId !== pinned ? { ok: false, reason: 'the key lineage is not the one this device started' }
        : checkAuthorization(receipt.authorization, chain.publicKey, {
          transactionHash: receipt.authorization.record.transactionHash,
          vaultId,
        });
    return { ...receipt, checked, chain };
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
  const { wallet, balance, spendable, coins, chainHistory, chainError, members, me } = data;
  const total = balance ? balance.confirmed + balance.pending : 0;
  const myName = members.find(m => m.id === me.id)?.label || 'there';
  const hour = new Date().getHours();
  $('greeting').textContent = `Good ${hour < 12 ? 'morning' : hour < 18 ? 'afternoon' : 'evening'}, ${myName}.`;
  const count = (data.accounts || []).length;
  $('greeting-note').textContent = `${count} account${count === 1 ? '' : 's'}, ${members.length} signer${members.length === 1 ? '' : 's'}.`;

  $('balance').textContent = btc(total);
  const notes = [];
  if (balance?.pending) notes.push(`${fmtSats(balance.pending)} sats still unconfirmed`);
  if (coins) notes.push(`${coins} spendable coin${coins === 1 ? '' : 's'} (${fmtSats(spendable)} sats)`);
  else if (balance && !balance.txCount) notes.push('No coins yet — open an account to find its address.');
  notes.push(device.holdsKeyFor(wallet) ? 'Key held in this browser only' : 'Key not on this device — restore it in Security');
  $('balance-note').textContent = notes.join(' · ');
  $('chain-error').textContent = chainError || '';
  $('accounts-note').textContent = `${members.length} signer${members.length === 1 ? '' : 's'} across this vault`;

  renderAccounts(data);
  renderSecurity(data);
  if (state.pane === 'account') renderAccount(data);
  $('legacy-lane').hidden = wallet.custody === 'client';
  renderRequests($('pending'), data.pending);
  $('pending-lane').hidden = data.pending.length === 0;
  renderAlerts(data);
  renderHistory(chainHistory || [], data.history || []);
  paintFiat();
}

/** The sidebar list and the cards on the vault overview: one per network. */
function renderAccounts(data) {
  const accounts = data.accounts || [];
  if (!accounts.some(account => account.network === state.account)) {
    state.account = accounts[0]?.network || 'bitcoin';
  }
  const open = state.pane === 'account' ? state.account : null;

  $('account-list').replaceChildren(...accounts.map(account => el('button', {
    class: `account${account.network === open ? ' active' : ''}`,
    type: 'button',
    onclick: () => openAccount(account.network),
  },
    el('span', { class: 'account-mark' }, MARKS[account.network] || account.symbol.slice(0, 1)),
    el('span', { class: 'account-text' }, el('b', {}, account.label), el('small', {}, account.chain)),
    el('span', { class: 'account-amount' }, account.formatted ?? '—'))));

  $('accounts').replaceChildren(
    ...accounts.map(account => accountCard(account, data)),
    el('button', { class: 'account-card add', type: 'button', onclick: openNewAccount },
      el('span', { class: 'account-mark big ghost' }, '+'),
      el('div', { class: 'stack tight' },
        el('b', {}, 'Add an account'),
        el('small', { class: 'quiet' }, 'Ethereum, Tron, Solana or Stellar, from this same phrase'))),
  );
}

function accountCard(account, data) {
  const bitcoin = account.network === 'bitcoin';
  const coins = bitcoin && data.coins ? `${data.coins} coin${data.coins === 1 ? '' : 's'}` : null;
  return el('article', {
    class: 'account-card',
    tabindex: '0',
    role: 'button',
    onclick: () => openAccount(account.network),
    onkeydown: event => { if (event.key === 'Enter' || event.key === ' ') openAccount(account.network); },
  },
    el('header', {},
      el('span', { class: 'account-mark big' }, MARKS[account.network] || account.symbol.slice(0, 1)),
      el('div', {}, el('b', {}, account.label), el('small', {}, account.chain)),
      el('span', { class: `chip soft${account.canSend ? '' : ' muted'}` }, coins ?? (account.canSend ? 'send and receive' : 'receive only'))),
    el('p', { class: 'account-balance' }, account.formatted ?? '—', el('span', { class: 'unit' }, account.symbol)),
    bitcoin ? el('p', { class: 'quiet small', id: 'account-fiat-card' }, '') : null,
    el('p', { class: 'quiet small rule-line' }, account.rulesText),
    el('p', { class: 'account-address' }, account.address),
    el('div', { class: 'row' },
      account.canSend
        ? button('Send', 'btn brand sm', event => { event.stopPropagation(); openAccount(account.network, 'send'); })
        : null,
      button('Receive', 'btn ghost sm', event => { event.stopPropagation(); openAccount(account.network, 'receive'); })));
}

/* ------------------------------------------------------- one account */

/** Everything inside the account pane: its header, its tabs, and whichever tab is open. */
function renderAccount(data) {
  const accounts = data.accounts || [];
  const account = accounts.find(item => item.network === state.account) || accounts[0];
  if (!account) return;

  $('account-mark').textContent = MARKS[account.network] || account.symbol.slice(0, 1);
  $('account-title').textContent = `${account.label} account`;
  $('account-subtitle').textContent = `${account.chain} · ${account.signers.length} signer${account.signers.length === 1 ? '' : 's'}`;
  $('account-chip').textContent = account.canSend ? 'send and receive' : 'receive only';
  $('account-chip').classList.toggle('muted', !account.canSend);
  $('account-explorer').href = account.explorer;

  // The tab strip, with the one that cannot work here left out rather than shown broken.
  const tabs = ACCOUNT_TABS.filter(tab => tab.key !== 'send' || account.canSend);
  if (!tabs.some(tab => tab.key === state.tab)) state.tab = 'overview';
  $('account-tabs').replaceChildren(...tabs.map(tab => el('button', {
    class: `tab${tab.key === state.tab ? ' active' : ''}`,
    type: 'button',
    role: 'tab',
    'aria-selected': tab.key === state.tab ? 'true' : 'false',
    onclick: () => openAccount(account.network, tab.key),
  }, tab.label)));
  for (const pane of document.querySelectorAll('.subpane')) pane.hidden = pane.dataset.sub !== state.tab;

  renderAccountOverview(account, data);
  renderAccountReceive(account, data);
  renderAccountSend(account, data);
  renderRules(account, data);
  checkLineage(data);
}

function renderAccountOverview(account, data) {
  $('account-balance').textContent = account.formatted ?? '—';
  $('account-unit').textContent = account.symbol;
  $('account-address').textContent = account.address;
  $('account-network').textContent = `${account.label} · ${account.chain}`;
  $('account-protection').textContent = data.wallet.protection;
  $('account-send').hidden = !account.canSend;
  $('rules-chip').textContent = `${account.changeRequired} to change`;
  $('rules-summary').textContent = account.rulesText;
  $('signer-chips').replaceChildren(...account.signers.map(signer => el('span', { class: 'signer-chip' },
    el('span', { class: 'avatar' }, initials(signer.label)),
    signer.label,
    signer.owner ? el('small', {}, 'owner') : null)));

  const mine = data.pending.filter(op => op.network === account.network || (account.network === 'bitcoin' && !op.network));
  renderRequests($('account-pending'), mine);
  $('account-pending-lane').hidden = mine.length === 0;
  paintFiat();
}

function renderAccountReceive(account, data) {
  $('address').textContent = account.address;
  $('explorer-link').href = account.explorer;
  $('qr').innerHTML = account.qr || ''; // A QR code this server generated; no external content.
  $('receive-hint').textContent = account.network === 'bitcoin'
    ? 'Send test coins here from a testnet4 faucet. They appear after one confirmation, and receiving never needs a palm scan.'
    : `Send ${account.chain} ${account.symbol} here. The address comes from your phrase, and receiving never needs a palm scan.`;
  $('receive-note').textContent = account.network === 'bitcoin'
    ? (data.balance?.txCount ? `${data.balance.txCount} transaction${data.balance.txCount === 1 ? '' : 's'} so far.` : '')
    : `Balance ${account.formatted ?? 'unknown'} ${account.symbol}.`;
}

function renderAccountSend(account, data) {
  $('send-form').hidden = !account.canSend;
  $('send-rule-note').textContent = account.canSend ? `This account: ${account.rulesText}.` : '';
  $('fee-note').textContent = data.feeRate ? `Network suggests ${data.feeRate} sat/vB` : '';
  $('send-soon').hidden = account.canSend;
  $('send-soon').textContent = account.canSend ? ''
    : `Signing for ${account.label} is the next step. This account receives and shows its balance today.`;
  renderRequests($('send-pending'), data.pending.filter(op => op.kind === 'withdraw'));
}

const initials = name => String(name || '?').trim().split(/\s+/).slice(0, 2).map(part => part[0]).join('').toUpperCase();

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
    button('Add signer', 'btn ghost sm', () => {
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

/* ------------------------------------------- replacing the authorisation key */

$('rotate-attestation').addEventListener('click', async () => {
  $('device-error').textContent = '';
  const fresh = !state.data?.wallet?.attestation?.keyId;
  const question = fresh
    ? 'Register the key that signs your authorisation records?\n\nIt is derived from the recovery phrase this browser already holds, and takes one palm scan.'
    : 'Replace the key that signs your authorisation records?\n\nReceipts signed by the old key stop being accepted. The new key comes from the same recovery phrase.';
  if (!confirm(question)) return;
  try {
    const { operation } = await api('/api/attestation/approval', {});
    openApproval(operation, 'Replacing the authorisation key…');
  } catch (error) {
    $('device-error').textContent = friendly(error);
  }
});

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
$('reset-keep').addEventListener('click', () => $('reset').close());

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

/**
 * What is waiting for this person, said once and loudly. The page polls, so a request raised
 * by another signer turns up here within a few seconds without anyone refreshing anything.
 */
function renderAlerts(data) {
  const waiting = (data.pending || []).filter(op => op.needsYou);
  $('alert-lane').hidden = waiting.length === 0;
  if (!waiting.length) {
    state.alerted = new Set();
    return;
  }
  const first = waiting[0];
  $('alert-title').textContent = waiting.length === 1
    ? 'Something is waiting for your palm'
    : `${waiting.length} requests are waiting for your palm`;
  $('alert-what').textContent = `${first.statement} — ${first.approvedBy.length} of ${first.required} approvals so far.`;
  $('alert-go').onclick = () => openApproval(first, busyText(first));

  // Say it once per request, rather than every poll.
  state.alerted ??= new Set();
  for (const op of waiting) {
    if (state.alerted.has(op.id)) continue;
    state.alerted.add(op.id);
    if (state.data) toast(`Waiting for your palm: ${op.statement}`);
  }
}

function renderRequests(container, requests) {
  const { me, labels = {} } = state.data;
  container.replaceChildren(...requests.map(op => {
    const done = op.approvedBy.length;
    const mine = op.mine;
    const actions = el('div', { class: 'row' });
    if (op.status === 'collecting' && (!mine || mine.status !== 'approved')) {
      actions.append(button('Approve with palm', 'btn brand sm', () => openApproval(op, busyText(op))));
    } else if (op.needsSignature) {
      // An account the chain guards needs this person's signature as well as their palm.
      actions.append(button('Sign with your key', 'btn brand sm', () => addSignature(op)));
    } else if (mine?.status === 'approved') {
      actions.append(el('span', { class: 'quiet' },
        op.signatures ? 'You signed. Waiting for the others.' : 'You approved. Waiting for the others.'));
    }
    if (op.startedBy === me.id || op.walletOwner === me.id) {
      actions.append(button('Cancel', 'btn ghost sm', () => cancelRequest(op)));
    }
    return el('article', { class: 'request' },
      el('p', { class: 'request-what' }, op.statement),
      el('p', { class: 'quiet small' }, [
        `${done} of ${op.required} approval${op.required === 1 ? '' : 's'}`,
        done ? `by ${op.approvedBy.map(id => labels[id] || 'someone').join(', ')}` : null,
        op.signatures ? `${op.signatures.done} of ${op.signatures.required} signatures on the chain` : null,
        op.status === 'running' && !op.signatures ? 'running' : null,
      ].filter(Boolean).join(' · ')),
      el('div', { class: 'meter', 'aria-hidden': 'true' }, el('span', { style: { width: `${Math.min(100, (done / op.required) * 100)}%` } })),
      actions);
  }));
}

/** Adds this browser's signature to a spend from an account the chain guards. */
async function addSignature(op) {
  try {
    toast('Signing with your key…');
    const result = await device.addSignature(op);
    toast(result.txid
      ? `Sent. ${result.signatures} of ${result.required} signatures (${shortId(result.txid)}).`
      : `Signed. ${result.signatures} of ${result.required} signatures so far.`);
  } catch (error) {
    toast(friendly(error));
  }
  refresh().catch(() => {});
}

const BUSY = {
  create: 'Creating the vault…', withdraw: 'Sending…', policy: 'Applying the new settings…',
  account: 'Adding the account…', recovery: 'Opening your phrase…', upgrade: 'Moving the vault into this browser…',
  reset: 'Erasing the vault…', attestation: 'Replacing the authorisation key…',
  signing: 'Making your signing key…', lock: 'Locking to the chain…',
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

/* ------------------------------------------------------ vault security */

/** The vault's own pane: the keys behind it, and the way to end it. */
function renderSecurity(data) {
  const { me, wallet } = data;
  $('my-code').textContent = me.code;

  const legacy = wallet.custody !== 'client';
  const holds = device.holdsKeyFor(wallet);
  $('device-chip').textContent = legacy ? 'server-held' : holds ? 'in this browser' : 'not on this device';
  $('device-chip').classList.toggle('warn', legacy || !holds);
  $('device-state').textContent = legacy
    ? 'This vault was made before keys lived in the browser: its key is sealed on the server, so there is no recovery phrase and no other-network accounts.'
    : holds
      ? 'This browser holds the key for this vault. The server has never seen it.'
      : 'This browser does not hold the key. Restore it here with your twelve words, or use the browser that made the vault.';
  $('show-phrase').hidden = legacy || !holds;
  $('restore-device').hidden = legacy || holds;
  $('move-vault').hidden = !legacy;

  const attestation = wallet.attestation;
  $('attestation-key').textContent = attestation?.keyId
    ? `${attestation.keyId} · epoch ${attestation.epoch} · from ${attestation.rootKeyId}`
    : attestation?.broken ? `lineage broken: ${attestation.broken}` : 'none registered';
  $('rotate-attestation').hidden = legacy;
  $('rotate-attestation').textContent = attestation?.keyId ? 'Replace the authorisation key' : 'Register the authorisation key';

  $('reset-note').textContent = legacy
    ? `Erasing destroys the key this server holds for ${wallet.address}. Anything left at that address goes with it, so sweep it somewhere on the way out.`
    : `Erasing removes the vault here and the key in this browser. Your twelve words are the only way back to ${wallet.address}, so send the coins on or write the words down first.`;
}

/* ------------------------------------------- one account's signers and rules */

/** The editable copy of one account's signers and thresholds, rebuilt from the server view. */
function renderRules(account, data) {
  // Keep an edit in progress if it belongs to this account; otherwise start from the server.
  if (state.draft?.network !== account.network) {
    state.draft = {
      network: account.network,
      rules: account.policy.rules.map(rule => ({ ...rule })),
      members: account.signers.map(signer => ({ ...signer })),
      removed: [],
    };
  }
  $('signers-note').textContent = `Everyone who can approve for the ${account.label} account with their palm.`;
  drawInvites(account).catch(() => {});
  $('settings-required').textContent = `${account.changeRequired} palm${account.changeRequired === 1 ? '' : 's'} to change`;
  void data;
  drawSettings();
  drawChainLock(account);
}

/*
 * What the chain itself keeps for this account, and what it would take to get there.
 *
 * Two things here are the chain's doing rather than a choice. A script cannot read the amount
 * being sent, so a locked account has one threshold and not a ladder of them. And the
 * threshold is part of the address, so changing it later means moving the coins again. Both
 * are said on the page rather than discovered afterwards.
 */
function drawChainLock(account) {
  const me = state.data.me;
  const mine = state.data.members?.find(m => m.id === me.id);
  const locked = account.quorum;
  const bitcoin = account.network === 'bitcoin';
  $('chain-card').closest('.lane').hidden = !bitcoin;
  if (!bitcoin) return;

  $('chain-state').textContent = locked
    ? `${locked.required} of ${locked.keys.length} on the chain`
    : 'a rule here, not on the chain';
  $('chain-state').classList.toggle('ok', Boolean(locked));
  $('lock-error').textContent = '';

  $('chain-address').hidden = !locked;
  $('chain-previous').hidden = !locked?.previousAddress;
  if (locked) {
    $('chain-address-value').textContent = account.address;
    if (locked.previousAddress) $('chain-previous-value').textContent = locked.previousAddress;
  }

  /* who has a key, and who is still to make one */
  const signers = account.signers;
  $('key-rows').replaceChildren(...(locked ? [] : signers.map(signer => el('div', { class: 'member-row' },
    el('span', { class: 'avatar' }, initials(signer.label)),
    el('span', { class: 'member-who' },
      el('b', {}, signer.label),
      el('small', {}, signer.signingKey ? `${signer.signingKey.slice(0, 10)}…` : 'no signing key yet')),
    el('span', { class: `chip soft ${signer.signingKey ? 'ok' : 'muted'}` }, signer.signingKey ? 'has a key' : 'waiting')))));

  const ready = signers.filter(s => s.signingKey).length;
  const owner = state.data.wallet && me.id === state.data.members?.find(m => m.owner)?.id;

  $('chain-explains').textContent = locked
    ? 'Bitcoin keeps this threshold. Spending takes that many signatures, each from its own signer, and this server cannot produce one.'
    : `Today the threshold is a rule this server remembers: the coins sit behind one key, and whoever holds it could spend alone. Locking moves them into a script naming every signer's key. ${ready} of ${signers.length} signers have made one.`;

  /* the threshold that would be locked in */
  const wanted = state.chainThreshold ?? Math.min(2, signers.length);
  $('chain-threshold').hidden = Boolean(locked) || ready < signers.length || signers.length < 2;
  if (!$('chain-threshold').hidden) {
    $('chain-threshold').replaceChildren(...Array.from({ length: signers.length }, (_, i) => i + 1).map(m => el('button', {
      class: `seg-item${wanted === m ? ' on' : ''}`,
      type: 'button',
      'aria-pressed': wanted === m ? 'true' : 'false',
      onclick: () => { state.chainThreshold = m; drawChainLock(account); },
    }, `${m} of ${signers.length}`)));
  }

  $('chain-note').textContent = locked
    ? 'Coins sent to the old address still arrive there and are still yours; tell people the new one.'
    : 'Locking moves every coin in this account to the new address in one transaction, and the amount steps above stop applying: a script cannot read the amount being sent.';

  /* what there is to do about it */
  const actions = [];
  if (!mine?.signingKey && !locked) {
    actions.push(button('Make my signing key', 'btn brand sm', () => startSigningKey(account)));
  }
  if (!locked && owner && ready === signers.length && signers.length >= 2) {
    actions.push(button(`Lock to ${wanted} of ${signers.length} with a palm scan`, 'btn brand sm', () => startLock(account, wanted)));
  }
  $('chain-actions').replaceChildren(...actions);
}

async function startSigningKey(account) {
  $('lock-error').textContent = '';
  try {
    const owner = state.data.members.find(m => m.owner)?.id ?? state.data.me.id;
    const { operation } = await api('/api/signing-key/approval', { vaultOwnerId: owner });
    openApproval(operation, 'Making your signing key…');
  } catch (error) {
    $('lock-error').textContent = friendly(error);
  }
  void account;
}

async function startLock(account, required) {
  $('chain-error').textContent = '';
  try {
    const asked = await api('/api/accounts/lock', { required });
    openApproval(asked.operation, 'Locking to the chain…');
  } catch (error) {
    $('chain-error').textContent = friendly(error);
  }
  void account;
}

function drawSettings() {
  const draft = state.draft;
  if (!draft) return;
  const count = draft.members.length;
  const account = (state.data?.accounts || []).find(item => item.network === draft.network);

  /* signers */
  $('signer-rows').replaceChildren(...draft.members.map(member => el('div', { class: 'member-row' },
    el('span', { class: 'avatar' }, initials(member.label)),
    el('span', { class: 'member-who' },
      el('b', {}, member.label),
      el('small', {}, [
        member.owner ? 'owner' : null,
        member.id === state.data.me.id ? 'you' : null,
        member.palmId || (member.isNew ? 'palm id on approval' : 'no palm yet'),
      ].filter(Boolean).join(' · '))),
    member.owner
      ? el('span', { class: 'chip soft muted' }, 'always signs')
      : el('button', {
        class: 'icon-btn danger', type: 'button', title: `Remove ${member.label}`, 'aria-label': `Remove ${member.label}`,
        onclick: () => {
          if (!member.isNew) draft.removed.push(member.id);
          draft.members = draft.members.filter(m => m.id !== member.id);
          for (const rule of draft.rules) rule.approvals = Math.min(rule.approvals, draft.members.length);
          drawSettings();
        },
      }, el('span', {}, '\u00d7')))));

  /* the every-amount threshold, as one segmented control */
  const single = draft.rules.length === 1;
  $('presets').replaceChildren(...Array.from({ length: count }, (_, i) => i + 1).map(m => el('button', {
    class: `seg-item${single && draft.rules[0].approvals === m ? ' on' : ''}`,
    type: 'button',
    'aria-pressed': single && draft.rules[0].approvals === m ? 'true' : 'false',
    onclick: () => { draft.rules = [{ upToSats: null, approvals: m }]; drawSettings(); },
  }, `${m} of ${count}`)));

  /* amount steps, only when there is more than the one rule */
  $('rule-rows').replaceChildren(...(single ? [] : draft.rules.map((rule, index) => {
    const last = index === draft.rules.length - 1;
    return el('div', { class: 'rule-row' },
      el('span', { class: 'rule-when' }, last ? 'Anything larger' : 'Up to'),
      last ? el('span', {}) : el('input', {
        class: 'amount-input',
        inputmode: 'numeric',
        value: rule.upToSats === null ? '' : String(rule.upToSats),
        placeholder: 'sats',
        'aria-label': 'Amount limit in satoshis',
        oninput: event => { rule.upToSats = event.target.value === '' ? null : Number(event.target.value); drawSummary(); },
      }),
      stepper(rule.approvals, count, value => { rule.approvals = value; drawSettings(); }),
      last ? el('span', {}) : el('button', {
        class: 'icon-btn', type: 'button', 'aria-label': 'Remove this step',
        onclick: () => { draft.rules.splice(index, 1); draft.rules.at(-1).upToSats = null; drawSettings(); },
      }, el('span', {}, '\u00d7')));
  })));

  $('add-rule').textContent = single ? '+ Different rule for larger amounts' : '+ Add an amount step';
  drawSummary();

  /* the save bar only exists when there is something to save */
  const same = JSON.stringify(draft.rules) === JSON.stringify(account?.policy.rules)
    && draft.removed.length === 0
    && draft.members.length === (account?.signers.length ?? 0);
  const onRules = state.pane === 'account' && state.tab === 'rules';
  $('save-bar').hidden = same || !onRules;
  $('save-settings').disabled = same;
  const added = draft.members.filter(m => m.isNew).length;
  const changes = [
    added ? `${added} signer${added === 1 ? '' : 's'} added` : null,
    draft.removed.length ? `${draft.removed.length} removed` : null,
    JSON.stringify(draft.rules) === JSON.stringify(account?.policy.rules) ? null : 'threshold changed',
  ].filter(Boolean);
  $('change-cost').textContent = same ? '' :
    `${changes.join(' · ')} — needs ${account?.changeRequired ?? 1} palm${(account?.changeRequired ?? 1) === 1 ? '' : 's'} from the current signers.`;
}

/** Plain language, so the rules can be read rather than decoded. */
function drawSummary() {
  const draft = state.draft;
  if (!draft) return;
  const count = draft.members.length;
  const parts = draft.rules.map((rule, index) => (rule.upToSats === null
    ? `${index === 0 ? 'any amount' : 'anything larger'} needs ${rule.approvals} of ${count}`
    : `up to ${fmtSats(rule.upToSats)} sats needs ${rule.approvals} of ${count}`));
  $('threshold-summary').textContent = `In plain words: ${parts.join('; ')}.`;
}

/** A minus/number/plus control: easier to reach than a select, and always in range. */
function stepper(value, max, onChange) {
  const step = delta => onChange(Math.min(max, Math.max(1, value + delta)));
  return el('div', { class: 'stepper' },
    el('button', { class: 'icon-btn', type: 'button', 'aria-label': 'Fewer palms', disabled: value <= 1, onclick: () => step(-1) }, el('span', {}, '\u2212')),
    el('span', { class: 'stepper-value' }, `${value} of ${max}`),
    el('button', { class: 'icon-btn', type: 'button', 'aria-label': 'More palms', disabled: value >= max, onclick: () => step(1) }, el('span', {}, '+')));
}

$('add-rule').addEventListener('click', () => {
  const draft = state.draft;
  const last = draft.rules.at(-1);
  draft.rules.splice(draft.rules.length - 1, 0, {
    upToSats: 100_000,
    approvals: Math.max(1, Math.min(last.approvals - 1, draft.members.length)),
  });
  drawSettings();
});

$('discard-settings').addEventListener('click', () => {
  state.draft = null;
  if (state.data) renderAccount(state.data);
});

/* ------------------------------------------------------- invitations */

/*
 * Adding a signer is an invitation, not an edit. The vault's own quorum authorises it, the
 * code that comes out is passed to the person by hand, and their palm is what redeems it.
 * Nobody is added to an account because someone typed their name.
 */
$('add-member').addEventListener('click', () => {
  const account = accountNow();
  if (!account) return;
  $('invite-error').textContent = '';
  $('invite-name').value = '';
  $('invite-explains').textContent =
    `Creating the invitation takes ${account.changeRequired} palm approval${account.changeRequired === 1 ? '' : 's'} from the signers of the ${account.label} account. You will get a code to send them.`;
  $('invite').showModal();
  $('invite-name').focus();
});
const closeInvite = () => $('invite').close();
$('invite-cancel').addEventListener('click', closeInvite);
$('invite-close').addEventListener('click', closeInvite);

$('invite-form').addEventListener('submit', async event => {
  event.preventDefault();
  const label = $('invite-name').value.trim();
  $('invite-error').textContent = '';
  if (!label) {
    $('invite-error').textContent = 'Give them a name, so the other signers know who this is.';
    return;
  }
  try {
    const { operation } = await api('/api/invites/approval', { network: state.account, label });
    $('invite').close();
    openApproval(operation, 'Creating the invitation…');
  } catch (error) {
    $('invite-error').textContent = friendly(error);
  }
});

/** Shows a code that now exists, big enough to read out over a phone. */
function showInviteCode(code, label) {
  if (!code) return;
  $('invite-code-for').textContent = label ? `Send this code to ${label}.` : 'Send this code to them.';
  $('invite-code-value').textContent = code;
  state.lastInvite = code;
  $('invite-code').showModal();
}
const closeInviteCode = () => $('invite-code').close();
$('invite-code-done').addEventListener('click', closeInviteCode);
$('invite-code-ok').addEventListener('click', closeInviteCode);
$('invite-code-copy').addEventListener('click', () => copy(state.lastInvite ?? '', 'Invitation code copied.'));

/* The other side of it: redeeming a code with your own palm. */
function openJoin() {
  $('join-error').textContent = '';
  $('join-code').value = '';
  $('join').showModal();
  $('join-code').focus();
}
$('join-vault').addEventListener('click', openJoin);
$('join-vault-empty').addEventListener('click', openJoin);
$('join-cancel').addEventListener('click', () => $('join').close());
$('join-close').addEventListener('click', () => $('join').close());

$('join-form').addEventListener('submit', async event => {
  event.preventDefault();
  const code = $('join-code').value.trim();
  $('join-error').textContent = '';
  if (!code) {
    $('join-error').textContent = 'Type the code you were sent.';
    return;
  }
  try {
    const { operation } = await api('/api/invites/join', { code });
    $('join').close();
    openApproval(operation, 'Joining the vault…');
  } catch (error) {
    $('join-error').textContent = friendly(error);
  }
});

/** The invitations this account has out, waiting to be redeemed. */
async function drawInvites(account) {
  let invites = [];
  try {
    ({ invites } = await api('/api/invites'));
  } catch {
    invites = [];
  }
  const mine = invites.filter(invite => invite.network === account.network);
  $('invite-rows').replaceChildren(...mine.map(invite => el('div', { class: 'invite-row' },
    el('span', { class: 'avatar ghost' }, initials(invite.label)),
    el('span', { class: 'member-who' },
      el('b', {}, `${invite.label} — invited`),
      el('small', {}, `${invite.code} · expires ${when(invite.expiresAt)}`)),
    button('Copy', 'link', () => copy(invite.code, 'Invitation code copied.')),
    button('Cancel', 'link', async () => {
      await api('/api/invites/cancel', { code: invite.code }).catch(error => toast(friendly(error)));
      refresh().catch(() => {});
    }))));
}

const accountNow = () => (state.data?.accounts || []).find(item => item.network === state.account);

$('open-rules').addEventListener('click', () => openAccount(state.account, 'rules'));
$('account-send').addEventListener('click', () => openAccount(state.account, 'send'));
$('account-receive').addEventListener('click', () => openAccount(state.account, 'receive'));

$('save-settings').addEventListener('click', async () => {
  $('rules-error').textContent = '';
  const draft = state.draft;
  const add = draft.members.filter(m => m.isNew).map(m => ({ code: m.id, label: m.label }));
  $('save-settings').disabled = true;
  try {
    const { operation } = await api('/api/policy', {
      network: draft.network, rules: draft.rules, add, remove: draft.removed,
    });
    openApproval(operation, 'Applying the new settings…');
  } catch (error) {
    $('rules-error').textContent = friendly(error);
    $('save-settings').disabled = false;
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
$('restore-close').addEventListener('click', () => $('restore').close());

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

/**
 * Compares the vault's key lineage with the root this device pinned when the vault was made,
 * and verifies the chain here rather than believing the server's summary of it. A mismatch is
 * the shape a substituted key would take, so sending is blocked until it is explained.
 */
function checkLineage(data) {
  const wallet = data.wallet;
  const attestation = wallet?.attestation;
  const pinned = device.record?.attestationRootKeyId ?? null;
  const problem = !attestation
    ? (wallet?.custody === 'client'
      ? 'This vault has no authorisation key yet. Register one in Settings — it takes one palm scan, and the key comes from the recovery phrase you already have.'
      : null)
    : attestation.broken ? `This vault's key lineage does not verify: ${attestation.broken}. Register a key again in Settings.`
      : pinned && attestation.rootKeyId !== pinned
        ? 'The authorisation key this server reports did not come from this device. Do not send anything until you know why.'
        : null;

  state.lineage = { ok: !problem, problem, attestation, pinned };
  $('lineage-warning').textContent = problem ?? '';
  $('lineage-warning').hidden = !problem;
  const form = $('send-form');
  if (problem) form.hidden = true;
}

/* ------------------------------------------------------------ receipt */

function showReceipt(receipt, txid) {
  if (!receipt || receipt.error) return;
  const record = receipt.authorization.record;
  const checked = receipt.checked?.ok;
  $('receipt-headline').textContent = 'Transaction authorised.';
  $('receipt-ticks').replaceChildren(
    el('li', {}, 'A palm approval was verified for this exact transaction'),
    el('li', {}, `Signed by your vault's own key, ${receipt.algorithm} · ${receipt.keyId ?? 'unknown'}`),
    el('li', { class: receipt.chain?.ok ? '' : 'unchecked' }, receipt.chain?.ok
      ? `Key lineage checked here: epoch ${receipt.chain.epoch}, from ${receipt.chain.rootKeyId}`
      : `Key lineage did not verify: ${receipt.chain?.reason ?? 'unknown'}`),
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
    key: `${receipt.algorithm} · ${receipt.keyId} · held by this vault`,
    ...(txid ? { txid } : {}),
  }));
  state.receipt = receipt;
  $('receipt').showModal();
}

const closeReceipt = () => $('receipt').close();
$('receipt-done').addEventListener('click', closeReceipt);
$('receipt-ok').addEventListener('click', closeReceipt);
$('receipt-copy').addEventListener('click', () => {
  if (state.receipt) copy(JSON.stringify(state.receipt.authorization, null, 2), 'Authorisation record copied.');
});

/* ----------------------------------------------------------- approval */

const DETAIL_LABELS = {
  action: 'Action', network: 'Network', to: 'To', amount_sats: 'Amount', fee_sats: 'Fee', fee_rate: 'Fee rate',
  change_sats: 'Change back', spends: 'Coins spent', approvals_required: 'Approvals', rules: 'New settings',
  approvers: 'Signers', spending_rule: 'Rule', owner_label: 'Your name', derived_from: 'Address from',
  transaction_hash: 'Transaction hash', vault: 'Vault', approvals: 'Approvals', method: 'Approved by',
  approved_at: 'Approved at', key: 'Authorisation key', txid: 'Transaction ID',
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
    attestation: 'Palm approval · authorisation key',
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
      // A co-signer completes the quorum; only the vault owner's device can sign the coins away.
      if (operation.walletOwner !== state.data?.me?.id || !device.holdsKeyFor(state.data?.wallet)) {
        toast('Approved. The vault owner’s device will sign and send it.');
        return refresh().catch(() => {});
      }
      toast('Human verified. Signing on this device…');
      const { txid, receipt } = await device.send(operation);
      toast(`Sent. Transaction ${shortId(txid)} is on the network.`);
      showReceipt(receipt, txid);
      $('send-form').reset();
      $('send-amount').disabled = false;
    } else if (operation.kind === 'recovery') {
      if (state.recoveryIntent === 'restore') await showRestore(operation);
      else await showPhrase(operation);
    } else if (operation.kind === 'invite') {
      // The code exists only once the approvals have landed, so it comes back with the settled
      // operation; if that raced, the vault view has it a moment later.
      let code = operation.inviteCode;
      if (!code) {
        const data = await api('/api/wallet');
        code = [...(data.history || []), ...(data.pending || [])].find(item => item.id === operation.id)?.inviteCode;
      }
      showInviteCode(code, operation.details?.invitee);
    } else if (operation.kind === 'join') {
      toast('You are a signer on that vault now. Its requests will appear here.');
    } else if (operation.kind === 'signing') {
      const { signingKey } = await device.makeSigningKey(operation);
      toast(`Signing key ready: ${signingKey.slice(0, 10)}…`);
    } else if (operation.kind === 'lock') {
      if (operation.details?.transaction_hash) {
        toast('Moving the coins into the script…');
        const { txid } = await device.send(operation);
        toast(`Locked to the chain. The coins are on their way (${shortId(txid)}).`);
      } else {
        toast('Locked to the chain.');
      }
    } else if (operation.kind === 'attestation') {
      const { attestation } = await device.rotateAttestation(operation);
      toast(attestation.epoch === 1
        ? `Authorisation key registered: ${attestation.keyId}. You can send again.`
        : `Authorisation key replaced: ${attestation.keyId} (epoch ${attestation.epoch}).`);
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
