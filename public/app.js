import {
  accountFrom, clearRecord, decryptMnemonic, encryptMnemonic, fromBase64, jitterFrom,
  loadRecord, makeMnemonic, saveRecord, signPlan,
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

const state = { config: null, data: null, price: null, range: 'week', loginNonce: null, draft: null };
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

  /** Makes the phrase, stores it encrypted, and registers only the public details. */
  async create(operation) {
    const [{ random }, unlocked] = await Promise.all([api('/api/random'), this.unlockFor(operation.id)]);
    const mnemonic = makeMnemonic({
      serverRandom: fromBase64(random),
      jitter: jitterFrom([operation.id, unlocked.salt, screen.width, screen.height]),
    });
    const account = accountFrom(mnemonic);
    const blob = await encryptMnemonic(mnemonic, unlocked.unlock, unlocked.salt);
    await saveRecord({ blob, salt: unlocked.salt, address: account.address, publicKey: toHex(account.publicKey), createdAt: Date.now() });
    await api('/api/wallet/register', {
      operationId: operation.id,
      address: account.address,
      publicKey: toHex(account.publicKey),
    });
    return account;
  },

  /** Signs an approved withdrawal and hands the raw transaction back for broadcasting. */
  async send(operation) {
    if (!this.record) throw new Error('This browser does not hold the key for this wallet.');
    const unlocked = await this.unlockFor(operation.id);
    const mnemonic = await decryptMnemonic(this.record.blob, unlocked.unlock, this.record.salt);
    const signed = signPlan(mnemonic, unlocked.plan, this.record.address);
    return api(`/api/operations/${operation.id}/broadcast`, { hex: signed.hex });
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
  const { wallet, balance, spendable, coins, chainHistory, feeRate, qr, chainError, policy, members, me } = data;
  const total = balance ? balance.confirmed + balance.pending : 0;
  const myName = members.find(m => m.id === me.id)?.label || 'there';
  const hour = new Date().getHours();
  $('greeting').textContent = `Good ${hour < 12 ? 'morning' : hour < 18 ? 'afternoon' : 'evening'}, ${myName}.`;
  $('greeting-note').textContent = `Here is the summary of your ${1} account.`;

  // Receive
  $('address').textContent = wallet.address;
  $('explorer-link').href = wallet.explorer;
  if (qr) $('qr').innerHTML = qr; // A QR code this server generated; no external content.
  $('receive-note').textContent = balance?.txCount ? `${balance.txCount} transaction${balance.txCount === 1 ? '' : 's'} so far.` : '';

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

  const steps = policy.rules.map(rule => (rule.upToSats === null
    ? `anything larger needs ${rule.approvals} of ${members.length}`
    : `up to ${fmtSats(rule.upToSats)} sats needs ${rule.approvals} of ${members.length}`));
  $('send-rule-note').textContent = `Your thresholds: ${steps.join(' · ')}.`;
  $('accounts-note').textContent = `${members.length} signer${members.length === 1 ? '' : 's'} on this vault`;

  renderAccounts(data, total);
  renderSettings(data);
  renderRequests($('pending'), data.pending);
  renderRequests($('send-pending'), data.pending.filter(op => op.kind === 'withdraw'));
  $('pending-lane').hidden = data.pending.length === 0;
  renderHistory(chainHistory || [], data.history || []);
  paintFiat();
}

/** The sidebar list and the account cards: one Bitcoin account today, more later. */
function renderAccounts(data, total) {
  const { wallet, policy, members, coins } = data;
  const strongest = Math.max(...policy.rules.map(rule => rule.approvals));
  const lightest = Math.min(...policy.rules.map(rule => rule.approvals));

  $('account-list').replaceChildren(
    el('button', { class: 'account active', type: 'button', onclick: () => setTab('dashboard') },
      el('span', { class: 'account-mark' }, '₿'),
      el('span', { class: 'account-text' }, el('b', {}, 'Bitcoin account'), el('small', {}, `tBTC ${btc(total)}`))),
  );

  $('accounts').replaceChildren(
    el('article', { class: 'account-card' },
      el('header', {},
        el('span', { class: 'account-mark big' }, '₿'),
        el('div', {}, el('b', {}, 'Bitcoin account'), el('small', {}, wallet.network)),
        el('span', { class: 'chip soft' }, coins ? `${coins} coin${coins === 1 ? '' : 's'}` : 'empty')),
      el('p', { class: 'account-balance' }, btc(total), el('span', { class: 'unit' }, 'tBTC')),
      el('p', { class: 'quiet small', id: 'account-fiat' }, ''),
      el('p', { class: 'quiet small' },
        `${lightest === strongest ? `${strongest}` : `${lightest}–${strongest}`} of ${members.length} palm approval${strongest === 1 && lightest === 1 ? '' : 's'} to spend`),
      el('p', { class: 'account-address' }, wallet.address),
      el('div', { class: 'row' },
        button('Send', 'btn brand small', () => setTab('send')),
        button('Receive', 'btn ghost small', () => setTab('receive')))),
    el('article', { class: 'account-card muted' },
      el('header', {}, el('span', { class: 'account-mark big ghost' }, '+'), el('div', {}, el('b', {}, 'Another account'), el('small', {}, 'later'))),
      el('p', { class: 'quiet small' }, 'Each account joins the same vault and keeps its own signers and thresholds.')),
  );
}

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

const busyText = op => (op.kind === 'withdraw' ? 'Sending…' : op.kind === 'policy' ? 'Applying the new settings…' : 'Creating the vault…');

function renderHistory(chain, operations) {
  const rows = operations.filter(op => op.kind !== 'create').map(op => el('li', {},
    el('span', { class: 'what' }, op.statement, el('small', {}, op.error || (op.txid ? shortId(op.txid) : op.status))),
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

/** The editable copy of signers and thresholds, rebuilt whenever the server view changes. */
function renderSettings(data) {
  const { policy, members, me, wallet } = data;
  state.draft = {
    rules: policy.rules.map(rule => ({ ...rule })),
    members: members.map(member => ({ ...member })),
    removed: [],
  };
  $('my-code').textContent = me.code;
  $('settings-network').textContent = wallet.network;
  $('settings-address').textContent = wallet.address;
  $('settings-protection').textContent = wallet.protection;

  const holds = device.holdsKeyFor(wallet);
  $('device-state').textContent = holds
    ? 'This browser holds the key for this wallet. The server has never seen it.'
    : 'This browser does not hold the key. Restore it here with your twelve words, or use the browser that made the wallet.';
  $('show-phrase').hidden = !holds;
  $('restore-device').hidden = holds;
  const changeCost = Math.min(Math.max(...policy.rules.map(rule => rule.approvals)), members.length);
  $('settings-required').textContent = `Changes here need ${changeCost} palm approval${changeCost === 1 ? '' : 's'}`;
  drawSettings();
}

function drawSettings() {
  const draft = state.draft;
  const count = draft.members.length;

  $('signer-rows').replaceChildren(...draft.members.map(member => el('div', { class: 'member-row' },
    el('span', {}, member.label, member.owner ? el('small', {}, 'owner') : null, member.id === state.data.me.id ? el('small', {}, 'you') : null),
    member.owner ? el('span', { class: 'quiet small' }, 'cannot be removed') : button('Remove', 'link', () => {
      draft.removed.push(member.id);
      draft.members = draft.members.filter(m => m.id !== member.id);
      for (const rule of draft.rules) rule.approvals = Math.min(rule.approvals, draft.members.length);
      drawSettings();
    }))));

  // Quick pick: the common "M of N" choices for every amount.
  const presets = [];
  for (let m = 1; m <= count; m++) presets.push(m);
  $('presets').replaceChildren(
    el('span', { class: 'quiet small' }, 'Every amount:'),
    ...presets.map(m => button(`${m} of ${count}`, `chip pick${draft.rules.length === 1 && draft.rules[0].approvals === m ? ' on' : ''}`, () => {
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

  const same = JSON.stringify(draft.rules) === JSON.stringify(state.data.policy.rules)
    && draft.removed.length === 0
    && draft.members.length === state.data.members.length;
  $('save-settings').disabled = same;
  $('change-cost').textContent = same
    ? 'Nothing changed yet.'
    : `Proposing this asks every required signer for a palm scan.`;
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
    const { operation } = await api('/api/policy', { rules: draft.rules, add, remove: draft.removed });
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

/* ----------------------------------------------------------- approval */

const DETAIL_LABELS = {
  action: 'Action', network: 'Network', to: 'To', amount_sats: 'Amount', fee_sats: 'Fee', fee_rate: 'Fee rate',
  change_sats: 'Change back', spends: 'Coins spent', approvals_required: 'Approvals', rules: 'New settings',
  approvers: 'Signers', spending_rule: 'Rule', owner_label: 'Your name',
};

function detailRows(details) {
  const known = Object.keys(DETAIL_LABELS).filter(key => key in details);
  const rest = Object.keys(details).filter(key => !(key in DETAIL_LABELS));
  return [...known, ...rest].map(key => {
    const raw = details[key];
    const value = key.endsWith('_sats') ? `${fmtSats(raw)} sats (${btc(raw)} tBTC)` : String(raw);
    return el('div', {}, el('dt', {}, DETAIL_LABELS[key] || key), el('dd', {}, value));
  });
}

async function openApproval(operation, busy) {
  active = { operation, busyText: busy };
  const kinds = { create: 'Palm approval · new vault', withdraw: 'Palm approval · withdrawal', policy: 'Palm approval · settings' };
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
      toast('Signing on this device…');
      const { txid } = await device.send(operation);
      toast(`Sent. Transaction ${shortId(txid)} is on the network.`);
      $('send-form').reset();
      $('send-amount').disabled = false;
    } else if (operation.kind === 'recovery') {
      if (state.recoveryIntent === 'restore') await showRestore(operation);
      else await showPhrase(operation);
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
