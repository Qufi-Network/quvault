const $ = id => document.getElementById(id);

const VIEWS = ['loading', 'setup', 'signin', 'create', 'wallet'];
const state = { config: null, wallet: null, loginNonce: null };
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
    else node.setAttribute(key, value);
  }
  node.append(...children.flat().filter(child => child != null && child !== false));
  return node;
}

const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
const btc = sats => (sats / 1e8).toFixed(8);
const fmtSats = sats => Number(sats).toLocaleString('en-US');
const shortId = id => `${id.slice(0, 10)}…${id.slice(-6)}`;

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
  state.wallet = data;
  if (!data.wallet) {
    show('create');
    return;
  }
  renderWallet(data);
  show('wallet');
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

/* ------------------------------------------------------------ sign-in */

async function showSignin() {
  show('signin');
  $('signin-browser').hidden = state.config.requirePalmSignin;
  $('signin-browser').disabled = $('signin-palm').disabled = true;
  try {
    // Both must be ready before the click: the Veyns window has to open straight from the gesture.
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
  state.wallet = null;
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

/** The same code + PKCE flow veyns.js runs in its pop-up, but in this tab. */
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

/* -------------------------------------------------------- the wallet */

$('create-wallet').addEventListener('click', async () => {
  $('create-error').textContent = '';
  $('create-wallet').disabled = true;
  try {
    const { approval } = await api('/api/wallet/approval', {});
    openApproval(approval, 'Creating the vault…');
  } catch (error) {
    $('create-error').textContent = friendly(error);
  } finally {
    $('create-wallet').disabled = false;
  }
});

function renderWallet(data) {
  const { wallet, balance, spendable, coins, history, feeRate, qr, chainError, openApproval: pending } = data;
  $('address').textContent = wallet.address;
  $('explorer-link').href = wallet.explorer;
  if (qr) $('qr').innerHTML = qr; // A QR code this server generated; no external content.

  $('balance').textContent = btc(balance ? balance.confirmed + balance.pending : 0);
  const notes = [];
  if (balance?.pending) notes.push(`${fmtSats(balance.pending)} sats still unconfirmed`);
  if (coins) notes.push(`${coins} spendable coin${coins === 1 ? '' : 's'} (${fmtSats(spendable)} sats)`);
  else if (balance && !balance.txCount) notes.push('No coins yet — send test coins to the address on the right.');
  notes.push(`Key sealed with ${wallet.protection}`);
  $('balance-note').textContent = notes.join(' · ');
  $('chain-error').textContent = chainError || '';
  $('fee-note').textContent = feeRate ? `Network suggests ${feeRate} sat/vB` : '';

  renderHistory(history || [], data.withdrawals || []);
  if (pending && !active) openApproval(pending, pending.kind === 'create' ? 'Creating the vault…' : 'Sending…');
}

function renderHistory(chain, withdrawals) {
  const failed = withdrawals.filter(w => w.status === 'failed').map(w => el('li', {},
    el('span', { class: 'what' }, w.statement, el('small', {}, w.error || 'Failed')),
    el('time', {}, new Date(w.at * 1000).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })),
    el('span', { class: 'amt failed' }, 'failed')));

  const rows = chain.map(tx => {
    const incoming = tx.deltaSats > 0;
    return el('li', {},
      el('span', { class: 'what' },
        incoming ? 'Received' : 'Sent',
        el('small', {}, shortId(tx.txid), tx.confirmed ? '' : ' · waiting for confirmation')),
      el('time', {}, tx.at ? new Date(tx.at * 1000).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'pending'),
      el('a', { class: `amt ${incoming ? 'plus' : 'minus'}`, href: tx.explorer, target: '_blank', rel: 'noopener' },
        `${incoming ? '+' : '−'}${btc(Math.abs(tx.deltaSats))}`));
  });

  const all = [...failed, ...rows];
  $('history').replaceChildren(...(all.length ? all : [el('li', { class: 'empty' }, 'Nothing yet.')]));
}

$('copy-address').addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText($('address').textContent);
    toast('Address copied.');
  } catch {
    toast('Select the address and copy it.');
  }
});

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
    const { approval } = await api('/api/withdrawals', {
      to: $('send-to').value.trim(),
      amount: max ? 'max' : Number($('send-amount').value),
      ...($('send-fee').value ? { feeRate: Number($('send-fee').value) } : {}),
    });
    openApproval(approval, 'Sending…');
  } catch (error) {
    $('send-error').textContent = friendly(error);
  } finally {
    if (submit) submit.disabled = false;
  }
});

/* ----------------------------------------------------------- approval */

const DETAIL_LABELS = {
  action: 'Action', network: 'Network', to: 'To', amount_sats: 'Amount', fee_sats: 'Fee', fee_rate: 'Fee rate',
  change_sats: 'Change back', spends: 'Coins spent', spending_rule: 'Rule',
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

async function openApproval(approval, busyText) {
  active = { approval, busyText };
  $('approval-kind').textContent = approval.kind === 'create' ? 'Palm approval · new vault' : 'Palm approval · withdrawal';
  $('approval-statement').textContent = approval.statement;
  $('approval-details').replaceChildren(...detailRows(approval.details));
  $('approval-error').textContent = '';
  $('approval-wait-text').textContent = 'Sending the request to your Veyns app…';
  $('approval-open').hidden = true;
  $('approval-cancel').textContent = 'Cancel';
  $('approval').showModal();

  try {
    const result = await api(`/api/approvals/${approval.id}/palm`, {});
    if (active?.approval.id !== approval.id) return;
    active.approval = result.approval;
    $('approval-wait-text').textContent = 'Open Veyns on your phone, check the request and scan your palm.';
    $('approval-open').hidden = !result.approval.approvalUrl;
    pollApproval(active);
  } catch (error) {
    if (active?.approval.id === approval.id) closedWith(friendly(error));
  }
}

function closedWith(message) {
  $('approval-error').textContent = message;
  $('approval-wait').hidden = true;
  $('approval-cancel').textContent = 'Close';
}

$('approval-open').addEventListener('click', () => {
  if (active?.approval.approvalUrl) window.open(active.approval.approvalUrl, 'veyns-approval', 'popup=yes,width=420,height=640,noopener');
});

async function pollApproval(current) {
  const deadline = Date.now() + 330_000;
  while (active === current && Date.now() < deadline) {
    await wait(2500);
    if (active !== current) return;
    try {
      const { approval } = await api(`/api/approvals/${current.approval.id}`);
      if (active !== current) return;
      if (approval.status === 'approved') {
        $('approval-wait-text').textContent = current.busyText;
        return settled(current, approval);
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

function settled(current, approval) {
  if (active !== current) return;
  active = null;
  $('approval').close();
  $('approval-wait').hidden = false;
  if (approval.kind === 'create') toast('Vault created. Its key is sealed and only your palm can spend from it.');
  else if (approval.txid) toast(`Sent. Transaction ${shortId(approval.txid)} is on the network.`);
  else toast('Approved.');
  if (approval.kind === 'withdraw') {
    $('send-form').reset();
    $('send-amount').disabled = false;
  }
  refresh().catch(() => {});
}

async function dismissApproval() {
  const current = active;
  active = null;
  $('approval').close();
  $('approval-wait').hidden = false;
  if (!current) return;
  await api(`/api/approvals/${current.approval.id}/cancel`, {}).catch(() => {});
  refresh().catch(() => {});
}

$('approval-cancel').addEventListener('click', dismissApproval);
$('approval').addEventListener('cancel', event => {
  event.preventDefault();
  dismissApproval();
});

/* -------------------------------------------------------------- start */

$('retry').addEventListener('click', boot);

// Coins arrive without telling us: check every 20 seconds while the wallet is on screen.
setInterval(() => {
  if (state.wallet?.wallet && !active && !document.hidden) refresh().catch(() => {});
}, 20_000);

boot();
