const $ = id => document.getElementById(id);

const VIEWS = ['loading', 'setup', 'signin', 'create', 'wallet'];
const state = { config: null, data: null, loginNonce: null };
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
  if (!data.wallet) {
    $('my-code').textContent = data.me.code;
    renderRequests($('create-pending'), data.pending);
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
  $('address').textContent = wallet.address;
  $('explorer-link').href = wallet.explorer;
  if (qr) $('qr').innerHTML = qr; // A QR code this server generated; no external content.
  $('my-code').textContent = me.code;

  $('balance').textContent = btc(balance ? balance.confirmed + balance.pending : 0);
  const notes = [];
  if (balance?.pending) notes.push(`${fmtSats(balance.pending)} sats still unconfirmed`);
  if (coins) notes.push(`${coins} spendable coin${coins === 1 ? '' : 's'} (${fmtSats(spendable)} sats)`);
  else if (balance && !balance.txCount) notes.push('No coins yet — send test coins to the address on the right.');
  notes.push(`Key sealed with ${wallet.protection}`);
  $('balance-note').textContent = notes.join(' · ');
  $('chain-error').textContent = chainError || '';
  $('fee-note').textContent = feeRate ? `Network suggests ${feeRate} sat/vB` : '';

  $('rule-list').replaceChildren(...policy.rules.map(rule => el('li', {},
    el('span', {}, rule.upToSats === null ? 'Any larger amount' : `Up to ${fmtSats(rule.upToSats)} sats`),
    el('b', {}, `${rule.approvals} palm${rule.approvals === 1 ? '' : 's'}`))));
  $('member-list').replaceChildren(...members.map(m => el('span', { class: 'member' },
    m.label, m.owner ? el('small', {}, 'owner') : null, m.id === me.id ? el('small', {}, 'you') : null)));

  renderRequests($('pending'), data.pending);
  $('pending-lane').hidden = data.pending.length === 0;
  renderHistory(chainHistory || [], data.history || []);
}

/** One card per request waiting for palms, with who has approved so far. */
function renderRequests(container, requests) {
  const { me, labels = {} } = state.data;
  container.replaceChildren(...requests.map(op => {
    const done = op.approvedBy.length;
    const mine = op.mine;
    const actions = el('div', { class: 'row' });
    if (op.status === 'collecting' && (!mine || mine.status !== 'approved')) {
      actions.append(button('Approve with palm', 'btn brand small', () => approveRequest(op)));
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

function renderHistory(chain, operations) {
  const rows = operations.filter(op => op.kind !== 'create').map(op => el('li', {},
    el('span', { class: 'what' }, op.statement,
      el('small', {}, op.error || (op.txid ? shortId(op.txid) : op.status))),
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

async function approveRequest(op) {
  openApproval(op, op.kind === 'withdraw' ? 'Sending…' : op.kind === 'policy' ? 'Applying the new rules…' : 'Creating the vault…');
}

async function cancelRequest(op) {
  if (!confirm(`Cancel this request?\n\n${op.statement}`)) return;
  await api(`/api/operations/${op.id}/cancel`, {}).catch(error => toast(friendly(error)));
  refresh().catch(() => {});
}

/* ---------------------------------------------------------- the rules */

let editing = null;

$('edit-rules').addEventListener('click', () => {
  const { policy, members, me } = state.data;
  editing = {
    rules: policy.rules.map(r => ({ ...r })),
    members: members.map(m => ({ ...m })),
    removed: [],
    meId: me.id,
  };
  $('rules-error').textContent = '';
  $('new-member-code').value = '';
  $('new-member-label').value = '';
  drawEditor();
  $('rules-editor').showModal();
});

function drawEditor() {
  $('rule-rows').replaceChildren(...editing.rules.map((rule, index) => {
    const last = index === editing.rules.length - 1;
    return el('div', { class: 'rule-row' },
      el('input', {
        inputmode: 'numeric', placeholder: last ? 'any amount' : 'limit in sats',
        value: rule.upToSats === null ? '' : String(rule.upToSats), disabled: last,
        oninput: event => { rule.upToSats = event.target.value === '' ? null : Number(event.target.value); },
      }),
      el('input', {
        inputmode: 'numeric', value: String(rule.approvals), class: 'narrow',
        oninput: event => { rule.approvals = Number(event.target.value); },
      }),
      el('span', { class: 'quiet small' }, 'palms'),
      editing.rules.length > 1 ? button('Remove', 'link', () => {
        editing.rules.splice(index, 1);
        editing.rules.at(-1).upToSats = null;
        drawEditor();
      }) : null);
  }));

  $('member-rows').replaceChildren(...editing.members.map(member => el('div', { class: 'member-row' },
    el('span', {}, member.label, member.owner ? el('small', {}, 'owner') : null),
    member.owner ? null : button('Remove', 'link', () => {
      editing.removed.push(member.id);
      editing.members = editing.members.filter(m => m.id !== member.id);
      drawEditor();
    }))));

  const required = Math.max(1, ...state.data.policy.rules.map(r => r.approvals));
  $('rules-required').textContent = `This change needs ${Math.min(required, state.data.members.length)} palm approval${required === 1 ? '' : 's'}.`;
}

$('add-rule').addEventListener('click', () => {
  const last = editing.rules.at(-1);
  editing.rules.splice(editing.rules.length - 1, 0, { upToSats: last.upToSats ?? 100000, approvals: last.approvals });
  drawEditor();
});

$('rules-cancel').addEventListener('click', () => $('rules-editor').close());

$('rules-form').addEventListener('submit', async event => {
  event.preventDefault();
  $('rules-error').textContent = '';
  const add = [];
  if ($('new-member-code').value.trim()) {
    add.push({ code: $('new-member-code').value.trim(), label: $('new-member-label').value.trim() });
  }
  try {
    const { operation } = await api('/api/policy', { rules: editing.rules, add, remove: editing.removed });
    $('rules-editor').close();
    openApproval(operation, 'Applying the new rules…');
  } catch (error) {
    $('rules-error').textContent = friendly(error);
  }
});

/* ----------------------------------------------------------- approval */

const DETAIL_LABELS = {
  action: 'Action', network: 'Network', to: 'To', amount_sats: 'Amount', fee_sats: 'Fee', fee_rate: 'Fee rate',
  change_sats: 'Change back', spends: 'Coins spent', approvals_required: 'Approvals', rules: 'New rules',
  approvers: 'Approvers', spending_rule: 'Rule', owner_label: 'Your name',
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

/** Opens the sheet and asks Veyns for this person's palm request. */
async function openApproval(operation, busyText) {
  active = { operation, busyText };
  const kinds = { create: 'Palm approval · new vault', withdraw: 'Palm approval · withdrawal', policy: 'Palm approval · rules' };
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

function settled(current, operation) {
  if (active !== current) return;
  active = null;
  $('approval').close();
  $('approval-wait').hidden = false;

  if (operation.status === 'failed') toast(operation.error || 'The action failed.');
  else if (operation.status !== 'done') {
    const left = operation.required - operation.approvedBy.length;
    toast(`Approved. Waiting for ${left} more palm approval${left === 1 ? '' : 's'}.`);
  } else if (operation.kind === 'create') toast('Vault created. Its key is sealed and only palm approvals can spend from it.');
  else if (operation.kind === 'policy') toast('New rules are in force.');
  else if (operation.txid) toast(`Sent. Transaction ${shortId(operation.txid)} is on the network.`);
  else toast('Approved.');

  if (operation.kind === 'withdraw' && operation.status === 'done') {
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
  if (current?.approval) await api(`/api/approvals/${current.approval.id}/cancel`, {}).catch(() => {});
  refresh().catch(() => {});
}

$('approval-cancel').addEventListener('click', dismissApproval);
$('approval').addEventListener('cancel', event => {
  event.preventDefault();
  dismissApproval();
});
$('rules-editor').addEventListener('cancel', () => { editing = null; });

/* -------------------------------------------------------------- start */

$('retry').addEventListener('click', boot);

// Coins arrive, and other people approve, without telling us: check every 15 seconds.
setInterval(() => {
  if (state.data && !active && !$('rules-editor').open && !document.hidden) refresh().catch(() => {});
}, 15_000);

boot();
