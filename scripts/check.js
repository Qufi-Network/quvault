/*
 * Live checks against a deployed QuVault, the real Veyns sandbox and the real Bitcoin API.
 *
 *   npm run check -- https://quvault-one.vercel.app
 *
 * Everything a script can prove without a person: settings, database, signing keys, whether
 * Veyns accepts this origin for sign-in and for approvals, the backend credential (if
 * VEYNS_BACKEND_SECRET is in a local .env) and the Bitcoin network service.
 * The palm scans themselves need a real person and a real hand.
 */
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
try { process.loadEnvFile(path.join(root, '.env')); } catch { /* optional */ }

const appUrl = (process.argv[2] || process.env.PUBLIC_ORIGIN || '').replace(/\/$/, '');
const secret = process.env.VEYNS_BACKEND_SECRET || '';
if (!appUrl) {
  console.error('Usage: npm run check -- https://your-wallet.vercel.app');
  process.exit(2);
}

let failures = 0;
const pass = (name, detail = '') => console.log(`  ✔ ${name}${detail ? ` — ${detail}` : ''}`);
const fail = (name, detail = '') => { failures++; console.log(`  ✖ ${name}${detail ? ` — ${detail}` : ''}`); };
const skip = (name, detail = '') => console.log(`  – ${name}${detail ? ` — ${detail}` : ''}`);
const b64 = bytes => crypto.randomBytes(bytes).toString('base64url');

async function http(url, init = {}) {
  const response = await fetch(url, { ...init, signal: AbortSignal.timeout(20_000) });
  const text = await response.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* HTML error pages */ }
  return { status: response.status, json, plain: text.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 160) };
}
const describe = r => (r.json ? r.json.error_description || r.json.error || JSON.stringify(r.json).slice(0, 160) : r.plain);

/** Starts a ceremony exactly as veyns.js does, from the app's origin. Nothing is approved. */
function prepare(issuer, clientId, intent, extra = {}) {
  const verifier = b64(48);
  return http(`${issuer}/v1/authorize/prepare`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: appUrl },
    body: JSON.stringify({
      response_type: 'code', response_mode: 'web_message', client_id: clientId,
      redirect_uri: `${appUrl}/`, scope: `openid ${intent}`, state: b64(16), nonce: b64(24),
      code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url'),
      code_challenge_method: 'S256', intent, ...extra,
    }),
  });
}

console.log(`\nApp: ${appUrl}`);
const config = await http(`${appUrl}/api/config`);
const c = config.json || {};
if (config.status !== 200) {
  fail('settings', `HTTP ${config.status}: ${describe(config)}`);
  process.exit(1);
}
c.configured ? pass('Veyns client ID', c.clientId) : fail('Veyns client ID', 'set VEYNS_CLIENT_ID and redeploy');
c.palmEnabled ? pass('backend credential', 'VEYNS_BACKEND_SECRET is set') : fail('backend credential', 'add VEYNS_BACKEND_SECRET and redeploy');
c.vaultReady ? pass('vault seed', 'WALLET_SEED is set, wallet keys can be sealed') : fail('vault seed', 'run npm run keygen, set WALLET_SEED and redeploy');
c.publicOrigin === appUrl ? pass('origin', c.publicOrigin) : fail('origin', `the app thinks it is ${c.publicOrigin}; set PUBLIC_ORIGIN=${appUrl}`);
pass('network', c.network);

const login = await http(`${appUrl}/api/login/start`, {
  method: 'POST', headers: { origin: appUrl, 'content-type': 'application/json' }, body: '{}',
});
if (login.status === 200) pass('database', 'sign-in nonce written');
else if (login.status === 409 && !c.configured) skip('database', 'cannot be checked until the client ID is set');
else fail('database', `HTTP ${login.status}: ${describe(login)}`);

const issuer = c.issuer;
console.log(`\nVeyns: ${issuer}`);
const jwks = await http(`${issuer}/jwks.json`);
const ecKeys = (jwks.json?.keys || []).filter(k => k.kty === 'EC' && k.crv === 'P-256' && k.kid);
let imported = 0;
for (const k of ecKeys) {
  try { crypto.createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: k.x, y: k.y }, format: 'jwk' }); imported++; } catch { /* counted below */ }
}
imported && imported === ecKeys.length ? pass('signing keys', `${imported} ES256 key(s) load`) : fail('signing keys', `${imported}/${ecKeys.length} usable`);

if (c.clientId) {
  for (const [name, request] of [
    ['browser sign-in', prepare(issuer, c.clientId, 'login')],
    ['palm sign-in', prepare(issuer, c.clientId, 'login', { required_method: 'palm' })],
    ['approval', prepare(issuer, c.clientId, 'action', { action: { statement: 'QuVault live check', details: { check: true } } })],
  ]) {
    const r = await request;
    const target = r.json?.authorization_url ? new URL(r.json.authorization_url) : null;
    if (r.status < 300 && target?.origin === new URL(issuer).origin && target.pathname === '/authorize') pass(name, 'ceremony can start');
    else fail(name, `HTTP ${r.status}: ${describe(r)}`);
  }
}

const anonymous = await http(`${issuer}/v1/approvals/${b64(24)}`);
anonymous.status === 401 ? pass('approvals API refuses anonymous calls') : fail('approvals API refuses anonymous calls', `HTTP ${anonymous.status}`);
if (secret && c.clientId) {
  const authorization = 'Basic ' + Buffer.from(`${c.clientId}:${secret}`).toString('base64');
  const probe = await http(`${issuer}/v1/approvals/${b64(24)}`, { headers: { authorization } });
  if (probe.status === 401) fail('credential accepted', 'Veyns rejected it: create or rotate it in the console');
  else if (probe.status === 404) pass('credential accepted', 'Veyns authenticated the app');
  else skip('credential accepted', `unexpected HTTP ${probe.status}`);
} else {
  skip('credential accepted', 'set VEYNS_BACKEND_SECRET in a local .env to check it from here');
}

const chainApi = process.env.CHAIN_API || 'https://mempool.space/testnet4/api';
console.log(`\nBitcoin: ${chainApi}`);
const fees = await http(`${chainApi}/v1/fees/recommended`);
fees.status === 200 && fees.json?.halfHourFee ? pass('fee rates', `${fees.json.halfHourFee} sat/vB suggested`) : fail('fee rates', `HTTP ${fees.status}`);
const tip = await http(`${chainApi}/blocks/tip/height`);
tip.status === 200 ? pass('chain tip', `block ${tip.plain}`) : fail('chain tip', `HTTP ${tip.status}`);

console.log(failures ? `\n${failures} check(s) need attention.\n` : '\nEverything a script can check is working. Next: sign in and create the vault with a palm scan.\n');
process.exit(failures ? 1 : 0);
