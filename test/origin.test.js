/*
 * What is allowed to run on the vault's own origin.
 *
 * A script here could read the encrypted phrase out of IndexedDB and the unlock secret as it
 * arrives, so the answer has to be nothing but our own — including the identity provider's
 * script, which is why sign-in is a redirect rather than an SDK.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { start, ISSUER, ORIGIN } from './harness.js';

const PUBLIC = fileURLToPath(new URL('../public', import.meta.url));

/**
 * The page as a browser really receives it. The harness replaces fetch, so this goes direct,
 * and it names the canonical host so the app serves the page rather than redirecting to it.
 */
const pageHeaders = port => new Promise((resolve, reject) => {
  http.get({ host: '127.0.0.1', port, path: '/', headers: { host: new URL(ORIGIN).host } }, res => {
    res.resume();
    res.on('end', () => (res.statusCode === 200
      ? resolve(res.headers)
      : reject(new Error(`the page answered ${res.statusCode}`))));
  }).on('error', reject);
});

/** The policy as the page really receives it, parsed into directives. */
async function policyFrom(headers) {
  const value = headers['content-security-policy'];
  assert.ok(value, 'every page must carry a policy');
  return Object.fromEntries(value.split(';').map(part => {
    const [name, ...rest] = part.trim().split(/\s+/);
    return [name, rest];
  }));
}

test('nothing but this origin may execute, not even the identity provider', async t => {
  const env = await start(t, { publicDir: PUBLIC });
  const csp = await policyFrom(await pageHeaders(env.app.server.address().port));

  assert.deepEqual(csp['script-src'], ["'self'"], 'the issuer must not be a script source');
  assert.deepEqual(csp['object-src'], ["'none'"]);
  assert.deepEqual(csp['frame-src'], ["'none'"]);
  assert.deepEqual(csp['frame-ancestors'], ["'none'"]);
  assert.deepEqual(csp['base-uri'], ["'none'"]);
  assert.deepEqual(csp['default-src'], ["'self'"]);

  // Talking to the issuer is the point; loading its code is not.
  assert.ok(csp['connect-src'].includes(ISSUER), 'sign-in still needs to reach the issuer');
  assert.ok(!csp['img-src'].includes(ISSUER), 'and nothing else comes from there');
});

test('the page never asks for a script from anywhere else', async t => {
  const html = fs.readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
  const sources = [...html.matchAll(/<script[^>]*\ssrc=["']([^"']+)["']/g)].map(m => m[1]);
  for (const src of sources) {
    assert.ok(src.startsWith('/'), `index.html loads a script from ${src}`);
  }

  const client = fs.readFileSync(new URL('../public/app.js', import.meta.url), 'utf8');
  assert.doesNotMatch(client, /veyns\.js/, 'the Veyns SDK must not be loaded');
  assert.doesNotMatch(client, /window\.veyns/, 'nor called');
  assert.doesNotMatch(client, /createElement\(['"]script['"]\)/, 'and no script is injected at all');
});

test('the policy served by the CDN is the policy served by the function', async t => {
  // index.html comes from Vercel's edge, the API from the function. Two places to write the
  // same rule is two places for it to drift, so they are compared rather than trusted.
  const env = await start(t, { publicDir: PUBLIC });
  const fromFunction = (await pageHeaders(env.app.server.address().port))['content-security-policy'];

  const vercel = JSON.parse(fs.readFileSync(new URL('../vercel.json', import.meta.url), 'utf8'));
  const fromEdge = vercel.headers
    .flatMap(entry => entry.headers)
    .find(header => header.key === 'Content-Security-Policy')?.value;

  assert.ok(fromEdge, 'vercel.json must set a policy for the static page');
  const normalise = value => value.replace(ISSUER, '<issuer>').replace('https://sandbox.id.veyns.io', '<issuer>');
  assert.equal(normalise(fromFunction), normalise(fromEdge));
});
