/*
 * The vault Bitcoin will not let anyone spend without a palm, and the signer that holds the palm
 * key. These tests run without a node; scripts/palm-vault-proof.js puts the same transactions
 * in front of Bitcoin Core's own consensus checks.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import * as btc from '@scure/btc-signer';
import { hex, base64 } from '@scure/base';
import { createKey, publicKeyOf } from '../src/bitcoin.js';
import { canonicalTransaction } from '../src/canonical.js';
import { transactionDigest, actionDigest } from '../src/veyns.js';
import {
  palmVaultOf, planPalmSpend, palmVaultPsbt, signPalmPsbt, finalizePalmPsbt, palmPathOf,
  descriptorChecksum, NUMS_KEY, DEFAULT_RECOVERY_DELAY,
} from '../src/palm-vault.js';
import { createPalmSigner, PalmRefused } from '../src/palm-signer.js';

const DEST = 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx';
const ISSUER = 'https://issuer.test';
const AUDIENCE = 'quvault-test';

/** Stands in for Veyns: real ES256 decision tokens, signed with a key the palm signer pins. */
function mockVeyns() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'ES256' };
  let serial = 0;
  const token = (claims, { key = privateKey, kid = 'k1' } = {}) => {
    const b64 = value => Buffer.from(JSON.stringify(value)).toString('base64url');
    const input = `${b64({ alg: 'ES256', kid, typ: 'JWT' })}.${b64(claims)}`;
    const signature = crypto.sign('sha256', Buffer.from(input), { key, dsaEncoding: 'ieee-p1363' });
    return `${input}.${signature.toString('base64url')}`;
  };
  const decision = (sub, action, at, overrides = {}) => token({
    iss: ISSUER, aud: AUDIENCE, sub, iat: at, exp: at + 300, auth_time: at,
    veyns_intent: 'action', veyns_presence: true, amr: ['veyns:palm'],
    request_id: `req-${++serial}`, request_nonce: `nonce-${serial}`,
    veyns_action: { statement: action.statement, digest: actionDigest(action.statement, action.details) },
    ...overrides,
  });
  return { jwk, token, decision };
}

/** A 2-of-3 vault with its palm signer, some coins, and a planned spend the palms can approve. */
function world({ amountSats = 40_000 } = {}) {
  let time = 1_800_000_000;
  const veyns = mockVeyns();
  const signer = createPalmSigner({
    seed: crypto.randomBytes(32), issuer: ISSUER, audience: AUDIENCE, pinnedKeys: [veyns.jwk], now: () => time,
  });
  const people = { alex: createKey(), bea: createKey(), cara: createKey() };
  const policy = {
    signerKeys: Object.values(people).map(publicKeyOf), required: 2, delay: DEFAULT_RECOVERY_DELAY,
    signerSubs: ['sub-alex', 'sub-bea', 'sub-cara'],
  };
  const vaultId = 'vault-1';
  const vault = palmVaultOf({ palmKey: signer.publicKeyFor(vaultId), ...policy });
  const utxos = [{ txid: 'ab'.repeat(32), vout: 0, value: 100_000 }];
  const spend = (to = DEST, amount = amountSats) => {
    const plan = planPalmSpend({ vault, utxos, toAddress: to, amountSats: amount, feeRate: 2 });
    const digest = transactionDigest(canonicalTransaction({ chain: 'bitcoin', network: 'testnet4', from: vault.address, plan }));
    const action = { statement: `Send ${amount} sats to ${to}`, details: { action: 'withdraw', to, amount_sats: amount, transaction_hash: digest } };
    let psbt = palmVaultPsbt(vault, plan);
    psbt = signPalmPsbt(psbt, people.alex);
    psbt = signPalmPsbt(psbt, people.bea);
    return { plan, action, psbt };
  };
  return { veyns, signer, people, policy, vaultId, vault, spend, now: () => time, advance: s => { time += s; } };
}

const refusedWith = pattern => error => error instanceof PalmRefused && pattern.test(error.message);

/* ------------------------------------------------------------- the vault */

test('the same signers always make the same vault, a standard descriptor with the key path closed', () => {
  const palm = publicKeyOf(createKey());
  const keys = [createKey(), createKey(), createKey()].map(publicKeyOf);
  const one = palmVaultOf({ palmKey: palm, signerKeys: keys, required: 2 });
  const two = palmVaultOf({ palmKey: palm, signerKeys: [...keys].reverse(), required: 2 });
  assert.equal(one.address, two.address, 'key order does not change the vault');
  assert.match(one.address, /^tb1p/, 'a Taproot address');
  assert.equal(hex.encode(one.tapInternalKey), hex.encode(NUMS_KEY), 'the internal key is the provably unspendable point');
  assert.equal(one.delay, 52560, 'the default recovery delay is about a year of blocks');

  const [body, checksum] = one.descriptor.split('#');
  assert.equal(checksum, descriptorChecksum(body));
  assert.match(body, /^tr\(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,\{and_v\(v:pk\([0-9a-f]{64}\),multi_a\(2,[0-9a-f,]+\)\),and_v\(v:older\(52560\),multi_a\(2,[0-9a-f,]+\)\)\}\)$/);
});

test('Bitcoin Core reads the vault exactly as we write it', () => {
  // The BIP380 test vector, and a fixed vault whose checksum and address Bitcoin Core 30.2
  // computed itself (getdescriptorinfo, deriveaddresses on regtest). A wrong polymod constant
  // once got past every other test here; these catch it.
  assert.equal(descriptorChecksum('raw(deadbeef)'), '89f8spxm');
  const key = label => publicKeyOf(crypto.createHash('sha256').update(label).digest());
  const vault = palmVaultOf({
    palmKey: key('palm'), signerKeys: [key('alex'), key('bea'), key('cara')], required: 2, delay: 52560,
    network: { bech32: 'bcrt', pubKeyHash: 0x6f, scriptHash: 0xc4, wif: 0xef },
  });
  assert.equal(vault.descriptor.split('#')[1], 'kd7pqsg5');
  assert.equal(vault.address, 'bcrt1ptfn4ch5rpr5qt6dgya329c09ad2pu7xuwzqluqv2qdlpgc5gycasdrhtgn');
});

test('the normal script needs the palm key first; the recovery script needs only the signers, and only later', () => {
  const { vault } = world();
  const ops = script => btc.Script.decode(script).map(op => (op instanceof Uint8Array ? `<${op.length}>` : op));
  assert.deepEqual(ops(vault.leaves.normal.script),
    ['<32>', 'CHECKSIGVERIFY', '<32>', 'CHECKSIG', '<32>', 'CHECKSIGADD', '<32>', 'CHECKSIGADD', 2, 'NUMEQUAL']);
  assert.deepEqual(ops(vault.leaves.recovery.script),
    ['<3>', 'CHECKSEQUENCEVERIFY', 'VERIFY', '<32>', 'CHECKSIG', '<32>', 'CHECKSIGADD', '<32>', 'CHECKSIGADD', 2, 'NUMEQUAL']);
  assert.equal(hex.encode(btc.Script.decode(vault.leaves.normal.script)[0]), hex.encode(vault.palmKey), 'the palm key leads the normal script');
});

test('a vault that could not be what it says is refused', () => {
  const palm = publicKeyOf(createKey());
  const [a, b] = [createKey(), createKey()].map(publicKeyOf);
  assert.throws(() => palmVaultOf({ palmKey: palm, signerKeys: [], required: 1 }), /at least one signer/);
  assert.throws(() => palmVaultOf({ palmKey: palm, signerKeys: [a, a], required: 1 }), /appears twice/);
  assert.throws(() => palmVaultOf({ palmKey: palm, signerKeys: [a, palm], required: 1 }), /palm key cannot also be a signer/);
  assert.throws(() => palmVaultOf({ palmKey: palm, signerKeys: [a, b], required: 3 }), /between one and 2/);
  assert.throws(() => palmVaultOf({ palmKey: palm, signerKeys: [a, b], required: 2, delay: 0 }), /between 1 and 65535/);
  assert.throws(() => palmVaultOf({ palmKey: palm, signerKeys: [a, b], required: 2, delay: 65536 }), /between 1 and 65535/);
  assert.throws(() => palmVaultOf({ palmKey: 'nope', signerKeys: [a], required: 1 }), /not a public key/);
});

test('without the palm signature the spend cannot be finished, and the witness is laid out slot by slot', () => {
  const { spend, signer, vaultId, policy, veyns, vault, now } = world();
  const { psbt, action } = spend();
  assert.throws(() => finalizePalmPsbt(vault, psbt), /palm key has not signed/);

  const decisions = [veyns.decision('sub-alex', action, now()), veyns.decision('sub-bea', action, now())];
  const signed = signer.sign({ vaultId, policy, psbt, action, decisions });
  const tx = btc.Transaction.fromRaw(hex.decode(finalizePalmPsbt(vault, signed.psbt).hex), { allowUnknownInputs: true });
  const witness = tx.getInput(0).finalScriptWitness;
  assert.equal(witness.length, 3 + 1 + 2, 'a slot per signer, the palm signature, the script, the control block');
  assert.deepEqual(witness.slice(0, 4).map(item => item.length).filter(n => n === 0).length, 1, 'the signer who did not sign leaves an empty slot');
  assert.equal(witness[3].length, 64, 'the palm signature sits on top of the stack, read first');
  assert.equal(hex.encode(witness[4]), hex.encode(vault.leaves.normal.script));
});

test('the recovery path needs no palm, but carries the delay as its sequence so Bitcoin enforces it', () => {
  const { vault, people } = world();
  const plan = planPalmSpend({ vault, utxos: [{ txid: 'cd'.repeat(32), vout: 1, value: 50_000 }], toAddress: DEST, amountSats: 'max', feeRate: 1, path: 'recovery' });
  let psbt = palmVaultPsbt(vault, plan, { path: 'recovery' });
  assert.equal(palmPathOf(vault, psbt), 'recovery');
  psbt = signPalmPsbt(psbt, people.bea);
  psbt = signPalmPsbt(psbt, people.cara);
  const tx = btc.Transaction.fromRaw(hex.decode(finalizePalmPsbt(vault, psbt).hex), { allowUnknownInputs: true });
  assert.equal(tx.version, 2, 'version 2, so the relative timelock applies');
  assert.equal(tx.getInput(0).sequence, DEFAULT_RECOVERY_DELAY);
  assert.equal(tx.getInput(0).finalScriptWitness.length, 3 + 2, 'no palm slot on the recovery path');
});

test('a signature is made over the leaf this vault names, so the leaf hashes agree with the library', () => {
  const { spend, vault } = world();
  const { psbt } = spend();
  const input = btc.Transaction.fromPSBT(base64.decode(psbt), { allowUnknownInputs: true }).getInput(0);
  for (const [meta] of input.tapScriptSig) assert.equal(hex.encode(meta.leafHash), hex.encode(vault.leaves.normal.leafHash));
});

test('the plan is exact: change returns to the vault, a sweep pays the fee from the amount, too little is refused', () => {
  const { vault } = world();
  const utxos = [{ txid: 'ef'.repeat(32), vout: 0, value: 80_000 }];
  const part = planPalmSpend({ vault, utxos, toAddress: DEST, amountSats: 30_000, feeRate: 3 });
  assert.equal(part.outputs.at(-1).address, vault.address);
  assert.equal(part.sentSats + part.changeSats + part.feeSats, 80_000);
  const all = planPalmSpend({ vault, utxos, toAddress: DEST, amountSats: 'max', feeRate: 3 });
  assert.equal(all.outputs.length, 1);
  assert.equal(all.sentSats + all.feeSats, 80_000);
  assert.throws(() => planPalmSpend({ vault, utxos, toAddress: DEST, amountSats: 200_000, feeRate: 3 }), /Not enough coins/);
  assert.throws(() => planPalmSpend({ vault, utxos, toAddress: DEST, amountSats: 100, feeRate: 3 }), /at least 330/);
});

/* ------------------------------------------------------------- the palm signer */

test('each vault has its own palm key, and only the signer can make it', () => {
  const { signer } = world();
  assert.equal(signer.publicKeyFor('vault-1'), signer.publicKeyFor('vault-1'));
  assert.notEqual(signer.publicKeyFor('vault-1'), signer.publicKeyFor('vault-2'));
  assert.match(signer.publicKeyFor('vault-1'), /^[0-9a-f]{64}$/);
});

test('with palms from enough different signers, bound to this transaction, the palm key signs', () => {
  const { spend, signer, vaultId, policy, veyns, vault, now } = world();
  const { psbt, action } = spend();
  const decisions = [veyns.decision('sub-bea', action, now()), veyns.decision('sub-alex', action, now())];
  const result = signer.sign({ vaultId, policy, psbt, action, decisions });
  assert.deepEqual(result.approvedBy, ['sub-alex', 'sub-bea']);
  assert.equal(result.palmKey, hex.encode(vault.palmKey));
  assert.ok(finalizePalmPsbt(vault, result.psbt).txid);
});

test('too few palms, or the same person twice, or a stranger, gets no signature', () => {
  const { spend, signer, vaultId, policy, veyns, now } = world();
  const { psbt, action } = spend();
  const sign = decisions => () => signer.sign({ vaultId, policy, psbt, action, decisions });
  assert.throws(sign([]), refusedWith(/needs 2 palm approvals from different signers and has 0/));
  assert.throws(sign([veyns.decision('sub-alex', action, now())]), refusedWith(/has 1/));
  assert.throws(sign([veyns.decision('sub-alex', action, now()), veyns.decision('sub-alex', action, now())]), refusedWith(/has 1/));
  assert.throws(sign([veyns.decision('sub-alex', action, now()), veyns.decision('sub-mallory', action, now())]),
    refusedWith(/does not sign for this vault/));
});

test('a decision that is not a live palm approval of this exact action does not count', () => {
  const { spend, signer, vaultId, policy, veyns, now } = world();
  const { psbt, action } = spend();
  const other = spend(DEST, 41_000).action;
  const good = veyns.decision('sub-alex', action, now());
  const cases = [
    [veyns.decision('sub-bea', other, now()), /approves a different action/],
    [veyns.decision('sub-bea', action, now(), { amr: ['veyns:browser'] }), /not made with a palm/],
    [veyns.decision('sub-bea', action, now(), { veyns_presence: false }), /person present/],
    [veyns.decision('sub-bea', action, now(), { veyns_intent: 'login' }), /not an action approval/],
    [veyns.decision('sub-bea', action, now(), { aud: 'someone-else' }), /different application/],
    [veyns.decision('sub-bea', action, now(), { iss: 'https://evil.test' }), /different issuer/],
    [veyns.decision('sub-bea', action, now(), { auth_time: now() - 7201 }), /too old/],
    [veyns.decision('sub-bea', action, now(), { request_nonce: undefined }), /no request nonce/],
  ];
  for (const [bad, pattern] of cases) {
    assert.throws(() => signer.sign({ vaultId, policy, psbt, action, decisions: [good, bad] }), refusedWith(pattern), String(pattern));
  }
});

test('a decision signed by a key the signer does not pin, or tampered with, does not count', () => {
  const { spend, signer, vaultId, policy, veyns, now } = world();
  const { psbt, action } = spend();
  const good = veyns.decision('sub-alex', action, now());
  const stranger = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey;
  const forged = veyns.decision('sub-bea', action, now()).split('.');
  const unpinned = veyns.token(JSON.parse(Buffer.from(forged[1], 'base64url')), { key: stranger, kid: 'k2' });
  const tampered = `${forged[0]}.${Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(forged[1], 'base64url')), sub: 'sub-cara' })).toString('base64url')}.${forged[2]}`;
  assert.throws(() => signer.sign({ vaultId, policy, psbt, action, decisions: [good, unpinned] }), refusedWith(/does not trust/));
  assert.throws(() => signer.sign({ vaultId, policy, psbt, action, decisions: [good, tampered] }), refusedWith(/does not verify/));
});

test('a server that lies about the transaction gets a refusal, not a signature', () => {
  const { spend, signer, vaultId, policy, veyns, people, vault, now } = world();
  const approved = spend();
  const decisions = [veyns.decision('sub-alex', approved.action, now()), veyns.decision('sub-bea', approved.action, now())];

  // The palms approved one payment; the transaction put in front of the signer pays someone else.
  const swapped = spend('tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7', 40_000);
  assert.throws(() => signer.sign({ vaultId, policy, psbt: swapped.psbt, action: approved.action, decisions }),
    refusedWith(/names a different transaction/));

  // Asking for the recovery path, or a signature that would not cover the outputs.
  const recovery = palmVaultPsbt(vault, approved.plan, { path: 'recovery' });
  assert.throws(() => signer.sign({ vaultId, policy, psbt: recovery, action: approved.action, decisions }), refusedWith(/normal spending path/));
  const loose = btc.Transaction.fromPSBT(base64.decode(approved.psbt), { allowUnknownInputs: true });
  loose.updateInput(0, { sighashType: btc.SigHash.NONE }, true);
  assert.throws(() => signer.sign({ vaultId, policy, psbt: base64.encode(loose.toPSBT()), action: approved.action, decisions }),
    refusedWith(/would not cover every output/));

  // A different vault's coins: the signer rebuilds the vault from the policy and its own key.
  const elsewhere = palmVaultOf({ palmKey: signer.publicKeyFor('vault-2'), ...policy });
  const theirs = signPalmPsbt(palmVaultPsbt(elsewhere, approved.plan), people.alex);
  assert.throws(() => signer.sign({ vaultId, policy, psbt: theirs, action: approved.action, decisions }), refusedWith(/normal spending path|not this vault/));
});

test('a palm decision counts towards one transaction only', () => {
  const { spend, signer, vaultId, policy, veyns, now } = world();
  const first = spend(DEST, 40_000);
  const a = veyns.decision('sub-alex', first.action, now());
  const b = veyns.decision('sub-bea', first.action, now());
  signer.sign({ vaultId, policy, psbt: first.psbt, action: first.action, decisions: [a, b] });

  // A second payment arrives carrying a decision whose request was already spent on the first.
  const second = spend(DEST, 42_000);
  const reused = veyns.decision('sub-alex', second.action, now(), { request_id: JSON.parse(Buffer.from(a.split('.')[1], 'base64url')).request_id });
  const fresh = veyns.decision('sub-bea', second.action, now());
  assert.throws(() => signer.sign({ vaultId, policy, psbt: second.psbt, action: second.action, decisions: [reused, fresh] }),
    refusedWith(/already been counted towards a different transaction/));
});
