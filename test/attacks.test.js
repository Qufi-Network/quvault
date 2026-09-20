/*
 * The attack suite. Every test here is an attempt to move money the owner did not authorise,
 * and every one must end with no broadcast.
 *
 * The attacker is assumed to have **write access to the database** and to be able to shape any
 * HTTP request. What they do not have is the owner's recovery phrase, and therefore neither
 * the wallet key nor the attestation key.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { deriveAttestationKeys, verifyAuthorization, verifyChain } from '../src/authorization.js';
import { signPlan } from '../src/bitcoin.js';
import { accountFrom, makeMnemonic, jitterFrom } from '../client/wallet.js';
import { DEST, start, ok, signedIn, palmApprove, walletFor, signAndSend, attestFor, registrationFor } from './harness.js';

const coins = [{ txid: 'a'.repeat(64), vout: 0, value: 500_000 }];
const attackerKeys = () => deriveAttestationKeys(new Uint8Array(crypto.randomBytes(64)), 1);
const elsewhere = () => accountFrom(makeMnemonic({ serverRandom: new Uint8Array(crypto.randomBytes(32)), jitter: jitterFrom(['x']) })).address;

/** A vault with coins, approved and waiting for its owner's device to sign. */
async function approved(env, owner, amount = 120_000) {
  env.world.chain.utxos = coins;
  const { operation } = ok(await owner.post('/api/withdrawals', { to: DEST, amount }));
  await palmApprove(env, owner, operation.id);
  const unlocked = ok(await owner.post(`/api/operations/${operation.id}/unlock`, {}));
  const signed = signPlan({ privateKey: owner.key, publicKey: owner.publicKey, plan: unlocked.plan });
  return { operation, unlocked, hex: signed.hex };
}

const refused = (response, what) => {
  assert.ok(response.status >= 400, `${what} was not refused (status ${response.status})`);
  return response;
};

/* ============================ attacks on the key ============================ */

test('ATTACK 1 — the database operator replaces the attestation key', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const { operation, unlocked, hex } = await approved(env, alex);

  // Straight into the table: a chain rooted at the attacker's own key, perfectly self-signed.
  const attacker = attackerKeys();
  const db = await env.app.db();
  await db.query('UPDATE wallets SET attestation_chain = $1 WHERE user_id = $2', [
    JSON.stringify([registrationFor({ vaultId: alex.address, keys: attacker })]), alex.id,
  ]);

  const forged = attestFor(env, alex, unlocked, { keys: attacker });
  refused(await alex.post(`/api/operations/${operation.id}/broadcast`, { hex, authorization: forged }), 'a substituted key');
  assert.equal(env.world.log.broadcast.length, 0);

  // The substitution is visible: the vault's lineage no longer starts where the owner's does.
  const view = ok(await alex.get('/api/wallet'));
  assert.notEqual(view.wallet.attestation.rootKeyId, alex.attestation.keyId, 'the root changed, and a device would see it');
});

test('ATTACK 2 — the database operator moves the epoch forward', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const { operation, unlocked, hex } = await approved(env, alex);
  const db = await env.app.db();

  // Claiming epoch 3 without the links that lead to it.
  const attacker = attackerKeys();
  const skipped = registrationFor({ vaultId: alex.address, keys: attacker, epoch: 3, previousKeys: attacker });
  await db.query('UPDATE wallets SET attestation_chain = $1 WHERE user_id = $2', [
    JSON.stringify([JSON.parse(await currentLink(db, alex.id)), skipped]), alex.id,
  ]);
  refused(await alex.post(`/api/operations/${operation.id}/broadcast`, { hex, authorization: attestFor(env, alex, unlocked, { keys: attacker }) }), 'an invented epoch');

  // Or simply renumbering the genuine link.
  const genuine = JSON.parse(await currentLink(db, alex.id));
  genuine.record.epoch = 5;
  await db.query('UPDATE wallets SET attestation_chain = $1 WHERE user_id = $2', [JSON.stringify([genuine]), alex.id]);
  refused(await alex.post(`/api/operations/${operation.id}/broadcast`, { hex, authorization: attestFor(env, alex, unlocked) }), 'a renumbered link');
  assert.equal(env.world.log.broadcast.length, 0);
});

test('ATTACK 3 — a rotation the current key never signed', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const attacker = attackerKeys();

  const { operation } = ok(await alex.post('/api/attestation/approval', {}));
  await palmApprove(env, alex, operation.id);

  // Signed by the attacker's own key, which cannot vouch for epoch 2 of this vault.
  refused(await alex.post('/api/attestation/register', {
    operationId: operation.id,
    attestationRegistration: registrationFor({ vaultId: alex.address, keys: attacker, epoch: 2, previousKeys: attacker }),
  }), 'a self-signed epoch 2');

  // Even naming the right previous key does not help without its signature.
  const lying = registrationFor({ vaultId: alex.address, keys: attacker, epoch: 2, previousKeys: attacker });
  lying.record.previousKeyId = alex.attestation.keyId;
  refused(await alex.post('/api/attestation/register', { operationId: operation.id, attestationRegistration: lying }), 'a forged lineage claim');

  assert.equal(ok(await alex.get('/api/wallet')).wallet.attestation.keyId, alex.attestation.keyId, 'the key did not move');
});

test('ATTACK 4 — the retired key tries to authorise after a rotation', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const old = alex.attestation;
  const next = deriveAttestationKeys(new Uint8Array(crypto.randomBytes(64)), 2);

  const { operation } = ok(await alex.post('/api/attestation/approval', {}));
  await palmApprove(env, alex, operation.id);
  ok(await alex.post('/api/attestation/register', {
    operationId: operation.id,
    attestationRegistration: registrationFor({ vaultId: alex.address, keys: next, epoch: 2, previousKeys: old }),
  }));

  const { operation: spend, unlocked, hex } = await approved(env, alex);
  refused(await alex.post(`/api/operations/${spend.id}/broadcast`, { hex, authorization: attestFor(env, alex, unlocked, { keys: old }) }), 'the retired key');
  assert.equal(env.world.log.broadcast.length, 0);
  assert.ok(ok(await alex.post(`/api/operations/${spend.id}/broadcast`, { hex, authorization: attestFor(env, alex, unlocked, { keys: next }) })).txid);
});

/* ======================= attacks on the transaction ========================= */

test('ATTACKS 5 to 8 — destination, amount, fee and coins moved after the palm', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const { operation, unlocked } = await approved(env, alex);
  const db = await env.app.db();
  const plan = unlocked.plan;

  const change = plan.outputs.find(output => output.address !== DEST);
  const swaps = {
    'ATTACK 5 destination': { ...plan, outputs: plan.outputs.map(o => (o.address === DEST ? { ...o, address: elsewhere() } : o)) },
    // Everything the coins hold, minus the fee: larger than approved, and still spendable.
    'ATTACK 6 amount': { ...plan, outputs: [{ address: DEST, sats: plan.outputs.reduce((sum, o) => sum + o.sats, 0) }] },
    'ATTACK 7 fee': { ...plan, outputs: [{ address: DEST, sats: plan.outputs[0].sats }, { ...change, sats: change.sats - 20_000 }] },
    'ATTACK 8 coins': { ...plan, inputs: [{ txid: 'c'.repeat(64), index: 0, value: 500_000 }] },
  };
  for (const [what, altered] of Object.entries(swaps)) {
    await db.query('UPDATE operations SET payload = $1 WHERE id = $2', [JSON.stringify(altered), operation.id]);
    // The device is not even given a plan to sign: the unlock refuses first.
    refused(await alex.post(`/api/operations/${operation.id}/unlock`, {}), `${what} at unlock`);
    // And if something signed it anyway, the server refuses the bytes.
    let hex;
    try {
      hex = signPlan({ privateKey: alex.key, publicKey: alex.publicKey, plan: altered }).hex;
    } catch {
      continue; // an unsignable transaction is already no transaction
    }
    refused(await alex.post(`/api/operations/${operation.id}/broadcast`, {
      hex, authorization: attestFor(env, alex, unlocked),
    }), `${what} at broadcast`);
  }
  assert.equal(env.world.log.broadcast.length, 0, 'nothing reached the network');
});

test('ATTACK 16 — palm first, then the transaction changes', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const { operation, unlocked } = await approved(env, alex);

  // The approval is genuine. The bytes are not the ones it covered.
  const other = { ...unlocked.plan, outputs: unlocked.plan.outputs.map(o => (o.address === DEST ? { ...o, address: elsewhere() } : o)) };
  const signed = signPlan({ privateKey: alex.key, publicKey: alex.publicKey, plan: other });
  const answer = refused(await alex.post(`/api/operations/${operation.id}/broadcast`, {
    hex: signed.hex, authorization: attestFor(env, alex, unlocked),
  }), 'a transaction changed after the palm');
  assert.match(answer.body.error, /different amounts|different coins|does not match/);
  assert.equal(env.world.log.broadcast.length, 0);
});

/* ====================== attacks on the authorisation ======================== */

test('ATTACKS 9 to 14 — statement, vault, replay, timestamps and invented approvers', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  const bob = await signedIn(env, 'sub-bob');
  await walletFor(env, alex);
  await walletFor(env, bob);
  const { operation, unlocked, hex } = await approved(env, alex);

  const tweaks = {
    'ATTACK 9 statement': { statementDigest: 'another-statement' },
    'ATTACK 10 wrong vault': { vaultId: bob.address },
    'ATTACK 12 future timestamp': { approvedAt: env.now() + 3600 },
    'ATTACK 13 expired': { approvedAt: env.now() - 7200 },
    'ATTACK 14 invented approver': { approvedBy: ['someone-who-did-not'] },
    'ATTACK 14 invented decision': { decisionIds: ['a-decision-that-never-happened'] },
  };
  for (const [what, tweak] of Object.entries(tweaks)) {
    refused(await alex.post(`/api/operations/${operation.id}/broadcast`, {
      hex, authorization: attestFor(env, alex, unlocked, tweak),
    }), what);
  }

  // ATTACK 11 — a complete, genuine authorisation, reused on a second withdrawal.
  const honest = attestFor(env, alex, unlocked);
  ok(await alex.post(`/api/operations/${operation.id}/broadcast`, { hex, authorization: honest }));
  env.world.chain.utxos = [{ txid: 'd'.repeat(64), vout: 0, value: 400_000 }];
  const second = ok(await alex.post('/api/withdrawals', { to: elsewhere(), amount: 200_000 }));
  await palmApprove(env, alex, second.operation.id);
  const unlockedSecond = ok(await alex.post(`/api/operations/${second.operation.id}/unlock`, {}));
  const signedSecond = signPlan({ privateKey: alex.key, publicKey: alex.publicKey, plan: unlockedSecond.plan });
  refused(await alex.post(`/api/operations/${second.operation.id}/broadcast`, {
    hex: signedSecond.hex, authorization: honest,
  }), 'ATTACK 11 replay');
  assert.equal(env.world.log.broadcast.length, 1, 'only the first, honest withdrawal was sent');
});

test('ATTACK 15 — an authorisation without a palm decision behind it', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  env.world.chain.utxos = coins;

  const { operation, plan } = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 120_000 }));
  // No palm at all: nothing to unlock, nothing to sign, nothing to send.
  refused(await alex.post(`/api/operations/${operation.id}/unlock`, {}), 'unlock without a palm');
  const signed = signPlan({ privateKey: alex.key, publicKey: alex.publicKey, plan });
  const made = attestFor(env, alex, {
    address: alex.address, transactionHash: 'invented', statementDigest: 'invented',
    approvals: '1 of 1', approvedBy: [alex.id], decisionIds: ['invented'],
  });
  refused(await alex.post(`/api/operations/${operation.id}/broadcast`, { hex: signed.hex, authorization: made }), 'an invented authorisation');
  assert.equal(env.world.log.broadcast.length, 0);
});

/* ====================== attacks on the record itself ======================== */

test('ATTACK 19 — every field of a receipt is covered by the signature', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const { operation, hex, unlocked } = await approved(env, alex);
  ok(await alex.post(`/api/operations/${operation.id}/broadcast`, { hex, authorization: attestFor(env, alex, unlocked) }));
  const receipt = ok(await alex.get(`/api/operations/${operation.id}/receipt`));
  assert.ok(receipt.verified.ok);

  for (const field of ['transactionHash', 'vaultId', 'statementDigest', 'approvedAt', 'keyEpoch', 'approvals', 'biometricVerified']) {
    const tampered = { ...receipt.authorization, record: { ...receipt.authorization.record, [field]: 'CHANGED' } };
    assert.equal(verifyAuthorization(tampered, receipt.publicKey).ok, false, field);
  }
  for (const list of ['approvedBy', 'decisionIds']) {
    const tampered = { ...receipt.authorization, record: { ...receipt.authorization.record, [list]: ['CHANGED'] } };
    assert.equal(verifyAuthorization(tampered, receipt.publicKey).ok, false, list);
  }
  // And the lineage it came from verifies on its own terms.
  const walked = verifyChain(receipt.attestationChain, { vaultId: alex.address });
  assert.ok(walked.ok);
  assert.equal(walked.keyId, receipt.keyId);
});

test('ATTACK 20 — the database operator cannot fabricate a receipt', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const { operation, unlocked, hex } = await approved(env, alex);
  const db = await env.app.db();

  // Full write access, and three attempts at a receipt the owner never made.
  const attacker = attackerKeys();
  const attempts = {
    'writing a record straight into the row': async () => {
      const fabricated = attestFor(env, alex, unlocked, { keys: attacker });
      await db.query('UPDATE operations SET human_authorization = $1 WHERE id = $2', [JSON.stringify(fabricated), operation.id]);
      return alex.post(`/api/operations/${operation.id}/broadcast`, { hex });
    },
    'and repointing the key at the same time': async () => {
      await db.query('UPDATE wallets SET attestation_chain = $1 WHERE user_id = $2', [
        JSON.stringify([registrationFor({ vaultId: alex.address, keys: attacker })]), alex.id,
      ]);
      return alex.post(`/api/operations/${operation.id}/broadcast`, { hex });
    },
    'and appending to the genuine lineage': async () => {
      const genuine = registrationFor({ vaultId: alex.address, keys: alex.attestation });
      await db.query('UPDATE wallets SET attestation_chain = $1 WHERE user_id = $2', [
        JSON.stringify([genuine, registrationFor({ vaultId: alex.address, keys: attacker, epoch: 2, previousKeys: attacker })]), alex.id,
      ]);
      return alex.post(`/api/operations/${operation.id}/broadcast`, { hex });
    },
  };
  for (const [what, attempt] of Object.entries(attempts)) refused(await attempt(), what);
  assert.equal(env.world.log.broadcast.length, 0, 'nothing was ever sent');

  // What the owner's device would see afterwards: a lineage that is not the one it started.
  const view = ok(await alex.get('/api/wallet'));
  assert.notEqual(view.wallet.attestation?.rootKeyId, alex.attestation.keyId);
});

/* ===================== attacks on the code and the store ==================== */

test('ATTACK 17 — no server path can sign an authorisation', () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const src = path.join(here, '..', 'src');
  const offenders = [];
  for (const name of readdirSync(src).filter(file => file.endsWith('.js'))) {
    // The module that defines signing is allowed to define it; nothing under src/ may call it.
    if (name === 'authorization.js') continue;
    const text = readFileSync(path.join(src, name), 'utf8');
    for (const forbidden of ['signAuthorization', 'signRegistration', 'deriveAttestationKeys']) {
      if (text.includes(forbidden)) offenders.push(`${name} mentions ${forbidden}`);
    }
  }
  assert.deepEqual(offenders, [], 'server code must not be able to sign');

  // And the server file imports only the verifying half.
  const app = readFileSync(path.join(src, 'app.js'), 'utf8');
  const imported = app.match(/import \{([^}]*)\} from '\.\/authorization\.js'/)[1];
  assert.deepEqual(imported.split(',').map(name => name.trim()).sort(), ['keyIdOf', 'verifyAuthorization', 'verifyChain']);
});

test('ATTACK 18 — no secret material is persisted server-side', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const { operation, unlocked, hex } = await approved(env, alex);
  ok(await alex.post(`/api/operations/${operation.id}/broadcast`, { hex, authorization: attestFor(env, alex, unlocked) }));

  const secret = Buffer.from(alex.attestation.secretKey);
  const probes = [
    secret.subarray(1000, 1060).toString('base64'),
    secret.subarray(1000, 1060).toString('hex'),
    alex.key.toString('hex'), // the wallet private key this client holds
  ];
  const db = await env.app.db();
  for (const table of ['wallets', 'operations', 'approvals', 'accounts', 'members', 'users', 'sessions']) {
    const dump = JSON.stringify((await db.query(`SELECT * FROM ${table}`)).rows);
    for (const probe of probes) assert.ok(!dump.includes(probe), `${table} holds secret material`);
  }
  // The one secret the server does hold is sealed, and is not a signing key.
  const row = (await db.query('SELECT * FROM wallets WHERE user_id = $1', [alex.id])).rows[0];
  assert.equal(row.sealed_key, null);
  assert.ok(row.unlock_sealed, 'only the sealed unlock secret, which cannot sign anything');
});

/** The vault's current registration link, as stored. */
async function currentLink(db, userId) {
  const { rows } = await db.query('SELECT attestation_chain FROM wallets WHERE user_id = $1', [userId]);
  return JSON.stringify(JSON.parse(rows[0].attestation_chain)[0]);
}

/* ================= a vault that predates key lineages ====================== */

test('a vault with no lineage can start one, and spends again afterwards', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);

  // As a vault registered before lineages existed would look: a key, and no chain.
  const db = await env.app.db();
  await db.query('UPDATE wallets SET attestation_chain = NULL, attestation_root_seal = NULL WHERE user_id = $1', [alex.id]);
  assert.equal(ok(await alex.get('/api/wallet')).wallet.attestation, null, 'the page would say: no key');

  // It cannot spend while it has no key to attest with.
  const { operation, unlocked, hex } = await approved(env, alex);
  refused(await alex.post(`/api/operations/${operation.id}/broadcast`, { hex, authorization: attestFor(env, alex, unlocked) }), 'no lineage');

  // Registering a root takes a palm, like every other change to a vault.
  const request = ok(await alex.post('/api/attestation/approval', {}));
  assert.equal(request.epoch, 1);
  assert.equal(request.starting, true);
  refused(await alex.post('/api/attestation/register', {
    operationId: request.operation.id,
    attestationRegistration: registrationFor({ vaultId: alex.address, keys: alex.attestation }),
  }), 'registering before the palm');

  await palmApprove(env, alex, request.operation.id);
  const registered = ok(await alex.post('/api/attestation/register', {
    operationId: request.operation.id,
    attestationRegistration: registrationFor({ vaultId: alex.address, keys: alex.attestation }),
  }));
  assert.equal(registered.attestation.epoch, 1);
  assert.equal(registered.attestation.keyId, alex.attestation.keyId);

  // And the repaired vault spends, while a substituted key still does not.
  const attacker = attackerKeys();
  refused(await alex.post(`/api/operations/${operation.id}/broadcast`, {
    hex, authorization: attestFor(env, alex, unlocked, { keys: attacker }),
  }), 'a substituted key after the repair');
  assert.ok(ok(await alex.post(`/api/operations/${operation.id}/broadcast`, { hex, authorization: attestFor(env, alex, unlocked) })).txid);
});
