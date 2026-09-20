/*
 * A quorum the chain keeps rather than a rule this server remembers.
 *
 * These tests work at the level of the coins: what address a set of keys locks them to, what
 * it costs to spend, and what happens when somebody signs who should not, or signs something
 * other than what was approved.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { hex } from '@scure/base';
import {
  createKey, publicKeyOf, addressOf, multisigOf, multisigAddressOf, lockOf, planSpend,
  psbtForPlan, signPsbt, signatureCount, combinePsbts, finalizePsbt, verifyAgainstPlan,
  WalletError, MAX_KEYS,
} from '../src/bitcoin.js';

const DEST = 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx';
const holder = () => {
  const privateKey = createKey();
  return { privateKey, publicKey: publicKeyOf(privateKey) };
};
const coins = (...values) => values.map((value, i) => ({ txid: String(i + 1).repeat(64), vout: 0, value }));

/** Three people and a 2-of-3 vault, which is the shape everything below is about. */
function vault(required = 2, count = 3) {
  const people = Array.from({ length: count }, holder);
  const publicKeys = people.map(p => p.publicKey);
  return { people, publicKeys, required, address: multisigAddressOf(publicKeys, required) };
}

test('the same keys always give the same address, in whatever order they arrive', t => {
  const { publicKeys, address } = vault();
  const shuffled = [publicKeys[2], publicKeys[0], publicKeys[1]];
  assert.equal(multisigAddressOf(shuffled, 2), address, 'key order must not change the vault');
  assert.equal(multisigAddressOf(publicKeys.map(k => k.toString('hex')), 2), address, 'hex and bytes agree');
  assert.match(address, /^tb1q[02-9ac-hj-np-z]{58}$/, 'a native segwit script address');

  // The threshold is part of the address, which is the whole point of putting it on the chain.
  assert.notEqual(multisigAddressOf(publicKeys, 3), address);
  assert.notEqual(multisigAddressOf(publicKeys.slice(0, 2), 2), address);
});

test('a quorum that could not hold money is refused before it is made', t => {
  const keys = Array.from({ length: 3 }, () => holder().publicKey);
  const fails = (fn, what) => assert.throws(fn, error => error instanceof WalletError && new RegExp(what, 'i').test(error.message));

  fails(() => multisigOf([keys[0]], 1), 'at least two keys');
  fails(() => multisigOf(keys, 4), 'between one and 3');
  fails(() => multisigOf(keys, 0), 'between one and 3');
  fails(() => multisigOf(keys, 1.5), 'between one and 3');
  fails(() => multisigOf([keys[0], keys[0], keys[1]], 2), 'appears twice');
  fails(() => multisigOf([keys[0], Buffer.alloc(33)], 2), 'compressed public key');
  fails(() => multisigOf([keys[0], 'not a key'], 2), 'compressed public key');
  fails(() => multisigOf(Array.from({ length: MAX_KEYS + 1 }, () => holder().publicKey), 2), `at most ${MAX_KEYS}`);
});

test('a spend from a quorum is planned against the quorum, not one of its keys', t => {
  const { publicKeys, required, address } = vault();
  const plan = planSpend({ publicKeys, required, utxos: coins(400_000), toAddress: DEST, amountSats: 150_000, feeRate: 3 });

  assert.equal(plan.sentSats, 150_000);
  assert.ok(plan.changeSats > 0, 'the change comes back to the vault');
  assert.equal(plan.outputs.find(o => o.sats === plan.changeSats).address, address, 'and to the quorum, not to a key');
  assert.ok(plan.feeSats > 0);

  // One key from the set is a different vault and must not be able to plan for this one.
  const single = planSpend({ publicKey: publicKeys[0], utxos: coins(400_000), toAddress: DEST, amountSats: 150_000, feeRate: 3 });
  assert.notEqual(single.outputs.find(o => o.address !== DEST)?.address, address);
});

test('the fee a sweep sets aside matches what the signed transaction really costs', async t => {
  // A sweep has no change to absorb a bad estimate, so this is the one that has to be right.
  for (const required of [1, 2, 3]) {
    const { people, publicKeys, address } = vault(required);
    const plan = planSpend({ publicKeys, required, utxos: coins(500_000), toAddress: DEST, amountSats: 'max', feeRate: 1 });
    assert.equal(plan.changeSats, 0);
    assert.equal(plan.outputs.length, 1);

    const signed = finalizePsbt(combinePsbts(
      people.slice(0, required).map(person => signPsbt(psbtForPlan({ publicKeys, required }, plan), person.privateKey)),
    ));
    const slack = plan.feeSats - signed.vsize * plan.feeRate;
    assert.ok(slack >= 0, `${required}-of-3: the estimate must never come out under the real cost (short by ${-slack})`);
    assert.ok(slack <= 8, `${required}-of-3: the estimate is ${slack} vbytes over, which is too generous`);
    assert.equal(verifyAgainstPlan(signed.hex, plan).txid, signed.txid, 'and it is the transaction that was planned');
    assert.notEqual(address, undefined);
  }
});

test('two of three send the money, and one of three cannot', async t => {
  const { people, publicKeys, required } = vault();
  const plan = planSpend({ publicKeys, required, utxos: coins(600_000), toAddress: DEST, amountSats: 200_000, feeRate: 2 });
  const unsigned = psbtForPlan({ publicKeys, required }, plan);
  assert.equal(signatureCount(unsigned), 0);

  const alone = signPsbt(unsigned, people[0].privateKey);
  assert.equal(signatureCount(alone), 1);
  assert.throws(() => finalizePsbt(alone), error => /not ready to send/.test(error.message));

  const together = combinePsbts([alone, signPsbt(unsigned, people[1].privateKey)]);
  assert.equal(signatureCount(together), 2);
  const sent = finalizePsbt(together);
  assert.equal(verifyAgainstPlan(sent.hex, plan).txid, sent.txid);
});

test('the same signer twice is still one signature', async t => {
  const { people, publicKeys, required } = vault();
  const plan = planSpend({ publicKeys, required, utxos: coins(600_000), toAddress: DEST, amountSats: 200_000, feeRate: 2 });
  const unsigned = psbtForPlan({ publicKeys, required }, plan);

  const once = signPsbt(unsigned, people[0].privateKey);
  const twice = combinePsbts([once, signPsbt(unsigned, people[0].privateKey)]);
  assert.equal(signatureCount(twice), 1, 'signing again adds nothing');
  assert.throws(() => finalizePsbt(twice), error => /not ready to send/.test(error.message));
});

test('somebody outside the quorum cannot sign for it', async t => {
  const { publicKeys, required } = vault();
  const plan = planSpend({ publicKeys, required, utxos: coins(600_000), toAddress: DEST, amountSats: 200_000, feeRate: 2 });
  const unsigned = psbtForPlan({ publicKeys, required }, plan);

  assert.throws(() => signPsbt(unsigned, holder().privateKey),
    error => error instanceof WalletError && /does not sign for this vault/.test(error.message));
  assert.equal(signatureCount(unsigned), 0, 'and nothing was added while trying');
});

test('a signature collected for one spend cannot be carried to another', async t => {
  const { people, publicKeys, required } = vault();
  const approved = planSpend({ publicKeys, required, utxos: coins(600_000), toAddress: DEST, amountSats: 200_000, feeRate: 2 });
  const elsewhere = planSpend({ publicKeys, required, utxos: coins(600_000), toAddress: DEST, amountSats: 550_000, feeRate: 2 });

  const forApproved = signPsbt(psbtForPlan({ publicKeys, required }, approved), people[0].privateKey);
  const forElsewhere = signPsbt(psbtForPlan({ publicKeys, required }, elsewhere), people[1].privateKey);

  assert.throws(() => combinePsbts([forApproved, forElsewhere]),
    error => error instanceof WalletError && /not for this transaction/.test(error.message));

  // Nor can a finished transaction for one plan pass as the other.
  const sent = finalizePsbt(combinePsbts(
    people.slice(0, 2).map(p => signPsbt(psbtForPlan({ publicKeys, required }, elsewhere), p.privateKey)),
  ));
  assert.throws(() => verifyAgainstPlan(sent.hex, approved),
    error => error instanceof WalletError && /different/.test(error.message));
});

test('a quorum of one is still the chain enforcing it, and is not the same as a lone key', t => {
  const person = holder();
  const other = holder();
  const lock = lockOf({ publicKeys: [person.publicKey, other.publicKey], required: 1 });
  assert.equal(lock.required, 1);
  assert.ok(lock.witnessScript, 'a script, not a bare key');
  assert.notEqual(lock.address, addressOf(person.publicKey));

  const single = lockOf({ publicKey: person.publicKey });
  assert.equal(single.required, null);
  assert.equal(single.witnessScript, undefined);
  assert.equal(single.address, addressOf(person.publicKey));
});

test('rubbish handed to the collecting endpoints is refused, not swallowed', t => {
  const bad = ['', 'not base64 at all!!', Buffer.from('hello').toString('base64')];
  for (const value of bad) {
    assert.throws(() => signatureCount(value), error => error instanceof WalletError, `signatureCount(${value})`);
    assert.throws(() => combinePsbts([value]), error => error instanceof WalletError, `combinePsbts(${value})`);
    assert.throws(() => finalizePsbt(value), error => error instanceof WalletError, `finalizePsbt(${value})`);
  }
  assert.throws(() => combinePsbts([]), error => /nothing to put together/.test(error.message));
});

test('the script is the ordinary one, so any wallet can spend these coins without us', t => {
  // If QuVault disappears, the people holding the keys still need to be able to rebuild this.
  const { publicKeys, required } = vault();
  const wsh = multisigOf(publicKeys, required);
  const script = hex.encode(wsh.witnessScript);
  const sorted = publicKeys.map(k => k.toString('hex')).sort();

  assert.match(script, /^52/, 'OP_2, the threshold, in plain sight');
  assert.match(script, /53ae$/, 'OP_3 OP_CHECKMULTISIG');
  assert.equal(script, `52${sorted.map(k => `21${k}`).join('')}53ae`, 'and nothing else in it');
});
