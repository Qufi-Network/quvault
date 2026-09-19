/* The browser wallet module, exercised in Node: entropy, addresses, signing and storage crypto. */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import * as btc from '@scure/btc-signer';
import { hex } from '@scure/base';
import { validateMnemonic, mnemonicToSeedSync } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { HDKey } from '@scure/bip32';
import {
  accountFrom, decryptMnemonic, encryptMnemonic, jitterFrom, makeMnemonic, signPlan, toBase64,
} from '../client/wallet.js';
import { planSpend, isValidAddress } from '../src/bitcoin.js';

const DEST = 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx';
const serverRandom = () => new Uint8Array(crypto.randomBytes(32));

test('a new phrase is 12 valid words and mixes every entropy source', () => {
  const jitter = jitterFrom(['pointer', 12, 'click']);
  const mnemonic = makeMnemonic({ serverRandom: serverRandom(), jitter });
  assert.equal(mnemonic.split(' ').length, 12);
  assert.ok(validateMnemonic(mnemonic, wordlist));

  // Same server randomness and jitter, different browser randomness: a different phrase.
  const fixedServer = serverRandom();
  const again = new Set();
  for (let i = 0; i < 20; i++) again.add(makeMnemonic({ serverRandom: fixedServer, jitter }));
  assert.equal(again.size, 20, 'the browser generator still contributes');

  // And changing only the server's bytes changes the phrase too.
  const browserFixed = makeMnemonic({ serverRandom: fixedServer, jitter });
  assert.notEqual(browserFixed, makeMnemonic({ serverRandom: serverRandom(), jitter }));
});

test('the phrase gives a standard testnet address that other wallets can restore', () => {
  const mnemonic = makeMnemonic({ serverRandom: serverRandom(), jitter: jitterFrom(['x']) });
  const account = accountFrom(mnemonic);
  assert.ok(isValidAddress(account.address));
  assert.match(account.address, /^tb1q/);
  assert.equal(account.path, "m/84'/1'/0'/0/0");

  // Deriving the same path by hand gives the same address: nothing bespoke in the derivation.
  const node = HDKey.fromMasterSeed(mnemonicToSeedSync(mnemonic)).derive("m/84'/1'/0'/0/0");
  assert.equal(btc.p2wpkh(node.publicKey, btc.TEST_NETWORK).address, account.address);
  assert.throws(() => accountFrom('not a real phrase at all'), /not a valid/);
});

test('the browser signs exactly the plan the server made', () => {
  const mnemonic = makeMnemonic({ serverRandom: serverRandom(), jitter: jitterFrom(['x']) });
  const account = accountFrom(mnemonic);
  const utxos = [{ txid: 'a'.repeat(64), vout: 0, value: 250_000 }];
  const plan = planSpend({ publicKey: Buffer.from(account.publicKey), utxos, toAddress: DEST, amountSats: 90_000, feeRate: 2 });

  const signed = signPlan(mnemonic, plan, account.address);
  const tx = btc.Transaction.fromRaw(hex.decode(signed.hex));
  assert.equal(tx.id, signed.txid);
  assert.equal(Number(tx.getOutput(0).amount), 90_000);
  assert.equal(btc.Address(btc.TEST_NETWORK).encode(btc.OutScript.decode(tx.getOutput(0).script)), DEST);
  assert.equal(btc.Address(btc.TEST_NETWORK).encode(btc.OutScript.decode(tx.getOutput(1).script)), account.address);

  // A plan whose numbers were altered will not sign.
  assert.throws(() => signPlan(mnemonic, { ...plan, feeSats: plan.feeSats + 1000 }, account.address), /does not match the approved plan/);
  // Another phrase is refused before anything is signed.
  const other = makeMnemonic({ serverRandom: serverRandom(), jitter: jitterFrom(['y']) });
  assert.throws(() => signPlan(other, plan, account.address), /different wallet/);
});

test('the stored blob needs both the unlock secret and this device\'s salt', async () => {
  const mnemonic = makeMnemonic({ serverRandom: serverRandom(), jitter: jitterFrom(['x']) });
  const unlock = toBase64(new Uint8Array(crypto.randomBytes(32)));
  const salt = toBase64(new Uint8Array(crypto.randomBytes(16)));
  const blob = await encryptMnemonic(mnemonic, unlock, salt);

  assert.ok(!blob.includes(mnemonic.split(' ')[0]), 'the phrase is not sitting in the blob');
  assert.equal(await decryptMnemonic(blob, unlock, salt), mnemonic);

  const otherUnlock = toBase64(new Uint8Array(crypto.randomBytes(32)));
  await assert.rejects(decryptMnemonic(blob, otherUnlock, salt), 'a different unlock secret cannot open it');
  const otherSalt = toBase64(new Uint8Array(crypto.randomBytes(16)));
  await assert.rejects(decryptMnemonic(blob, unlock, otherSalt), 'a different device salt cannot open it');

  const tampered = Buffer.from(blob, 'base64');
  tampered[tampered.length - 3] ^= 1;
  await assert.rejects(decryptMnemonic(tampered.toString('base64'), unlock, salt), 'tampering is caught');
});
