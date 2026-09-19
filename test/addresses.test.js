/*
 * The addresses every account is derived from, checked against other implementations.
 * A wrong address here would send funds nowhere, so each network is pinned twice:
 * once to the phrase used across the ecosystem, once to a library that is not ours.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { base58, base58check, base32 } from '@scure/base';
import { sha256 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { mnemonicToSeedSync } from '@scure/bip39';
import { HDKey } from '@scure/bip32';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { StrKey } from '@stellar/stellar-base';
import { accountsFrom, NETWORKS } from '../client/wallet.js';
import { NETWORKS as SERVER_NETWORKS } from '../src/networks.js';

// The phrase every wallet uses in its own test suite, so these addresses can be compared anywhere.
const PHRASE = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const accounts = accountsFrom(PHRASE);
const bytes = hex => Uint8Array.from(Buffer.from(hex, 'hex'));

test('every network derives on its own standard path', () => {
  assert.deepEqual(
    Object.fromEntries(Object.entries(accounts).map(([id, account]) => [id, account.path])),
    {
      bitcoin: "m/84'/1'/0'/0/0",
      ethereum: "m/44'/60'/0'/0/0",
      tron: "m/44'/195'/0'/0/0",
      solana: "m/44'/501'/0'/0'", // what Phantom and Solflare use for the first account
      stellar: "m/44'/148'/0'",
    },
  );
  assert.deepEqual(Object.keys(accounts).sort(), Object.keys(SERVER_NETWORKS).sort());
});

test('the server recognises every address its own page derives', () => {
  for (const [id, account] of Object.entries(accounts)) {
    assert.ok(SERVER_NETWORKS[id].valid(account.address), `${id}: ${account.address}`);
    // And does not mistake it for another network.
    for (const [other, network] of Object.entries(SERVER_NETWORKS)) {
      if (other === id) continue;
      assert.ok(!network.valid(account.address), `${other} accepted a ${id} address`);
    }
  }
});

test('Ethereum matches the address every wallet gives for this phrase', () => {
  // The canonical BIP44 result for m/44'/60'/0'/0/0, in EIP-55 casing.
  assert.equal(accounts.ethereum.address, '0x9858EfFD232B4033E47d90003D41EC34EcaEda94');
});

test('Tron is the same key as Ethereum would make, on the Tron path and prefix', () => {
  const node = HDKey.fromMasterSeed(mnemonicToSeedSync(PHRASE)).derive(NETWORKS.tron.path);
  const hash20 = keccak_256(secp256k1.getPublicKey(node.privateKey, false).subarray(1)).subarray(-20);
  const decoded = base58check(sha256).decode(accounts.tron.address); // also checks the checksum
  assert.equal(decoded[0], 0x41, 'the mainnet Tron prefix');
  assert.deepEqual(decoded.subarray(1), hash20);
  assert.equal(accounts.tron.address[0], 'T');
});

test('Solana is the ed25519 key in base58, by another encoder', () => {
  assert.equal(accounts.solana.address, base58.encode(bytes(accounts.solana.publicKey)));
  assert.equal(base58.decode(accounts.solana.address).length, 32);
});

test('Stellar matches the encoding the Stellar SDK produces', () => {
  const fromSdk = StrKey.encodeEd25519PublicKey(Buffer.from(accounts.stellar.publicKey, 'hex'));
  assert.equal(accounts.stellar.address, fromSdk);
  assert.ok(StrKey.isValidEd25519PublicKey(accounts.stellar.address));
  // 35 bytes is a whole number of base32 characters, so a strkey carries no padding.
  assert.deepEqual(base32.decode(accounts.stellar.address).subarray(1, 33), bytes(accounts.stellar.publicKey));
});

test('an address with a broken checksum or the wrong key length is refused', () => {
  const tron = accounts.tron.address;
  const swapped = `${tron.slice(0, -2)}${tron.slice(-1)}${tron.at(-2)}`;
  assert.ok(!SERVER_NETWORKS.tron.valid(swapped), 'two characters swapped breaks the checksum');
  assert.ok(!SERVER_NETWORKS.solana.valid(base58.encode(new Uint8Array(31))), '31 bytes is not a Solana key');
  assert.ok(!SERVER_NETWORKS.stellar.valid(`G${'A'.repeat(55)}`), 'a strkey needs its own checksum too');
});

test('a different phrase moves every address', () => {
  const other = accountsFrom('legal winner thank year wave sausage worth useful legal winner thank yellow');
  for (const id of Object.keys(accounts)) assert.notEqual(other[id].address, accounts[id].address);
});
