/*
 * Prints a new server seed for the wallet vault.
 *
 *   npm run keygen
 *
 * The seed derives the ML-KEM-768 and X25519 key pairs that seal every wallet key.
 * Keep it secret, and keep a copy: without it, no sealed wallet key can ever be opened.
 */
import crypto from 'node:crypto';
import { serverKeys } from '../src/vault.js';

const seed = crypto.randomBytes(64).toString('base64');
const keys = serverKeys(seed);

console.log('\nWALLET_SEED (64 random bytes, base64) — put this in .env locally, and in the hosting environment as a secret:\n');
console.log(seed);
console.log(`\nIt derives an ML-KEM-768 public key of ${keys.kemPublicKey.length} bytes and an X25519 public key of ${keys.x25519Public.length} bytes.`);
console.log('Losing it means losing every wallet sealed with it. Changing it has the same effect.\n');
