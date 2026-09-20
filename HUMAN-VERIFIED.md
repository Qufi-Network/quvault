# Human verified transactions — what QuVault does, and what it does not

QuVault V1 binds a person's palm approval to one exact Bitcoin transaction, signs a record of
that authorisation with ML-DSA-65, and refuses to broadcast anything the record does not
cover. This file states the mechanism and its limits precisely enough to argue with.

## The ceremony

```text
plan the spend          server, from live coins
      ↓
canonicalise + hash     src/canonical.js → transaction_hash
      ↓
put the hash in the sentence the person will read
      ↓
palm approval           Veyns digests the whole sentence, including the hash
      ↓
authorisation record    src/authorization.js → ML-DSA-65 over the record
      ↓
sign                    the browser re-hashes the plan and refuses if it differs
      ↓
broadcast               only if plan, hash and record all still agree
```

## What is bound to what

| Step | Bound by | Refusal if broken |
|---|---|---|
| The sentence a person reads | `actionDigest(statement, details)`, computed by **both** QuVault and Veyns | The palm decision does not verify |
| The transaction | `transaction_hash` = SHA-256 of the canonical transaction, **inside** `details` | The palm decision covers a different sentence, so it does not verify |
| The stored plan | re-hashed before signing and before broadcast | `409 The stored transaction no longer matches the one that was approved` |
| The device's signature | browser re-hashes the plan it is given | `This is not the transaction that was approved. Nothing has been signed.` |
| The authorisation | ML-DSA-65 over the record, checked against the transaction hash and the vault | `409 No valid human authorisation for this transaction` |
| The raw bytes | `verifyAgainstPlan` — same coins, same outputs, same fee, fully signed | `400` with the specific mismatch |

The canonical transaction covers the chain, the network, the sending address, every input
(sorted), every output, and the fee. Changing any of them changes the hash, and a changed hash
invalidates the approval that was collected for the old one.

## What a valid receipt proves

> This QuVault instance verified a palm decision from the identity provider whose action
> digest covered this exact transaction, before the transaction was signed, and the
> transaction that was broadcast matches that approval.

## What it does not prove

- **Not legal identity.** A Veyns subject is a pairwise identifier. Nothing here establishes
  who that person is in law.
- **Not liveness.** The provider asserts presence (`veyns_presence`) and that the method was a
  palm (`amr: veyns:palm`). It does not tell us a live hand was present, and QuVault does not
  claim it.
- **Not device integrity.** No attestation binds an approval to a particular phone, secure
  element or browser. A compromised device is a compromised device.
- **Not independent of this server.** The ML-DSA key that signs authorisation records is
  derived from `WALLET_SEED`, which this server holds. A receipt proves what *this instance*
  verified. Someone who takes the seed can sign records that say anything.
- **Not quantum-proof.** ML-DSA-65 and ML-KEM-768 are lattice schemes believed to resist
  quantum attack; they run on ordinary hardware. Bitcoin itself still signs with secp256k1,
  which a quantum computer would break on-chain regardless of anything here.

## Threats, and where they land

| Threat | What stops it today | What remains |
|---|---|---|
| Destination, amount, fee or coin changed after approval | The hash is inside the approved sentence; three independent checks re-derive it | — |
| An old authorisation replayed on a new transaction | The record names the transaction hash and the vault | — |
| A transaction signed with no palm at all | No record exists; broadcast refuses | — |
| A compromised page showing A and sending B | The browser re-hashes the plan it is handed; the server re-checks before broadcast | A page that also holds the key could sign a transaction it never showed. Nothing in a browser prevents that |
| A compromised server swapping the plan | Digest checks at sign and broadcast; the browser refuses first | A server that holds `WALLET_SEED` can forge *records*. It still cannot spend: the key is in the browser |
| Biometric spoofing | Whatever the provider's sensor does | Outside our code. We verify a decision, not a hand |
| Key extraction from the browser | AES-256-GCM at rest, unlock secret released only after a palm approval | Malware with full control of the browser can wait for an unlock |
| Seed theft (`WALLET_SEED`) | Environment variable, never sent to clients | Forged receipts. Rotating the seed invalidates old records — there is no key history yet |

## Fail-closed list

Nothing is signed and nothing is broadcast when: the palm decision does not verify; the
statement digest differs; the transaction hash differs; the plan no longer hashes to the
approved digest; the authorisation record is missing, malformed, signed by another key, or
names another transaction or vault; the raw transaction spends other coins, pays other
outputs, or carries another fee; or the transaction is not fully signed.

## How anyone checks a receipt

The record, its ML-DSA-65 signature, and the public key are returned by
`GET /api/operations/:id/receipt`. The page verifies it in the browser with the same module
that signed it (`src/authorization.js`, imported into the client bundle), under the FIPS 204
context `QUVAULT-HUMAN-AUTHORIZATION-V1`. A receipt that fails that check is shown as
unverified rather than as proof.
