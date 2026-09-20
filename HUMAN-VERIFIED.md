# Human verified transactions — what QuVault does, and what it does not

QuVault V1 binds a person's palm approval to one exact Bitcoin transaction, signs a record of
that authorisation with an ML-DSA-65 key **held by the owner's vault**, and refuses to
broadcast anything that record does not cover. This file states the mechanism and its limits
precisely enough to argue with.

## Two keys, both the owner's

```text
                    the recovery phrase, in the browser
                                 │
                 ┌───────────────┴───────────────┐
                 ▼                               ▼
         wallet signing key              attestation key
         secp256k1 / BIP84               ML-DSA-65, per epoch
                 │                               │
                 ▼                               ▼
         signs the Bitcoin               signs the authorisation
           transaction                          record
                 └───────────────┬───────────────┘
                                 ▼
                              server
                         verifies, never signs
```

The server stores the **public** half of the attestation key and the lineage it came from.
There is no function anywhere in `src/` that derives an attestation signing key: the only one
lives in `client/wallet.js` and takes the recovery phrase. A QuVault deployment therefore
cannot manufacture an authorisation record.

## Which key is authoritative

Not whichever key a column happens to hold. A vault's key is decided by a **chain of signed
registrations**:

```text
epoch 1        signs its own registration          root
   │
   │ epoch 1's key signs epoch 2's registration
   ▼
epoch 2        names epoch 1 by key id
   │
   ▼
epoch 3 …
```

Each link names the vault, the public key, the epoch and the key before it, and is signed
under the context `QUVAULT-ATTESTATION-KEY-REGISTRATION-V1`. The server walks the chain on
every use: a gap, a repeat, a wrong vault, or a link signed by anything other than its
predecessor ends the walk and no key is authoritative at all.

A chain is self-rooted, so walking it is not enough on its own — someone able to rewrite the
row could store a chain rooted at their own key. The root is therefore **sealed with
`WALLET_SEED`**, an HMAC over the vault id and the root key id, kept in a column but only
producible from the environment. A database operator can rewrite the chain; they cannot
produce a seal for the root they invented, so the vault's key becomes *no key* rather than
*their key*, and nothing verifies. This is what closes the substitution gap, and it is the
one place `WALLET_SEED` still matters to authorisation — it authenticates storage, it does
not sign anything.

On top of that, the owner's browser pins the **root key id** of its own vault when the vault
is created, and checks the server's answer against it on every load. A lineage that does not
match what the device started is shown as a warning and sending is disabled.

The attestation key is derived from the same phrase as the wallet key rather than stored as a
second independent secret. That is deliberate: the same twelve words restore both, the same
palm-gated unlock releases both, and there is no new secret to lose. The trade-off is a shared
root — someone holding the phrase can both spend and attest — which costs nothing, because
holding the phrase already means holding the money.

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
unlock                  the server hands the device the plan and what the record must name
      ↓
sign + attest           the browser signs the transaction, and signs the record
      ↓
verify                  the server checks the record against the registered public key
      ↓
broadcast               only if plan, hash, record and bytes all agree
```

## What is bound to what

| Step | Bound by | Refusal if broken |
|---|---|---|
| The sentence a person reads | `actionDigest(statement, details)`, computed by **both** QuVault and Veyns | The palm decision does not verify |
| The transaction | `transaction_hash` = SHA-256 of the canonical transaction, **inside** `details` | The palm decision covers a different sentence |
| The stored plan | re-hashed at unlock, before signing, and before broadcast | `409 The stored transaction no longer matches the one that was approved` |
| The device's signature | the browser re-hashes the plan it is handed | `This is not the transaction that was approved. Nothing has been signed.` |
| The authorisation | ML-DSA-65 under context `QUVAULT-HUMAN-AUTHORIZATION-V1`, checked against the vault's registered key, the transaction hash, the statement digest, the approvers, the palm decision ids, the key epoch and the time window | `409 No valid human authorisation for this transaction: <reason>` |
| The raw bytes | `verifyAgainstPlan` — same coins, same outputs, same fee, fully signed | `400` with the specific mismatch |

## What a valid receipt proves

> A key held by this vault — and by no one else, including the operator of this server —
> signed a record saying that a palm approval covering this exact transaction was verified,
> naming the palm decisions that settled it, before the transaction was broadcast.

## What it does not prove

- **Not legal identity.** A Veyns subject is a pairwise identifier. Nothing here establishes
  who that person is in law.
- **Not liveness.** The provider asserts presence and that the method was a palm. It does not
  tell us a live hand was present, and QuVault does not claim it.
- **Not device integrity.** No attestation binds an approval to a particular phone, secure
  element or browser, and none is claimed. Biometric success is not device trustworthiness.
- **Not hardware-backed.** Keys live in IndexedDB, encrypted with AES-256-GCM under a key
  derived from a palm-released unlock secret and a device salt. That is software protection in
  a browser. Where a platform offers hardware-backed storage this does not use it yet.
- **Not proof against local malware.** Code running inside the browser session can wait for an
  unlock and then use both keys. Nothing in a web page prevents that.
- **Not quantum-proof.** ML-DSA-65 and ML-KEM-768 are lattice schemes believed to resist
  quantum attack; they run on ordinary hardware. Bitcoin itself still signs with secp256k1,
  which a quantum computer would break on-chain regardless of anything here.

## Threats, and where they land

| Threat | What stops it today | What remains |
|---|---|---|
| Destination, amount, fee or coin changed after approval | The hash is inside the approved sentence; four independent checks re-derive it | — |
| An old authorisation replayed on a new transaction | The record names the transaction hash, statement, approvers and decisions | — |
| A transaction signed with no palm | No record can be produced; broadcast refuses | — |
| **The server forging a receipt** | It holds only a public key | — (it can still refuse service, or lie about what it never signed) |
| **A database operator substituting the key** | The registration chain must walk, and its root must carry a seal only `WALLET_SEED` can produce. A rewritten row leaves the vault with no valid key, not with the attacker's | Someone who has **both** the database and the environment can register a lineage of their own. The owner's device still refuses it, because the root is not the one it pinned — and they still cannot spend, because the wallet key is not there either |
| A forged rotation | Each epoch is signed by the key it replaces; the epoch steps by exactly one | — |
| Replaying a retired key | Records carry their epoch, and the current epoch is the end of the chain | — |
| A compromised page showing A and sending B | The browser re-hashes the plan; the server re-checks before broadcast | A page that holds the keys can sign what it never displayed |
| A compromised server swapping the plan | Digest checks at unlock, sign and broadcast | Denial of service |
| Biometric spoofing | Whatever the provider's sensor does | Outside our code. We verify a decision, not a hand |
| Losing the device | The phrase restores both keys, including the attestation key | If the phrase is lost too, the vault is lost. There is no recovery network, and this is not solved |

## Replacing the key

Settings → *Replace the authorisation key*. It takes a palm approval like any other change to
the vault, derives the next epoch from the same phrase, and registers it in a link **signed by
the key it replaces** — which is why the server can accept the change without being able to
make it. The old key stops being accepted immediately: records signed under a retired epoch
are refused.
Receipts already issued still verify against the key that signed them, but the vault will not
accept new ones from it.

**Security implications, stated plainly.** Rotation helps if you believe the old key's records
are being misused; it does not help if the phrase itself is compromised, because the phrase
derives every epoch. If the phrase is compromised, move the coins.

## Recovery

If the device and the local key material are lost, the twelve words restore both keys on a new
device, after the two-palm recovery ceremony (or by typing them in). **If the phrase is also
lost, the funds are not recoverable.** There is no social recovery, no distributed recovery and
no escrow in V1. That problem is not solved, and nothing here should be read as solving it.

## How anyone checks a receipt

`GET /api/operations/:id/receipt` returns the record, its ML-DSA-65 signature, the vault's
registered public key and its fingerprint. The page verifies it in the browser with the same
module that signed it (`src/authorization.js`, imported into the client bundle), under the
context `QUVAULT-HUMAN-AUTHORIZATION-V1`. A receipt that fails that check is shown as
unverified rather than as proof of anything.
