# Portable palm-vein wallet — Phase 0 audit

Read-only. No code was changed to produce this. Every statement below was checked against the
files as they stand at `ffe197a`; where something is absent, that is written down as absent
rather than assumed.

---

## 1. Current architecture

One Node 24 application, ES modules, no framework. `src/app.js` builds a router over
`node:http`; `server.js` runs it locally and `api/handler.js` runs the same `createApp()` on
Vercel, where `public/` is served by the CDN and everything under `/api/*` reaches the handler.

| Module | Lines | What it owns |
|---|---|---|
| `src/app.js` | 2,234 | 27 routes, the palm gate, every policy decision |
| `src/bitcoin.js` | 321 | P2WSH `p2ms`, BIP67 ordering, PSBT collect/combine/finalize |
| `src/db.js` | 313 | schema, nine tables, idempotent versioned migrations |
| `client/wallet.js` | 368 | **the only module that ever holds key material** |
| `src/authorization.js` | 219 | ML-DSA-65 records and the registration chain |
| `src/networks.js` | 132 | chain table; only testnet4 has `canSend: true` |
| `src/veyns.js` | 119 | OIDC client — authorization code + PKCE, ES256 |
| `src/chain.js` | 117 | Esplora reads |
| `src/vault.js` | 97 | ML-KEM-768 + X25519 → AES-256-GCM envelope |
| `src/policy.js` | 67 | approval ladder |
| `src/canonical.js` | 45 | canonical JSON, shared by server and browser |

Tables: `users`, `wallets`, `members`, `accounts`, `operations`, `approvals`, `invites`,
`sessions`, `login_nonces`. Migrations run under `pg_advisory_xact_lock(4970)`. Neon Postgres
hosted; PGlite locally and in tests, so the 122 tests across 18 files need no database.

Two custody modes exist on the `wallets` table:

- `custody = 'client'` — the browser holds the phrase; the server holds `unlock_sealed` only.
- `custody = 'server'` — **legacy**; the server holds `sealed_key`, the whole private key.

---

## 2. Current key lifecycle

```
  CEREMONY (browser, client/wallet.js)
    crypto.getRandomValues(32)  ──┐
    GET /api/random (server)    ──┼─► HKDF-SHA256 'quvault wallet seed v1' ─► 16 bytes
    pointer/timing jitter       ──┘                                             │
                                                                                ▼
                                                    BIP39 12 words / 128 bits of entropy
                                                                                │
        ┌───────────────────────────────────────────────────────────────────────┤
        ▼                                                                       ▼
  BIP84 m/84'/1'/0'/0/0  ─► secp256k1 spend key              HKDF 'quvault attestation'
        │                                                     epoch N ─► ML-DSA-65 keypair
        ▼                                                                       │
     address                                                                    ▼
                                                              registration chain, epoch 1
                                                              self-signed, later epochs
                                                              signed by the epoch before

  AT REST (browser only)
    IndexedDB  quvault / wallet / current
      { blob, salt, address, publicKey, createdAt }          ← never the phrase itself
      blob = AES-256-GCM( mnemonic,
                          HKDF(unlockSecret, salt, 'quvault device key v1', 32) )

  THE UNLOCK SECRET (32 random bytes, made once at vault creation)
    server stores   wallets.unlock_sealed = seal(unlockSecret, serverKeys(WALLET_SEED))
                    ML-KEM-768 ct ‖ X25519 pub ‖ nonce ‖ AES-256-GCM ct+tag
    server releases it only through unlockFor(), and only when:
        the operation has enough completed palm approvals
        op.txid is null                       (never used to send before)
        now <= op.expires_at + UNLOCK_SECONDS
        now <= op.unlocked_at + UNLOCK_SECONDS   (if already unlocked once)
      then markUnlocked(op.id, now)           ← single use, time-boxed
```

**Recovery** is the same phrase typed back in, after the two-scan ceremony
(`device.restore()`); the address is re-derived and must match before anything is written.

**Legacy path.** For `custody = 'server'` wallets the phrase does not exist at all. The server
opens the sealed private key directly at `src/app.js:604`, `:1474`, `:1755`, signs, and calls
`privateKey.fill(0)` in a `finally`. `moveWalletToBrowser` migrates such a wallet by setting
`sealed_key = NULL` — but only forward, and only on request.

---

## 3. Current signing lifecycle

Bitcoin spend, `custody = 'client'`:

1. Browser asks the server to plan the spend. The server selects UTXOs and returns inputs,
   outputs and `feeSats`.
2. The browser computes the digest with `planDigest()` — canonical JSON → SHA-256 → base64url,
   from `src/canonical.js`, the same file the server uses.
3. The operation is opened; each approver scans a palm at Veyns; each decision is recorded.
4. When the ladder in `src/policy.js` is satisfied, `unlockFor()` releases the unlock secret
   once.
5. `signPlan(mnemonic, plan, expectedAddress, approved)` in `client/wallet.js` re-derives the
   account and refuses on three separate grounds:
   - the phrase does not belong to `expectedAddress`;
   - `planDigest({network, from: address, plan}) !== approved.transactionHash` — *"This is not
     the transaction that was approved. Nothing has been signed."*;
   - after signing, `inputs − outputs !== plan.feeSats`.
6. `attest()` produces the ML-DSA-65 authorization record over the same digest.
7. The server verifies the record with `verifyAuthorization(...)`, passing `expected` values
   for `transactionHash`, `vaultId`, `statementDigest`, `keyEpoch`, `approvedBy`,
   `decisionIds`, `notBefore`, `notAfter`, and broadcasts.

Quorum spends use `signQuorum()`, which returns a **PSBT** — never a key — and co-signers
derive at `m/48'/1'/0'/2'/0/{index}`.

**This is already transaction-bound.** The palm approval names a digest; the signer refuses
anything that is not that digest. The brief's requirement that "every signing operation must
be bound to the exact transaction being authorized" is met today for `custody = 'client'`.

---

## 4. Current authentication lifecycle

Veyns OIDC, authorization code + PKCE (S256), ES256 ID tokens, pairwise subjects,
`amr: veyns:palm`, 30-second clock leeway. PKCE state and verifier live in `sessionStorage`
and nowhere else. **The Veyns SDK was deliberately removed** — nothing of theirs executes on
this origin. Sessions are server rows; a wallet is bound to `bound_sub` and `bound_decision`
at creation, so a different palm identity cannot later claim it.

`isFresh(authTime, notBefore, now)` is what stops a stale login standing in for a fresh scan.

---

## 5. Current vault lifecycle

`src/vault.js`, 97 lines. `serverKeys()` derives an ML-KEM-768 and an X25519 keypair from a
64-byte `WALLET_SEED`. `seal()`/`open()` write and read
`version ‖ ML-KEM ct ‖ X25519 pub ‖ nonce ‖ ct+tag`, the two shared secrets concatenated
through HKDF-SHA256 into one AES-256-GCM key. `sealRoot()`/`rootSealMatches()` HMAC the
attestation root key id so the first epoch cannot be swapped after the fact.

What the vault protects today: **unlock secrets** (all client wallets) and **private keys**
(legacy server wallets only).

---

## 6. Existing scanner integration

**None.** There is no scanner code in this repository. The single occurrence of the word is a
user-facing error string at `src/app.js:445` telling someone their Veyns account has no palm
scanner connected. There is:

- no device driver, no USB/serial/WebHID/WebUSB path, no vendor SDK;
- no PAD (presentation-attack detection) signal anywhere in the data model;
- no scanner attestation, no device certificate, no firmware version, no sensor id;
- no biometric template, image, score or threshold — by design, and stated as such in the
  header comment of `src/authorization.js`.

What exists instead is a **decision reference**: Veyns performs the scan on their side and
returns a decision id, which the authorization record names. The V1 record's entire statement
about the palm is the literal `biometricVerified: true`, written unconditionally by
`signAuthorization()`. There is no field in which a PAD result or a scanner identity *could*
be recorded.

This is the largest gap between the repository and the brief.

---

## 7. Exact private-key exposure points

Classified per the brief's Phase 14 scheme.

| # | Location | Material | Class |
|---|---|---|---|
| 1 | `client/wallet.js` `makeMnemonic()` | 12 words, in a local | **REQUIRED** — it has to exist to be created |
| 2 | `client/wallet.js` `accountFrom()` | secp256k1 private key | **REQUIRED** — momentary, inside sign |
| 3 | `client/wallet.js` `signPlan()` / `signQuorum()` | private key during signing | **REQUIRED** |
| 4 | `client/wallet.js` IndexedDB blob | ciphertext only | **SAFE** |
| 5 | `client/wallet.js` — 5 × `fill(0)` | zeroing of typed arrays | **SAFE** |
| 6 | `public/app.js:438–615` — `makeKey`, `send`, `cosign`, `quorum`, `rotate`, `network`, `restore` | **plaintext mnemonic as a JS string, 8 sites, zero `fill(0)` calls** | **DANGEROUS** |
| 7 | `public/app.js:1574` `phrase-words` | the 12 words painted into the DOM | **DANGEROUS** (cleared on close at `:1579`, but present meanwhile) |
| 8 | `src/app.js:604, 1474, 1755` `openSealed(wallet.sealed_key, vault())` | full private key **on the server** | **LEGACY** — `fill(0)` in `finally`, but the server sees the key |
| 9 | `src/app.js:868, 875, 879, 926` `openSealed(unlock_sealed)` | unlock secret, base64 to the browser | **REQUIRED** — this is the palm gate's output |
| 10 | `wallet-seed.txt` in the repo root | the server's `WALLET_SEED` | **TEST ONLY** — must never be the production value |
| 11 | `scripts/ids.js`, `test/` fixtures | throwaway phrases | **TEST ONLY** |

Two findings worth stating plainly:

- **#6 is the real one.** `client/wallet.js` is careful — it zeroes five times. `public/app.js`
  is not: it has **zero** `fill(0)` calls, and a JavaScript string cannot be zeroed anyway.
  Eight code paths hold the plaintext phrase as a string and hand it to GC. This is the
  "browser casually holding the spending key" the brief forbids.
- **#8 means a QuVault operator can spend a legacy wallet's money without any palm at all.**
  The code path exists, is reachable, and is gated only by the same session checks. It should
  become unreachable, not merely deprecated.

`localStorage`: **zero uses**. `sessionStorage`: PKCE only. No secret reaches a log line.

---

## 8. Proposed target architecture

```
  PHRASE  ─────────────────────────────────────────────────────────────────────
     no longer the sole root. It becomes one factor of a two-factor key.

  WALLET KEY = KDF( phrase-derived secret , palm-derived secret , domain )
                        │                        │
                        │                        └─ from a scanner attestation,
                        │                           not from a template, and not
                        │                           reversible to biometric data
                        └─ IndexedDB blob as today

  SCANNER  ────────────────────────────────────────────────────────────────────
     attests: device identity, firmware, PAD verdict, match verdict, a nonce
     supplied by *this transaction*. Signs that attestation with a device key.
     The scanner never holds, derives or sees the wallet key. Any compatible
     scanner can produce a valid attestation — the wallet is portable.

  AUTHORIZATION RECORD V2  ────────────────────────────────────────────────────
     v: 2
     ...every V1 field...
   + padVerdict        { result, method, scannerClass }
   + biometricVerdict  { result, matcherVersion }
   + scannerAttestation{ deviceId, firmware, signature, nonce }
   + bindingNonce      ← equals the transaction digest, so an attestation
                         cannot be replayed onto a different transaction

  SIGNING  ────────────────────────────────────────────────────────────────────
     unchanged in shape: digest → approve → unlock → sign → verify.
     What changes is that the unlock now needs a *fresh scanner attestation
     naming this digest*, and the record carries what the scanner actually said
     rather than the constant `biometricVerified: true`.

  SERVER  ─────────────────────────────────────────────────────────────────────
     loses `sealed_key` entirely. Zero private keys. Verify-only.
```

The three properties the brief asks for, mapped to mechanisms:

- *biometric match alone must not authorize* → the match verdict is one input to a KDF that
  also needs the phrase-derived secret.
- *PAD success alone must not authorize* → PAD is a field in a record that is only valid when
  `bindingNonce === transactionHash`.
- *authentication must not authorize unlimited future transactions* → already true via
  `markUnlocked` single-use; V2 makes it true of the scanner attestation too.

---

## 9. Files that must change

| File | Why |
|---|---|
| `src/authorization.js` | V2 record, PAD/verdict/attestation fields, `verifyAuthorization` expectations for them, V1 accepted read-only |
| `client/wallet.js` | two-factor key derivation; a scanner interface it calls but does not implement |
| `public/app.js` | the eight plaintext-phrase paths — narrow them, and stop returning the phrase to callers |
| `src/app.js` | require a fresh attestation in `unlockFor()`; **remove** the three `openSealed(sealed_key)` sites |
| `src/db.js` | columns for scanner/PAD provenance; drop `sealed_key` once no rows use it |
| `src/vault.js` | unchanged in mechanism, but its only remaining job becomes unlock secrets |
| new: a scanner-abstraction module | so no vendor API is assumed anywhere else |
| `test/` | V2 coverage, plus a test asserting the server-custody path is gone |

## 10. Files that must NOT change

`src/canonical.js` — server and browser must keep computing the identical digest; a change
here silently invalidates every existing receipt. `src/bitcoin.js`, `src/policy.js`,
`src/networks.js` (no network gains `canSend`), `src/chain.js`, `src/veyns.js`. All marketing
code — `public/veyns.js`, `public/*.css`, `public/index.html`'s marketing views — stays
outside the security boundary and must not acquire a role inside it. No existing test is to be
deleted.

## 11. Migration phases

1. **V2 record, dormant.** Add the fields and verification; nothing writes V2 yet.
2. **Scanner abstraction.** Define the interface. Ship a `null` provider that declares no PAD
   and no attestation, so behaviour is identical to today and nothing is invented.
3. **Legacy custody removal.** Force-migrate or refuse `custody = 'server'`; delete the three
   `openSealed(sealed_key)` sites; drop the column.
4. **Phrase-handling hardening.** Confine the plaintext phrase to `client/wallet.js`; the
   application layer receives handles, not words.
5. **Two-factor derivation.** Only once a real scanner can produce a real attestation.
6. **V2 becomes required.** After every live vault has rotated.

Phases 1–4 can be done now and are worth doing regardless of hardware. **Phase 5 cannot be
written honestly until a scanner exists to test against.**

## 12. Security risks introduced by the proposed changes

1. **Two-factor derivation can brick a wallet.** If the palm-derived factor is not perfectly
   reproducible across scanners — different firmware, different sensor, a re-enrollment — the
   money is gone. Biometrics are fuzzy; key derivation is not. This needs a fuzzy extractor
   with published parameters and a recovery path that does not depend on the scanner, or it
   must not ship.
2. **Portability and binding pull against each other.** "Any compatible scanner works" and
   "this exact device attested" are opposite requirements. The trust anchor has to be a
   *class* of device, which means a compromised device in that class is a compromised class.
3. **The attestation is a new forgeable object.** A scanner signing key that can be extracted
   turns PAD and match verdicts into attacker-chosen values. The record must stay worthless
   without the phrase factor — which is the argument for two-factor, not against it.
4. **Removing legacy custody is irreversible for anyone who has not migrated.** Needs an
   inventory of live `custody = 'server'` rows first, and a migration they can actually
   complete.
5. **V1/V2 coexistence is a downgrade surface.** If V1 stays acceptable for spending, an
   attacker who can strip fields gets the old guarantees. V1 should verify for *reading old
   receipts* and never for *authorizing a new spend*.
6. **Claim inflation.** With PAD fields in the record it becomes easy to write "hardware
   secure" on the website. Nothing here is certified, no hardware exists, and no entropy
   estimate has been measured. Phase 23's separation — IMPLEMENTED / EXPERIMENTALLY VALIDATED
   / CRYPTOGRAPHICALLY REVIEWED / FORMALLY CERTIFIED — has to be enforced in the copy at the
   same time as the code lands, not after.

---

*Audit only. No implementation has begun.*
