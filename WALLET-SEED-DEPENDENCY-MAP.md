# WALLET_SEED dependency map

Every production use of `WALLET_SEED`, what it protects, and whether the final architecture
needs it or has merely inherited it.

**Nothing is removed in Phase 1.6.**

---

## The distinction that matters most

> **`WALLET_SEED` protects an unlock secret and anchors an attestation root. It is not, and
> has never been, the wallet's spending key.**

This is not a technicality. The two would have completely different consequences if the seed
leaked:

| If `WALLET_SEED` leaked | Consequence |
|---|---|
| …and the attacker has the database | They can open any `unlock_sealed` value and obtain unlock secrets. **An unlock secret opens nothing on its own** — it is one of two inputs to `HKDF(unlockSecret, salt, 'quvault device key v1')`, and the other is the AES-GCM blob that exists only in the owner's browser's IndexedDB. |
| …and the attacker has the database **and** a victim's browser storage | They can decrypt that victim's mnemonic. This is the real risk, and it requires compromising the browser as well. |
| …and the attacker wants to forge an authorisation | They cannot. The attestation key is ML-DSA-65, derived from the owner's phrase, and the server has only the public half. `sealRoot` is an HMAC that pins *which* public key is authoritative; it cannot produce a signature. |
| …for a **legacy** wallet | Irrelevant — legacy keys are sealed under `QUVAULT_LEGACY_SEED`, a separate secret, absent from an ordinary deployment. |

So `WALLET_SEED` is a **wrapping root for one of two factors**, plus an integrity anchor. It is
one layer removed from spending authority in every direction.

---

## The chain, drawn out

```
  WALLET_SEED  (64 bytes, env)
        │
        ├─ serverKeys()  ──► ML-KEM-768 + X25519 keypair ──► vault()
        │                                                      │
        │                          seal / open the UNLOCK SECRET (32 random bytes)
        │                                                      │
        │                                                      ▼
        │                        browser: HKDF(unlockSecret, salt, 'quvault device key v1')
        │                                                      │
        │                                          AES-256-GCM key for the blob
        │                                                      │
        │                          ┌───────────────────────────┴──────────────────┐
        │                          │  the blob is in IndexedDB, in the browser,   │
        │                          │  and the server has never seen it            │
        │                          └──────────────────────────────────────────────┘
        │                                                      │
        │                                                      ▼
        │                                              MNEMONIC ──► BIP84 ──► SPENDING KEY
        │                                                              (never touches WALLET_SEED)
        │
        └─ sealRoot() / rootSealMatches()  ──► HMAC over { vaultId, rootKeyId }
                                                  pins which ML-DSA public key is the root
                                                  of a vault's attestation lineage.
                                                  Cannot sign. Cannot be turned into a key.

  QUVAULT_LEGACY_SEED  (separate, absent by default)
        │
        └─ serverKeys() ──► legacyVault() ──► open( wallets.sealed_key ) ──► A FULL PRIVATE KEY
                                                    MIGRATION ONLY — src/app.js:809
```

---

## Every production use

### Root derivation

| Module | Function | Line | Purpose | Secret protected | Login? | Signing? | Migration? | Replaceable root? | Removing breaks wallets? |
|---|---|---|---|---|---|---|---|---|---|
| `src/app.js` | `vault()` | 268 | derive the sealing keypair | — (derives the key that protects unlock secrets) | no | **yes, indirectly** | yes | **yes, with re-wrapping** | **yes** |

`serverKeys(walletSeed)` is memoised per process. Replacing this root means re-wrapping every
`unlock_sealed` value — a data migration, not a code change.

### Unlock-secret protection — `vault()` consumers

| Module | Function | Line | Purpose | Secret protected | Login? | Signing? | Migration? | Replaceable? | Removing breaks wallets? |
|---|---|---|---|---|---|---|---|---|---|
| `src/app.js` | `createWallet` | 635 | `seal(unlock, vault())` at vault creation | unlock secret | no | no | no | yes, by re-wrapping | **yes** — new wallets could not be created |
| `src/app.js` | `prepareUpgrade` | 652 | `seal(unlock, vault())` for the browser key a migration is about to make | unlock secret | no | no | **yes** | yes | yes |
| `src/app.js` | `unlockFor` | 1095 | open the unlock secret for a `create` operation | unlock secret | no | no | no | yes | **yes** |
| `src/app.js` | `unlockFor` | 1102 | open it for an `upgrade` operation | unlock secret | no | no | **yes** | yes | yes |
| `src/app.js` | `unlockFor` | 1106 | open the wallet's own `unlock_sealed` | unlock secret | no | **YES — every spend** | no | yes | **yes** |
| `src/app.js` | `quorumUnlock` | 1156 | open the co-signer's own `unlock_sealed` | unlock secret | no | **YES — every quorum share** | no | yes | **yes** |

**Line 1106 is the one that makes `WALLET_SEED` unavoidable today.** Every browser-custody
spend calls `unlockFor`, which opens `wallet.unlock_sealed` with `vault()`. There is no
signing without it.

### Attestation roots

| Module | Function | Line | Purpose | Secret protected | Login? | Signing? | Migration? | Replaceable? | Removing breaks wallets? |
|---|---|---|---|---|---|---|---|---|---|
| `src/app.js` | `attestationOf` | 431 | `rootSealMatches(...)` — check the anchor when reading a lineage | none — integrity only | no | **yes, on every broadcast** | no | **yes** | no — receipts would stop verifying, coins unaffected |
| `src/app.js` | `registerWallet` | 1203 | `sealRoot(...)` — write the anchor | none — integrity only | no | no | no | yes | no |
| `src/app.js` | `registerAttestationKey` | 1832 | `sealRoot(...)` on rotation | none — integrity only | no | no | no | yes | no |
| `src/app.js` | `completeUpgrade` | 2018 | `sealRoot(...)` for the migrated lineage | none — integrity only | no | no | **yes** | yes | no |

These use `WALLET_SEED` as an **HMAC key, not an encryption key**. They protect no secret;
they stop a rewritten database from promoting an attestation key that no previous key ever
signed for. Losing this capability costs receipt verification, not money — which is a strictly
weaker requirement than the unlock path and could be served by a different, lower-privilege
key.

### Configuration

| Module | Function | Line | Purpose | Secret protected | Reveals anything? |
|---|---|---|---|---|---|
| `src/app.js` | `getConfig` | 929 | `vaultReady: Boolean(walletSeed)` | none | **no** — a boolean |
| `server.js` | module scope | 25 | `walletSeed: env.WALLET_SEED \|\| ''` | none | no |
| `api/handler.js` | module scope | 36 | same | none | no |

### Legacy custody — a different secret

| Module | Function | Line | Purpose | Secret protected | Login? | Signing? | Migration? |
|---|---|---|---|---|---|---|---|
| `src/app.js` | `legacyVault()` | 300 | `serverKeys(legacySeed)` | the legacy sealing keypair | no | **no** | **yes, only** |
| `src/app.js` | `sweepLegacyVault` | 809 | `openSealed(wallet.sealed_key, legacyVault())` | **a full private key** | no | **no** | **yes, only** |
| `server.js` | module scope | 28 | `legacySeed: env.QUVAULT_LEGACY_SEED \|\| ''` | — | — | — | — |
| `api/handler.js` | module scope | 38 | same | — | — | — | — |

`QUVAULT_LEGACY_SEED` is absent by default. Where it is absent no request can open a legacy
key at all. See `LEGACY-CUSTODY-DELETION-GATE.md`.

### Tests

| Module | Line | Purpose | Classification |
|---|---|---|---|
| `test/harness.js` | 23 | `SEED = crypto.randomBytes(64).toString('base64')` — a fresh throwaway per run | TEST |
| `test/harness.js` | 121 | passes `walletSeed: SEED` into `createApp` | TEST |
| `test/harness.js` | 307 | `startWithMigration` passes `legacySeed: SEED` | TEST |
| `test/harness.js` | 264 | seals a fake legacy key for `legacyWallet()` | TEST |
| `test/legacy-closure.test.js` | 334, 343 | asserts no seed reaches a response | TEST |

No test seed is ever a production value, and none is written to disk.

### Not a repository file

`wallet-seed.txt` is in `.gitignore`, is untracked, and `git log --all -- wallet-seed.txt` is
empty — **it has never been committed.** It is a local development artefact on one machine.
*(This corrects the Phase 1 report, which listed it as a repository vulnerability.)*

---

## Classification summary

| Class | Sites | Required in the final architecture? |
|---|---|---|
| **SIGNING** (indirect) | `unlockFor:1106`, `quorumUnlock:1156` | **Yes, as the architecture stands.** Every spend opens an unlock secret. |
| **AUTHORIZATION** | none | `WALLET_SEED` plays no part in authorising anything. Palm decisions come from Veyns; the ML-DSA record is signed by a key the server does not have. |
| **ATTESTATION** | `attestationOf:431`, `registerWallet:1203`, `registerAttestationKey:1832`, `completeUpgrade:2018` | Yes, but **as an HMAC key, not an encryption key**, and separable. |
| **MIGRATION** | `prepareUpgrade:652`, `unlockFor:1102`, `completeUpgrade:2018`; and `legacyVault:300`, `sweepLegacyVault:809` under the *separate* legacy seed | Only until the legacy population is zero. |
| **TEST** | 5 sites in `test/` | n/a |
| **OTHER / CONFIGURATION** | `getConfig:929`, two entry points | Reveals nothing. |

---

## Is it fundamental, or inherited?

**Both, in different places.**

**Inherited, and separable:**

- The **attestation anchor** does not need the same root as the unlock path. It is an HMAC key
  whose compromise costs receipt verification rather than money, and it could live under a
  distinct, lower-privilege secret. Keeping them on one root is convenience, not necessity.
- The **legacy capability** has already been separated, in Phase 1.5, and proves the pattern
  works.

**Fundamental to the *current* design, and not to the *target* design:**

- The unlock secret exists because the server needs a way to gate access to a browser-held key
  behind a palm approval. Something must wrap that secret, and today that is `WALLET_SEED`.
- **In the target architecture it is displaced rather than removed.** Per
  `PORTABLE-WALLET-INVARIANT.md`, a palm-derived key-encryption capability reconstructed on the
  device takes over the job of unwrapping the wallet key. At that point the server-held unlock
  secret is no longer the only gate, and `WALLET_SEED`'s role shrinks to the attestation anchor
  — which, as above, does not need to be this key.

So the honest answer: **`WALLET_SEED` is required today and is not required by the final
architecture, but removing it is a data migration (re-wrapping every `unlock_sealed`) plus a
biometric capability that does not exist yet.** It is not a code change and must not be
attempted as one.

---

## What is true today, without qualification

- **No seed reaches the browser.** Tested: the unlock response carries none.
- **No configuration endpoint reports one.** Tested for `/api/config` and `/api/scanner`.
- **No seed is written to a log.** The security-event allowlist has no seed field, and
  phrase-shaped and key-shaped values are scrubbed even on allowed fields.
- **`WALLET_SEED` is never used during login.** Verified: no `vault()`, `sealRoot` or
  `rootSealMatches` call appears in `loginStart`, `loginFinish`, `logout` or `requireUser`.
- **`WALLET_SEED` never touches the wallet's spending key.** The mnemonic is generated in the
  browser from a CSPRNG and never leaves it.
- It lives for the process lifetime as a JavaScript string and **cannot be erased**.
