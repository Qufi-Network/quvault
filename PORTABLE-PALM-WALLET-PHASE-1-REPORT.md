# Phase 1 — security boundary hardening

No scanner hardware, no palm reconstruction, no fuzzy extraction, no biometric integration.
Phase 1 was interface and boundary work, plus the review that checks the boundary is real.

**Result: 144 tests pass, 0 fail.** The 122-test baseline is intact; 22 tests were added and
none were removed or weakened.

---

## 1. What changed

| Area | Change |
|---|---|
| Legacy custody | The general server-side spending path is gone. One narrowly-scoped function is the only code that can open a legacy key, and it can only sweep. |
| Secret confinement | A narrow operations layer in `client/wallet.js`; the page imports no phrase-taking primitive. |
| Signing boundary | A `Signer` interface (`src/signer.js`) that cannot expose a key, with a declared isolation level. The page holds a signer, not a key. |
| Authorization | Version 2 added, dormant, carrying measurements instead of assertions. Version 1 unchanged. |
| Scanner | `src/scanner.js`: an abstraction and a null provider that can never report a pass. |
| Security events | `src/events.js`: nine events with an enforced field allowlist and value scrubbing. |
| Zeroisation | `fill(0)` in `client/wallet.js` went from 5 to 18; every typed-array form of a secret is now zeroed, including on the throwing path. |
| Correctness | Two literal NUL bytes removed from `src/authorization.js` source (see §12). |

New files: `src/signer.js`, `src/scanner.js`, `src/events.js`, `test/boundary.test.js`,
`test/signing-boundary.test.js`, `SCANNER-TRUST-BOUNDARY.md`, `PORTABLE-WALLET-INVARIANT.md`.

---

## 2. Legacy custody status

**Objective: a legacy wallet may be migrated, but the server must not be able to spend.**

`broadcastPlan()` — the path that signed arbitrary withdrawals server-side for legacy wallets
— has been deleted. It had **zero test coverage**, which is worth stating plainly: the single
most dangerous function in the codebase was also the least exercised.

Every call site of `openSealed(...)` was traced. There are five, and only one touches a
private key:

| Line | What it opens | Classification |
|---|---|---|
| `src/app.js:678` | `wallet.sealed_key` — a full private key | **MIGRATION ONLY** — inside `sweepLegacyVault`, reachable only from `/api/wallet/upgrade` and `/api/wallet/reset`, both requiring a completed palm-approved operation |
| `src/app.js:964` | `payload.unlockSealed` | LEGITIMATE — the unlock secret, which is the palm gate's output |
| `src/app.js:971` | `payload.unlockSealed` | LEGITIMATE |
| `src/app.js:975` | `wallet.unlock_sealed` | LEGITIMATE |
| `src/app.js:1022` | `mine.unlock_sealed` | LEGITIMATE |

`sweepLegacyVault` is deliberately incapable of being a spending path: it takes no amount, no
output list and no externally supplied plan. It builds the plan itself from the chain's own
view of the vault immediately before signing, and can only send everything to one address.

Three independent guards now stop a legacy spend:

1. `requestWithdrawal` refuses at the door, so no palm approvals are collected for a
   transaction that was never going to be signed.
2. `runOperation` throws if anything else reaches the point of moving coins.
3. `sweepLegacyVault` refuses any wallet that is not legacy custody with a sealed key.

**An additional property found during the review:** `insertWallet` — the INSERT that creates a
server-custody row — is now unreachable. Only `insertClientWallet` is called. **No new
server-custody wallet can be created by any route.** The population of legacy wallets is
closed and can only shrink.

No legacy wallet record is deleted. Migration was tested end to end: a legacy vault upgrades,
its coins are swept to the browser-held address, `sealed_key` becomes NULL, and the vault can
then spend — which it could not a moment earlier.

---

## 3. Secret exposure, before and after

### Before

| Location | Material | Class |
|---|---|---|
| `public/app.js` — 8 paths | plaintext mnemonic as a JavaScript string | DANGEROUS |
| `public/app.js` imports | 11 phrase-taking primitives | DANGEROUS |
| `src/app.js` × 3 | full private key, server-side | LEGACY |
| `client/wallet.js` | 5 `fill(0)` calls | partial |

### After

| Location | Material | Class |
|---|---|---|
| `client/wallet.js` operations layer | mnemonic, in a local, for the length of one call | REQUIRED |
| `public/app.js:591–593` — `restore()` | the words the user typed, passed straight through | REQUIRED |
| `public/app.js:1548–1549` — reveal modal | the words, put into the DOM and cleared on close | REQUIRED |
| `src/app.js:678` | full private key, server-side | MIGRATION ONLY |
| `client/wallet.js` | 18 `fill(0)` calls | — |

**Repository-wide verification.** `public/app.js` contains **zero** occurrences of
`privateKey`, `sealed_key`, `openSealed` or `biometric`. It imports no primitive that takes a
phrase. `localStorage` is used nowhere in the repository. `sessionStorage` holds exactly one
thing: the PKCE state and verifier for the OIDC redirect — not wallet material. No secret
appears in a URL parameter, a DOM attribute, a cookie or an event payload. There is no
logging at all in `public/app.js` or `client/wallet.js`.

A test drives a real vault through create, withdraw, broadcast, receipt, unlock, scanner and
wallet routes, and asserts that the exact private key and ML-DSA secret key the test vault
holds appear in none of the response bodies. This is a material check, not a shape heuristic —
an ML-DSA-65 public key is 1952 bytes of base64 and defeats shape heuristics.

### Remaining secret lifetimes

| Secret | Created / decrypted | Owner | Reachable for | Destroyed | String? | GC-limited? |
|---|---|---|---|---|---|---|
| Mnemonic (new) | `makeMnemonic` in `createVaultKey` | `client/wallet.js` | one call | dropped at return | **yes** | **yes** |
| Mnemonic (in use) | `decryptMnemonic` inside `withPhrase` | `client/wallet.js` | one operation | dropped at return | **yes** | **yes** |
| Mnemonic (reveal) | `revealPhrase` | page, then DOM | until the dialog is closed | `replaceChildren()` clears the DOM; the string is dropped | **yes** | **yes** |
| Mnemonic (restore) | typed by the user | page → wallet module | one call | input cleared; string dropped | **yes** | **yes** |
| HKDF seed material | `makeMnemonic` | `client/wallet.js` | 3 statements | `fill(0)` in `finally` | no | no |
| BIP32 master seed | `accountFrom` / `cosignerFrom` / `accountsFrom` | `client/wallet.js` | 1 statement | `fill(0)` in `finally` | no | no |
| secp256k1 private key | `accountFrom` / `cosignerFrom` | `client/wallet.js` | one signing call | `fill(0)` in `finally`, on success and on refusal | no | no |
| ML-DSA secret key | `deriveAttestationKeys` | `src/authorization.js` | one sign | `fill(0)` in `finally` | no | no |
| Decrypted blob plaintext | `decryptMnemonic` | `client/wallet.js` | 1 statement | `fill(0)` in `finally` | no | no |
| Unlock secret (server) | `openSealed(unlock_sealed)` | `src/app.js` | one response | Node GC; base64 string | **yes** | **yes** |
| Legacy private key | `openSealed(sealed_key)` | `src/app.js` | one sweep | `fill(0)` in `finally` | no | no |
| Server `WALLET_SEED` | process env | `src/vault.js` | process lifetime | never | **yes** | **yes** |

**On zeroisation, stated plainly: JavaScript string erasure is not achievable and is not
claimed here.** `String.prototype` offers no way to overwrite the bytes; the engine may have
copied, interned or relocated them; and the garbage collector decides when the original is
released. Every secret that is a typed array is zeroed, including on the throwing path. Every
secret that is a string has had its lifetime shortened. Those are different guarantees and
this report does not conflate them.

---

## 4. Signing boundary, before and after

**Before:** `public/app.js` decrypted the mnemonic, derived the key, signed, and attested —
inline, across eight code paths.

**After:**

```
  Browser / UI            public/app.js — holds a Signer, never a key
        │
        ▼
  wallet operation        client/wallet.js — the only module that sees a phrase
        │
        ▼
  authorization /         planDigest re-check, expectedAddress check, fee check,
  policy validation       ML-DSA attestation
        │
        ▼
  protected signing       browserSigner — signTransaction / signMessage / getPublicKey
  boundary
        │
        ▼
  signature / PSBT only   { hex, txid, authorization } or { psbt }
```

The page receives a signature, a PSBT, transaction metadata and authorization status. It never
receives a mnemonic, a seed, a private key or a decrypted wallet secret.

Two properties are enforced in code rather than by convention:

- `assertSigner` **refuses to construct** a signer exposing any of `getPrivateKey`,
  `privateKey`, `exportKey`, `getMnemonic`, `mnemonic`, `getSeed`, `seed`, `unlock`, `reveal`
  or `dump`.
- `sealResult` strips every field outside a fixed allowlist on the way back to the caller.

### The limitation, stated without softening

**QuVault's only signer executes in browser JavaScript, in the same realm as the page.** It is
declared as `ISOLATION.BROWSER_JAVASCRIPT`, described as *"Signing runs in browser JavaScript,
in the same realm as the page. Script running in this origin can reach the key while it is in
use. This is not a secure element, a TEE, an HSM or a hardware wallet."*

Anything with script execution in this origin — an XSS, a malicious extension with host
permissions, a compromised bundle dependency — is **inside** this boundary and is not stopped
by it. `assertSigner` refuses to build a signer claiming an isolation level this build does not
implement, so the interface cannot later be pointed at as evidence of hardware protection.
There is a test for that refusal.

---

## 5. Authorization model

**V1 is unchanged, byte for byte.** Existing receipts continue to verify. It still writes
`biometricVerified: true` unconditionally — a statement about the Veyns palm decisions the
operation collected, not about a scanner, because there is no scanner.

**V2 is implemented and dormant.** It carries:

| Requirement | Field |
|---|---|
| wallet identity | `vaultId` |
| user identity | `subject` |
| authorization version | `v` |
| exact transaction digest | `transactionHash` |
| network / chain | `network`, `chain` |
| policy version | `policyVersion` |
| authorization timestamp | `approvedAt` |
| authorization nonce | `nonce` |
| biometric verification state | `biometricVerification` |
| PAD state | `padResult` |
| scanner identity / attestation | `scannerClass`, `scannerAttestation`, `biometricProvider`, `captureReference` |
| transaction binding of the evidence | `bindingNonce`, which must equal `transactionHash` |

`signAuthorizationV2` refuses unless every part is named **and** a provider supplied evidence
where each check was explicitly `PASSED` and `performed`. Verification refuses a V2 record
whose contents are assertions rather than measurements — including `padResult: true`,
`biometricVerification: true`, a missing attestation, evidence bound to another transaction, or
`biometricVerified` smuggled back in.

Nothing in this build can produce a V2 record, because the only provider cannot report a pass.
`/api/scanner` reports `authorizationVersion: 1`.

`expected.minVersion` was added so a caller can one day require V2 without any of today's
callers changing — closing the V1 downgrade surface in advance.

---

## 6. Scanner abstraction

`src/scanner.js` defines discovery, capabilities, capture, PAD result, biometric result,
attestation, and a capture/session identifier shape. It contains no vendor protocol, no USB
descriptors, no certificates, no device IDs and no biometric measurements.

The only provider is the null one:

- `getCapabilities()` → `available: false`, everything false
- `getPADResult()`, `getBiometricResult()`, `getAttestation()` → `NOT_AVAILABLE`,
  `performed: false`
- `connect()`, `capture()` → throw `ScannerUnavailable`
- `discover()` → `[]`

There is no code path in the module that returns `PASSED`. `assertProvider` refuses a provider
exposing `deriveKey`, `unwrapKey`, `getKey`, `getPrivateKey`, `getSecret`, `getTemplate`,
`getImage` or `getRawCapture` — a scanner that could touch key or raw biometric material is
not a sensor.

USB-C is treated as transport only and nothing is shaped around it.

---

## 7. Portable wallet invariant

Documented in [PORTABLE-WALLET-INVARIANT.md](PORTABLE-WALLET-INVARIANT.md):

> The wallet is portable across compatible scanners. A person's palm must not open a different
> wallet merely because a different scanner was used.

**This note corrects the Phase 0 audit**, which sketched a wallet key derived from
`KDF(phrase, palm)`. That was wrong: it makes the key as fragile as the biometric. The palm
belongs one layer up as a key-encryption capability that unwraps an independently
CSPRNG-generated wallet key — it never decides what the key *is*.

Enforced today, with tests:

- `client/wallet.js` does not import `src/scanner.js`, and contains no reference to a scanner
  in code. A test asserts both.
- Restoring the same phrase twice, with different unlock secrets, different salts and
  different device records, yields the same address and the same public key.

---

## 8. Database findings

The schema contains **none** of: raw palm images, raw biometric templates, a reconstructed
palm secret, a private key in any non-legacy row, a mnemonic, or a decrypted seed.

| Column | Contents | Assessment |
|---|---|---|
| `users.sub` | pairwise OIDC subject | opaque, per-application |
| `wallets.sealed_key` | ML-KEM-768 + X25519 + AES-256-GCM envelope | **legacy rows only**; nullable; NULL after migration; the one private-key column |
| `wallets.unlock_sealed` | sealed unlock secret | not a key — useless without the browser's blob |
| `wallets.public_key`, `address` | public | fine |
| `wallets.attestation_chain`, `attestation_root_seal` | ML-DSA public keys and an HMAC | public + integrity anchor |
| `approvals.decision_id`, `proof_id`, `challenge`, `request_id` | Veyns references | opaque |
| `members.palm_id` | `PALM-` + 12 chars of `SHA-256("palm:" + sub)` | **derived from the OIDC subject, not from any biometric** — an opaque enrollment reference, which is what §9 asks for |

No biometric information is proposed for storage. If any ever is, it must be an opaque
commitment or enrollment reference, never biometric material.

---

## 9. Security events

`src/events.js` defines nine events: scanner unavailable, PAD failure, biometric failure,
authorization failure, transaction digest mismatch, signing attempt, signing success, signing
rejection, migration.

Secrets cannot enter an event, and this is enforced rather than reviewed:

1. **Field allowlist.** Only 22 named fields may appear; every other key is dropped. The
   allowlist contains no secret-bearing name.
2. **Value scrubbing.** A phrase-shaped value (twelve lowercase words) and a key-shaped value
   (long hex or base64) are replaced even on an allowed field. Objects become `[object]`.
   Values are capped at 120 characters.
3. **Never fatal.** Emission is wrapped so an event cannot fail the security decision that
   produced it.

Wired at real decision points in `src/app.js`: `broadcastSigned` (attempt, digest mismatch,
authorization failure, rejection, success — the success records `isolation`), the legacy
withdrawal refusal, and `sweepLegacyVault` (migration). `recordScannerEvidence` maps a
provider's verdict to the right event, so PAD and biometric failures are already recorded the
moment a provider exists that can fail.

---

## 10. Tests added (22)

**`test/boundary.test.js` (11)** — the narrow interface signs only the approved transaction
(destination, amount, fee, another coin, an added output, network); returns nothing secret;
refuses a phrase from another wallet; legacy vault cannot spend; legacy migration works and
retires the key; legacy protection text is honest; the null scanner can never pass;
`evidenceIsUsable` requires performed passes; V2 cannot be signed without evidence and cannot
be moved between wallet/account/chain/network/policy/subject/nonce; a V2 record with
placeholders is refused (with a control proving the refusal is about contents, not signature);
V1 still verifies and `minVersion` works.

**`test/signing-boundary.test.js` (11)** — the signer's whole surface is three methods; it
refuses to claim unimplemented isolation; results drop non-allowlisted fields; no API response
carries the vault's actual key material or phrase; unlock returns a 32-byte unlock secret and
never a key; events cannot carry a secret; a refusal records attempt + authorization failure +
rejection and a success records `isolation`; a legacy migration and a legacy spend refusal are
both recorded; the same phrase opens the same wallet regardless of device record; the wallet
module does not import the scanner; `/api/scanner` reports no scanner.

---

## 11. Tests passed

```
ℹ tests 144
ℹ pass 144
ℹ fail 0
```

Baseline preserved: 122 → 144, none removed, none weakened. Verified unchanged: testnet4 send
capability, multisig/PSBT behaviour, Veyns OIDC, ML-DSA authorization, ML-KEM/X25519 vault
sealing, AES-GCM sealing, canonical transaction hashing. Ethereum, Tron, Solana and Stellar
remain `canSend: false`.

The browser flows were exercised against a live demo — vault creation, a send through the
Signer, and the phrase reveal — because the suite does not cover `public/app.js`. All three
work; no console errors.

---

## 12. Remaining vulnerabilities

1. **Signing runs in browser JavaScript.** The dominant remaining risk. See §4 and KNOWN
   SECURITY LIMITATIONS.
2. **One server-side private-key path remains** (`src/app.js:678`). It is migration-only and
   sweep-only, but a QuVault operator with database and `WALLET_SEED` access can still empty a
   legacy vault to an address of their choosing by forging a completed operation row. The fix
   is to have no legacy rows.
3. **`WALLET_SEED` lives for the process lifetime** as a string. It seals unlock secrets and
   legacy keys. An operator with it, plus the database, can release any unlock secret — though
   without the browser's encrypted blob that still opens nothing.
4. **The unlock secret crosses the wire** as base64 in a JSON response. Necessary — the
   browser needs it to decrypt — but it means TLS and origin controls are load-bearing.
5. **`wallet-seed.txt` is in the repository root.** Test-only, but it must never be the
   production value.
6. **No rate limiting** on any route.
7. **V1 remains acceptable for authorizing a spend.** `minVersion` exists but nothing sets it,
   correctly, since V2 cannot yet be produced.
8. **Two NUL bytes were found in `src/authorization.js` source** — the `sameSet` separator was
   written as a raw NUL rather than `U+0000`, which made the file register as binary and be
   silently skipped by `grep` during auditing. The separator semantics are correct (a NUL
   cannot collide with a value, a space could); only the encoding was wrong. Replaced with the
   escape, byte-identical at runtime, and the tests confirm it. **Worth noting as a process
   finding: a file that greps as binary is a file an audit does not read.**

---

## KNOWN SECURITY LIMITATIONS

Stated without hedging.

- **Signing happens in browser JavaScript.** The private key is decrypted into the page's
  realm, used, and dropped. Script executing in this origin can reach it. This is not a TEE,
  not a Secure Element, not an HSM and not a hardware wallet, and the `Signer` interface exists
  to make that replaceable — not to imply it has already been replaced.
- **JavaScript strings cannot be erased.** The mnemonic is a string wherever it exists. Typed
  arrays are zeroed; strings are not, and cannot be. No claim of memory erasure is made.
- **There is no palm-vein scanner.** No driver, no protocol, no PAD, no attestation, no device
  identity. Every scanner concept in this repository is an interface with a null provider.
- **No biometric entropy has been measured.** No fuzzy extractor exists. No number describing
  biometric key strength may appear anywhere in this product.
- **Nothing here is certified.** Not ISO, not FIPS-validated as a system, not formally
  reviewed. The algorithms are standard; the composition has had no external review.
- **The Veyns palm decisions are real, and are not scanner evidence.** V1's
  `biometricVerified: true` is an assertion about a decision collected from Veyns, not a
  measurement this code made.
- **A legacy vault's key can still be opened by the server** for a palm-approved sweep.
- **Only Bitcoin testnet4 can send.** No mainnet capability, and the other four networks are
  address derivation only.
- **`public/app.js` is unit-untested.** Its flows were verified manually in a browser.

| State | Contents |
|---|---|
| IMPLEMENTED | ML-DSA-65 authorization records; ML-KEM-768 + X25519 sealing; AES-256-GCM; transaction-bound signing; palm-gated single-use unlock; browser-held keys; the Signer, scanner and event interfaces |
| EXPERIMENTALLY VALIDATED | nothing |
| CRYPTOGRAPHICALLY REVIEWED | nothing |
| FORMALLY CERTIFIED | nothing |

---

## 13. Phase 2 prerequisites

Before hardware work begins:

1. **This phase is reviewed and signed off.**
2. **An inventory of live `custody = 'server'` rows**, and a migration each owner can actually
   complete. Removing the last legacy row removes `src/app.js:678`.
3. **The real scanner protocol**, from the vendor — not guessed at.
4. **Measured numbers before any biometric key work**: false-rejection rate at the operating
   threshold, error-correction budget, and entropy of the extracted representation, on real
   hardware and a real population.
5. **A decision on the trust anchor**: a device class, with revocation by class.
6. **A recovery path that does not depend on the scanner.** The phrase must remain complete and
   sufficient, or the fuzzy extractor's failure rate becomes a fund-loss rate.
7. **A plan for a real signing boundary**, since browser JavaScript remains the weakest part of
   this architecture and no amount of scanner work improves it.

Not to be implemented until then: palm image processing, biometric template generation, fuzzy
extraction, biometric-to-key derivation, PAD algorithms, USB protocol work, vendor SDK
integration, scanner attestation, hardware secure element integration.
