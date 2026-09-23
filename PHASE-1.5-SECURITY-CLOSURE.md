# Phase 1.5 — security closure

Narrowly scoped to the two risks the Phase 1 report named: legacy server custody, and browser
JavaScript signing. No biometric processing, no fuzzy extraction, no PAD, no USB protocol, no
palm-derived secrets.

**Result: 156 tests pass, 0 fail.** 144 before, 12 added, none removed or weakened.

---

## 1. Legacy custody

### Population

**Not measured.** Producing production counts requires a connection to the production
database, which this work did not have. Nothing here claims a number. What exists instead is
the tool to produce one:

```bash
QUVAULT_ADMIN_DATABASE_URL="postgres://…" npm run inventory
```

It runs one read-only SELECT and reports every count the brief asked for: total wallets,
client custody, server custody, active and inactive server custody, wallets with pending
operations, wallets migratable automatically, and wallets requiring manual recovery. Balances
are reported as `null` rather than guessed at — counting coins needs the chain, and the script
only reads the database.

The query lives in `src/legacy-inventory.js` so the test checks the same SQL the operator
runs, not a copy of it. Wallets are named `W-` plus twelve characters of SHA-256 over the
address: stable across runs, not reversible to an address. No sealed key, unlock secret or
seed is ever printed, and the script does not read `WALLET_SEED` at all.

### Migration status

Documented in [LEGACY-CUSTODY-MIGRATION.md](LEGACY-CUSTODY-MIGRATION.md): why the path exists,
exactly where it is reachable, the automatic and manual procedures, seven failure cases, the
rollback boundary, and four checks that prove no server signing path remains.

**No new legacy wallet can be created.** `insertWallet` — the INSERT that writes a
server-custody row — is called from nowhere. The population is closed and can only shrink.

---

## 2. Server key exposure

One line in the codebase opens a legacy private key:

```
src/app.js:809    const privateKey = openSealed(wallet.sealed_key, legacyVault());
```

| Call site | Opens | Classification |
|---|---|---|
| `src/app.js:809` | `sealed_key` — a full private key | **MIGRATION ONLY** |
| `src/app.js:1095` | `payload.unlockSealed` | LEGITIMATE — unlock secret |
| `src/app.js:1102` | `payload.unlockSealed` | LEGITIMATE |
| `src/app.js:1106` | `wallet.unlock_sealed` | LEGITIMATE |
| `src/app.js:1156` | `mine.unlock_sealed` | LEGITIMATE |

Four conditions must all hold before line 809 executes, and none of them is a database row:

1. `QUVAULT_LEGACY_SEED` is configured — a different variable from `WALLET_SEED`, absent by
   default. Without it there is nothing to open the key with.
2. The operation still hashes to its own digest: `actionDigest(statement, details) == digest`.
3. The quorum is recomputed from the policy rather than read from `op.required`.
4. **Every approval is re-verified against Veyns** — the decision must exist upstream, be
   approved, and name this exact action digest.

Condition 4 is what answers *"the server must not accept a fabricated operation row as
sufficient authorization"*. A database writer can forge rows and can compute a correct digest,
because `actionDigest` is deterministic and the statement is public. They cannot make Veyns
agree that a palm was scanned. Both cases are tested — the weak forgery and the one with a
correct digest — and both are refused with nothing broadcast.

This is enforced in `assertSweepAuthorization`, at the server authorization layer, before any
key is opened. It is not a UI restriction and the old endpoint was not merely hidden: the
general server-side spending function was deleted in Phase 1, and `requestWithdrawal` refuses
a legacy wallet before any palm approvals are collected.

`sweepLegacyVault` also cannot become a spending path by construction: no amount, no output
list, no externally supplied plan. It builds the plan from the chain immediately before
signing and can only send everything to one address.

---

## 3. WALLET_SEED

### Why it exists, and every usage

`WALLET_SEED` is 64 bytes from which `serverKeys()` derives an ML-KEM-768 and an X25519
keypair. Three distinct jobs:

| Usage | Line | What it does | Needed in normal running? |
|---|---|---|---|
| `serverKeys(walletSeed)` → `vault()` | 268 | seals and opens **unlock secrets** | **yes — on every unlock** |
| `sealRoot(walletSeed, …)` | 1203, 1832, 2018 | HMAC anchor pinning an attestation root | **yes — on registration** |
| `rootSealMatches(walletSeed, …)` | 431 | checks that anchor | **yes — on every read** |
| `Boolean(walletSeed)` | 929 | reports `vaultReady` as a boolean | yes, and reveals nothing |
| `serverKeys(legacySeed)` → `legacyVault()` | 300 | opens **legacy private keys** | **no — migration only** |

### What was achieved, and what was not

**Achieved:** the legacy private-key capability is now a separate secret, `QUVAULT_LEGACY_SEED`,
absent from an ordinary deployment. Where it is absent, no request can open a legacy key at
all — there is nothing to open it with. This is tested: a fully palm-approved upgrade is
refused, and the row survives untouched so it can still be migrated later.

**Not achieved, and cannot be without re-architecting the unlock mechanism:** `WALLET_SEED`
remains required during normal operation, because it seals the unlock secrets that the palm
gate releases and anchors the attestation roots. The brief's goal of "no WALLET_SEED during
normal signing" is **not met** and this report will not claim it is. What is true:

- No seed is sent to the browser. Tested: the unlock response carries no seed and no seed-named
  field.
- No configuration endpoint reports a seed. Tested for `/api/config` and `/api/scanner`;
  `vaultReady` is a boolean.
- No seed is written to a log. The security event allowlist has no seed field, and phrase- and
  key-shaped values are scrubbed even on allowed fields.
- `wallet-seed.txt` — **correcting the Phase 1 report, which was wrong about this.** It is
  listed in `.gitignore`, is not tracked by git, and `git log --all -- wallet-seed.txt` is
  empty: it has never been committed. It is a local development artifact on one machine, not a
  file in the repository. It should still be confirmed never to hold a production value.

### Remaining exposure, stated plainly

`WALLET_SEED` lives for the process lifetime as a string and cannot be erased. An operator
holding it plus the database can release any unlock secret — though without the encrypted blob
in the owner's browser, an unlock secret opens nothing.

**Setting `QUVAULT_LEGACY_SEED` on the web process puts the legacy key capability in the same
process as every ordinary request handler. That is configuration, not isolation, and it is not
described as isolation anywhere in this codebase.** The comment above `legacyVault()` says so
explicitly, so the function cannot later be read as a sandbox. Real isolation means running
the migration from a separate process with the variable set only for that process.

---

## 4. Secure signer — current implementation and exact limitations

### The capability model

```
getPublicKey()
signTransaction(authorization)
signMessage(authorization)
capabilities() → { isolationLevel, keyHandle, supportedAlgorithms,
                   supportedNetworks, transactionBinding, humanAuthorizationRequired }
```

`keyHandle` is the wallet's public address — a name, never material. The browser signer
reports `supportedAlgorithms: ['secp256k1-ecdsa', 'ML-DSA-65']`,
`supportedNetworks: ['bitcoin:testnet4']`, `transactionBinding: 'recomputed-canonical-digest'`
and `humanAuthorizationRequired: true`.

**The interface has no way to ask for a key.** `assertSigner` refuses to construct a signer
exposing `getPrivateKey`, `privateKey`, `exportKey`, `exportPrivateKey`, `exportSeed`,
`getSecretKey`, `secretKey`, `getSecret`, `getMnemonic`, `mnemonic`, `getSeed`, `seed`,
`decryptWallet`, `unlock`, `reveal` or `dump`. `sealResult` strips every field outside a fixed
allowlist on the way back.

### Exact transaction authorization

`signTransaction` takes an authorization object, not an arbitrary key operation:

```
{ authorizationId, walletId, transactionDigest, network, chain,
  policyVersion, authorizationVersion, bindingNonce }
```

Two independent checks, and the caller can satisfy neither by assertion:

1. **Every field must equal the authorisation the server issued.** The server now returns
   these in the unlock response — including `policyVersion`, a digest of the sentence the
   approval screen showed, so a record made under one set of rules cannot be read as having
   been made under another. Changing any single field is refused; there is a test that walks
   all eight.
2. **The digest is then recomputed from the plan itself** and compared again. A request and an
   authorisation that agree with each other are still refused if the plan does not hash to
   what they both claim.

`assertSigner` refuses any signer whose `transactionBinding` is not `RECOMPUTED_DIGEST` — a
signer that takes the caller's word for what it is signing is not a boundary, and cannot be
constructed here.

`signMessage` refuses a registration naming a vault the signer does not hold.

### Isolation levels

```
none:browser-javascript   ← the only one implemented
tee
secure-element
hsm
hardware-signer
os-keystore
```

`IMPLEMENTED_ISOLATION` contains exactly one entry, and `assertSigner` **throws** on a signer
claiming any of the others. There is a test that asserts the refusal for each. The interface
therefore cannot later be pointed at as evidence of hardware protection.

### The limitation, without softening

**QuVault's only signer executes in browser JavaScript, in the same realm as the page.** The
private key is decrypted into that realm, used, and dropped. Script executing in this origin —
an XSS, a malicious extension with host permissions, a compromised bundle dependency — is
**inside** this boundary and is not stopped by it.

This is not a hardware wallet. It is not a TEE, a Secure Element or an HSM. `describeIsolation`
says so in those words and a test asserts the wording.

JavaScript strings cannot be erased. The mnemonic is a string wherever it exists. Typed arrays
are zeroed, including on the throwing path; strings are not, and cannot be.

---

## 5. Future hardware signer — interface and trust boundary

```
  Browser
     ↓  a request naming the authorisation, never a key
  Authorization           ← server-issued; the signer checks the request against it
     ↓
  Signer request
     ↓  USB-C, or anything else. UNTRUSTED TRANSPORT.
  Hardware / TEE / Secure Element
     ↓  the key is here and does not leave
  Human authorization     ← confirmed on the device, not in the page
     ↓
  Signature
     ↓
  Browser
```

A hardware signer implements the same three methods and declares a different
`isolationLevel`. Nothing above the boundary changes, which is the point of having built the
interface first.

**USB-C is a cable.** It is transport and carries no security property. A future signer must
assume the transport is observed and modified, which is why the authorisation object and the
recomputed digest are the security boundary rather than the link. Nothing in this repository
invents a secure enclave, an attestation format or a device certificate; when hardware exists,
those come from the hardware.

---

## 6. Palm integration boundary

```
  NIR palm scanner → capture → quality assessment → PAD → biometric verification
        → palm-derived key-encryption capability
        → unlock/authorize secure signer
        → exact transaction authorization
        → signature
```

**The palm never becomes** the Bitcoin private key, the seed phrase, the wallet entropy or the
signature. The wallet spending key is generated by a CSPRNG and by nothing else; the palm
decides whether an existing key can be unwrapped. This is written up in
[PORTABLE-WALLET-INVARIANT.md](PORTABLE-WALLET-INVARIANT.md), which supersedes the Phase 0
audit's `KDF(phrase, palm)` sketch — that was wrong, because it made the key as fragile as the
biometric.

### Portability

> Same user + same enrolled biometric identity + compatible scanner ≠ different wallet.

The wallet must never be tied to a scanner serial number, USB device ID, camera sensor ID,
physical device or scanner-specific random secret. Device attestation may establish that a
scanner is an approved *class* of device; it must not become the wallet's cryptographic
identity.

Enforced today: `client/wallet.js` does not import `src/scanner.js` and contains no scanner
reference in code — asserted by a test. `assertProvider` refuses a provider exposing
`deriveKey`, `unwrapKey`, `getKey`, `getPrivateKey`, `getSecret`, `getTemplate`, `getImage` or
`getRawCapture`. Restoring the same phrase twice with different device records, unlock secrets
and salts yields the same address and public key.

*One precision the audit sweep surfaced:* scanner **constants** do reach the browser bundle,
because `src/authorization.js` imports `SCANNER` and `evidenceIsUsable` for its dormant V2
support, and the wallet module imports `authorization.js`. Nothing in the key derivation path
consults a scanner, so the invariant holds — but "the scanner code is not in the bundle" would
be false, and is not claimed.

### What Phase 2 may implement

Scanner discovery and connection over the real protocol; capture; quality assessment; PAD;
biometric verification; scanner attestation from real hardware; populating authorization V2
with measured evidence.

### What remains deliberately absent

Any transport, vendor API, USB descriptor, certificate or device ID that hardware has not
provided. Feature extraction, template formats, matching, thresholds. Fuzzy extraction.
Biometric-to-key derivation. Any number describing biometric entropy. Hardware secure element
integration.

**Three numbers must be measured before any biometric key work**: false-rejection rate at the
operating threshold, error-correction budget, and entropy of the extracted representation — on
real hardware and a real population. None exists. Until they do, the recovery phrase must
remain a complete and sufficient recovery path on its own, or the fuzzy extractor's failure
rate becomes a fund-loss rate.

---

## 7. Repository sweep

`npm run audit` — 62 tracked text files.

| Term | server | client | page | bundle | test | docs |
|---|---|---|---|---|---|---|
| `privateKey` | 10 | 15 | **0** | 31 | 40 | 3 |
| `private_key` | 0 | 0 | **0** | 0 | 1 | 0 |
| `mnemonic` | 1 | 47 | 4 | 4 | 37 | 10 |
| `seed` | 23 | 19 | 1 | 21 | 18 | 12 |
| `WALLET_SEED` | 4 | 0 | 1 | 0 | 3 | 12 |
| `sealed_key` | 7 | 0 | **0** | 0 | 8 | 12 |
| `openSealed` | 6 | 0 | **0** | 0 | 5 | 8 |
| `getPrivateKey` | 2 | 0 | **0** | 1 | 2 | 2 |
| `exportSeed` | 1 | 0 | **0** | 1 | 1 | 0 |
| `scanner` | 68 | 0 | 0 | 9 | 42 | 83 |
| `biometric` | 30 | 0 | 0 | 7 | 15 | 50 |
| `PAD` | 6 | 0 | 0 | 0 | 2 | 22 |
| `signTransaction` | 1 | 1 | 2 | 2 | 2 | 1 |
| `signMessage` | 1 | 1 | 1 | 2 | 2 | 1 |

Classification:

- **server `privateKey` (10)** — LEGITIMATE: parameter names in `src/bitcoin.js`; one in
  `sweepLegacyVault`, which is MIGRATION.
- **client `privateKey` (15), `mnemonic` (47), `seed` (19)** — LEGITIMATE: this is the module
  that is allowed to hold key material, and the counts include the 18 `fill(0)` sites.
- **page `mnemonic` (4)** — LEGITIMATE: two are comments, two are the restore pass-through and
  the reveal modal. Both irreducible: somebody has to type a phrase in and read one out.
- **page `seed` / `WALLET_SEED` (1 each)** — UI METADATA: the setup message telling an operator
  to run `npm run keygen`.
- **page `signTransaction` / `signMessage` (3)** — LEGITIMATE: calls through the Signer.
- **`getPrivateKey`, `exportSeed`** — LEGITIMATE: forbidden-name lists in `src/signer.js`, and
  tests asserting they are refused. Their presence is the control, not a leak.
- **`sealed_key`, `openSealed` (server)** — MIGRATION (one) and LEGITIMATE (four, unlock
  secrets). Zero in the page.
- **bundle** — the compiled `client/wallet.js`; every count is the client's, plus the scanner
  constants reaching it via `authorization.js` (§6).
- **docs** — DOCUMENTATION.
- **MUST REMOVE** — nothing.

**Binary files cannot evade the audit.** The sweep fails if any tracked text file contains a
control byte, and there is a test asserting the same. This matters because it already
happened: `src/authorization.js` carried two NUL bytes in a `join()` separator, which made it
binary to grep, so every Phase 1 sweep for `biometricVerified` reported a count that omitted
the file defining it. **The Phase 1 report reproduced the bug while describing it** — writing
the escape sequence literally put a NUL into the report, making that file binary too. Both are
fixed, and the check now runs in CI via the test suite.

---

## 8. Tests

**156 pass, 0 fail.** 144 before, 12 added, none removed or weakened.

Four pre-existing migration tests now call `startWithMigration(t)` instead of `start(t)`. That
supplies the migration capability those tests exist to exercise; it does not relax an
assertion. Every other test runs with the capability absent, which is how the property is
proven.

New in `test/legacy-closure.test.js`:

1. the inventory query the operator runs is the one the test checks, and its output carries no
   key material and no address;
2. a legacy wallet cannot start a withdrawal even with migration enabled;
3. with `legacySeed` unset, a fully palm-approved upgrade cannot open the key, and the row
   survives;
4. a forged operation row cannot move the coins — with a wrong digest, and with a correct one;
5. an operation edited after approval is refused;
6. an approval Veyns does not corroborate is refused;
7. a real migration is recorded as an event with no key material, and leaves `serverActive: 0`;
8. the signer refuses a request differing in any of the eight authorization fields;
9. the signer will not sign a message for a vault it does not hold;
10. normal signing needs no seed and the unlock carries none;
11. no configuration endpoint reports anything about the seeds;
12. no tracked source file contains a byte that makes grep skip it.

The browser flows — vault creation and a send through the strengthened signer — were exercised
against a live demo, because the suite does not cover `public/app.js`. Both work, no console
errors.

---

## 9. Remaining risks

1. **Signing runs in browser JavaScript.** Unchanged and dominant. Phase 1.5 made the boundary
   real and checkable; it did not move the key anywhere safer, because nowhere safer exists
   yet.
2. **`WALLET_SEED` is still required in normal running.** Unlock secrets and attestation
   anchors depend on it. It lives for the process lifetime as an unerasable string.
3. **One server-side private-key path remains**, gated four ways. Gated and proven is not the
   same as absent. It goes away when the inventory is permanently zero.
4. **Enabling the migration removes gate 1.** While `QUVAULT_LEGACY_SEED` is set on the web
   process, the capability is in reach of every handler in that process.
5. **The production legacy population is unknown.** The tool exists; it has not been run
   against production.
6. **A crash between sweep and database write** leaves coins at the new address and the row
   saying `server`. Narrow window, recoverable, documented.
7. **The unlock secret crosses the wire** as base64 JSON. Necessary, and it makes TLS and
   origin controls load-bearing.
8. **No rate limiting** on any route.
9. **V1 remains acceptable for authorizing a spend.** `minVersion` exists; nothing sets it,
   correctly, because V2 cannot yet be produced.
10. **`public/app.js` is unit-untested.** Verified manually in a browser.

---

## KNOWN SECURITY LIMITATIONS

- **The browser implementation is not equivalent to a hardware wallet.** It is not a TEE, a
  Secure Element or an HSM. Script in this origin can reach the key while it is in use.
- **Biometric security does not exist in this product yet.** There is no scanner.
- **PAD does not exist yet.** No liveness check has ever run.
- **Scanner attestation does not exist yet.** Nothing has signed anything about a capture.
- **No biometric entropy has been measured.** No fuzzy extractor exists.
- **Nothing is certified.** The algorithms are standard; the composition has had no external
  review.
- **Only Bitcoin testnet4 can send.** Ethereum, Tron, Solana and Stellar remain `canSend:
  false` — address derivation only.

| State | Contents |
|---|---|
| IMPLEMENTED | ML-DSA-65 authorization records; ML-KEM-768 + X25519 sealing; AES-256-GCM; transaction-bound signing with an authorization object; palm-gated single-use unlock; browser-held keys; upstream re-verification of palm decisions before any legacy key opens; Signer, scanner and event interfaces |
| EXPERIMENTALLY VALIDATED | nothing |
| CRYPTOGRAPHICALLY REVIEWED | nothing |
| FORMALLY CERTIFIED | nothing |

---

Phase 2 has not been started. No palm image processing, biometric template generation, fuzzy
extractor, biometric-to-key derivation, PAD algorithm, USB protocol, vendor SDK integration,
scanner attestation or hardware secure element integration has been implemented.
