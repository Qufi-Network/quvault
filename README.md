# QuVault

A Bitcoin **testnet4** wallet where a human palm authorises each individual transaction, and
that authorisation is a post-quantum signed receipt anyone can check.

The codebase, the npm package and the database variables are all named QuVault. The web
surface is branded **Veyns** — *Human Gated Security* — which is also the name of the palm
identity service the approvals go through.

- **The key is generated in your browser** and never leaves it. The server holds an address, a
  public key, and a sealed secret that is useless on its own.
- **Every withdrawal needs its own palm scan**, bound to that exact transaction: these coins,
  this address, this amount, this fee. The statement Veyns shows you is the statement the
  digest covers, and your browser refuses to sign anything that does not hash to it.
- **Receiving needs nothing.** The address is an ordinary bech32 testnet address.

Node 24. One build step, for the browser wallet module: `npm run build:client`.

## What it actually does, in order

```
  you enter an address and an amount
        ↓
  the server plans the spend — exact inputs, outputs, fee — and hashes it
        ↓                                    (canonical JSON → SHA-256 → digest)
  Veyns shows you that statement; you scan your palm
        ↓
  enough palms land for the rules this amount triggers
        ↓
  the server releases a one-time unlock secret
        ↓
  your browser decrypts its key, RE-COMPUTES the digest, and refuses on mismatch
        ↓
  it signs the transaction and an ML-DSA-65 receipt with a key the server does not have
        ↓
  the server verifies the receipt against the plan, and broadcasts
```

The digest is the security boundary. Change the destination, the amount, the fee, a single
input, or the network after the scan, and the browser refuses: *"This is not the transaction
that was approved. Nothing has been signed."*

## Custody, plainly

**The server cannot spend your coins.** The twelve words exist only in your browser, encrypted
under a key derived from two things: a secret the server releases after a palm approval, and a
salt stored only on your device. The server has one of those and never the other — so taking
over the server and its seed opens nothing without also taking over your browser's storage.

What the server *can* do is refuse to release the unlock secret. That stops you spending from
that browser; it does not lose your money, because your twelve words restore the wallet
anywhere.

**Wallets created before version 3 are different.** Those have `custody = 'server'`: the server
holds the whole private key, sealed. They **cannot spend at all** any more — a withdrawal is
refused before any palm is collected — and the only thing that key may still do is empty the
vault to one address under a completed palm approval, as part of migrating into a browser. That
capability needs a separate `QUVAULT_LEGACY_SEED` which is absent from a normal deployment. See
[LEGACY-CUSTODY-MIGRATION.md](LEGACY-CUSTODY-MIGRATION.md).

No new server-custody wallet can be created; the code path that made them is unreachable.

## What "post-quantum" means here, exactly

Two separate things, and neither is the Bitcoin signature:

**The sealed secrets.** A hybrid envelope: **ML-KEM-768** (FIPS 203) and **X25519** each produce
a shared secret, both go through HKDF-SHA256, and the result is an **AES-256-GCM** key. Opening
it needs a break of *both*, so a quantum computer alone is not enough and neither is a classical
break of X25519. This protects the unlock secrets — and, for legacy wallets only, the old
private keys.

**The authorisation receipts.** Each approval is signed with **ML-DSA-65** (FIPS 204) under a
domain-separated context, by a key derived from your recovery phrase. The server learns only the
public half, so a QuVault operator cannot manufacture a receipt claiming you approved something.
That is what makes an approval evidence rather than a log line.

**What it does not do:** Bitcoin signs with secp256k1, which a quantum computer breaks
**on-chain**, whatever this wallet does. That is Bitcoin's problem, not this wallet's.

## What does not exist

Stated here because the rest of this file would otherwise imply it:

- **There is no palm-vein scanner.** No NIR capture, no liveness detection, no biometric
  matching, no device attestation. The palm decisions are real and come from Veyns; nothing in
  this repository has ever spoken to scanner hardware. The interfaces in `src/scanner.js` are
  preparation, and the only provider reports `NOT_AVAILABLE` to everything.
- **Signing runs in browser JavaScript.** It is not a secure element, a TEE, an HSM or a
  hardware wallet. Script running in this origin can reach the key while it is in use. This is
  the dominant security limitation and `src/signer.js` says so in those words.
- **Nothing is certified.** The algorithms are standard; the composition has had no external
  review.
- **Testnet4 only.** Ethereum, Tron, Solana and Stellar addresses derive from the same phrase
  but cannot send.

## Run it

```bash
npm install
npm run keygen          # prints WALLET_SEED
cp .env.example .env
npm run build:client    # bundles client/wallet.js → public/vendor/wallet.js
npm start
```

Fill in `.env`:

| Setting | What it is |
|---|---|
| `VEYNS_CLIENT_ID` | From the Veyns console. Register this exact origin, and the origin plus `/` as the redirect URI, with ES256. |
| `VEYNS_BACKEND_SECRET` | Backend credential from the console. Required: palm approvals go through it. |
| `WALLET_SEED` | From `npm run keygen`. Seals unlock secrets and anchors attestation roots. Lose it and browsers cannot be unlocked — owners recover from their twelve words. See [WALLET-SEED-DEPENDENCY-MAP.md](WALLET-SEED-DEPENDENCY-MAP.md). |
| `QUVAULT_LEGACY_SEED` | **Leave unset.** Only a process migrating pre-v3 server-custody wallets needs it. Without it, nothing served here can open a legacy private key. |
| `REQUIRE_PALM_SIGNIN` | `true` also forces palm at sign-in. Spending always needs palm. |
| `CHAIN_API` | Defaults to `https://mempool.space/testnet4/api`. |
| `QUVAULT_DATABASE_URL` | Optional. Without it, data lives in `data/pgdata` (PGlite). Deliberately **not** `DATABASE_URL`, which on a dev machine often belongs to another project. |

Get test coins from a testnet4 faucet, send them to the address on the page, and they appear
after one confirmation.

## Rules and approvers

Each account carries a list of approvers and a ladder of amount rules, for example:

| Amount | Approvals |
|---|---|
| Up to 100,000 sats | 1 palm |
| Up to 5,000,000 sats | 2 palms |
| Anything larger | 3 palms |

One approver and one rule is an ordinary personal wallet. Add people by their **approver code**,
shown on their own wallet page after they sign in once.

Three things keep the rules honest:

- **Changing the rules is itself palm-approved**, at the strongest quorum the *current* rules
  ask for. Going from two palms back to one needs two palms.
- **Every approver signs the same exact action.** The digest covers the statement and all its
  details, so approvals of different transactions can never add up to a quorum. A request that
  never gathers its quorum expires after 30 minutes, and palm requests still waiting at Veyns
  are cancelled.
- **The rules in force are named in the signing request**, as a `policyVersion` digest, and your
  browser refuses to sign if it disagrees with what the server authorised. Note the limit: the
  V1 receipt that gets stored does *not* carry that digest — only the dormant V2 record does —
  so today the policy is checked at signing time and is not part of the permanent evidence.

Larger amounts can never need fewer approvals than smaller ones, and no rule can ask for more
approvals than there are approvers.

## On-chain quorum

A database rule is a rule this server enforces. Moving it on-chain makes Bitcoin enforce it:
the account's coins are swept to a **P2WSH m-of-n** address (BIP67 key order), after which
spending needs real signatures, not a row.

Each signer derives their key from **their own** recovery phrase at `m/48'/1'/0'/2'/0/{branch}`,
one branch per vault — so co-signing requires having your own vault, and there is no second set
of words to keep. The server combines PSBTs and can never produce a signature itself.

Two things Bitcoin forces: no amount ladder on-chain, because a script cannot read output
amounts; and changing signers or the threshold means a new address and another sweep.

**Known gap:** a quorum spend completed by co-signers carries no ML-DSA receipt, because only
the vault owner holds an attestation key. Per-signer attestation keys are the next step. See
[ON-CHAIN-MULTISIG.md](ON-CHAIN-MULTISIG.md).

## Rate limiting

Counts live in Postgres, not in memory — this runs as a serverless function, where each
instance would keep its own count and a cold start would forget it. Policies are attached to
individual routes in `src/app.js`, so the cost falls on the routes that are worth protecting:
sign-in, anything that spends someone else's quota, and anything that touches money.

The routes the page *polls* while waiting for a palm carry no limit, deliberately. It fails
open: a limiter whose own table is unreachable lets traffic through, because it decides how
often and never whether. See `src/rate-limit.js`.

## Deploy to Vercel

`public/` on the CDN, all `/api/*` through one function (`api/handler.js`).

1. Push to a repository and import it at vercel.com/new.
2. Add Postgres (Neon) from the marketplace and connect it to Production. The handler accepts
   any `postgres://` variable — `DATABASE_URL`, `STORAGE_DATABASE_URL`, `POSTGRES_URL` and
   others — preferring a pooled one, and reports which name it chose in `/api/config`.
3. Register the production origin in the Veyns console.
4. Set `VEYNS_CLIENT_ID`, `VEYNS_BACKEND_SECRET` and `WALLET_SEED`, marking the last two
   **Sensitive**, then redeploy. Leave `QUVAULT_LEGACY_SEED` unset.

## Test and audit

```bash
npm test                      # 166 tests across 21 files
npm run audit                 # repository security sweep
npm run inventory -- --help   # legacy custody inventory (needs QUVAULT_ADMIN_DATABASE_URL)
```

The suite runs the whole server against a fake Veyns issuer that signs real ES256 tokens, a
fake Bitcoin API, and Postgres-in-wasm — so it needs no database and no network. It covers the
sealed envelopes, palm-gated creation and spending, transaction binding against every
substitution (destination, amount, fee, network, inputs, outputs, structure, wallet, account,
policy), on-chain multisig and PSBT flows, the signing boundary, the legacy custody refusals
including forged database rows, the security event allowlist, and rate limiting.

`npm run audit` also fails if any tracked text file contains a control byte — such a file reads
as binary to `grep` and is silently skipped, so a security sweep over it reports a confident
zero. That happened once here, and the check exists so it cannot happen again.

## Security documents

| Document | What it covers |
|---|---|
| [PORTABLE-PALM-WALLET-AUDIT.md](PORTABLE-PALM-WALLET-AUDIT.md) | Phase 0: the architecture as found, and every private-key touchpoint |
| [PORTABLE-PALM-WALLET-PHASE-1-REPORT.md](PORTABLE-PALM-WALLET-PHASE-1-REPORT.md) | Phase 1: secret confinement, the signer, dormant authorisation V2 |
| [PHASE-1.5-SECURITY-CLOSURE.md](PHASE-1.5-SECURITY-CLOSURE.md) | Phase 1.5: legacy custody closed, signing boundary hardened |
| [PHASE-1.6-PRODUCTION-READINESS.md](PHASE-1.6-PRODUCTION-READINESS.md) | Readiness classification per area, with evidence and blockers |
| [LEGACY-CUSTODY-MIGRATION.md](LEGACY-CUSTODY-MIGRATION.md) | Why legacy custody exists, how to migrate, how to prove it is gone |
| [LEGACY-CUSTODY-DELETION-GATE.md](LEGACY-CUSTODY-DELETION-GATE.md) | The ten conditions before legacy code may be deleted |
| [WALLET-SEED-DEPENDENCY-MAP.md](WALLET-SEED-DEPENDENCY-MAP.md) | Every use of `WALLET_SEED`, and what it does and does not protect |
| [SCANNER-TRUST-BOUNDARY.md](SCANNER-TRUST-BOUNDARY.md) | Where trust changes hands in a future scanner, and what is absent |
| [PORTABLE-WALLET-INVARIANT.md](PORTABLE-WALLET-INVARIANT.md) | The palm must not become the key; the wallet must survive a new scanner |
| [PHASE-2-ENTRY-GATE.md](PHASE-2-ENTRY-GATE.md) | What must be known before scanner integration begins |
| [ON-CHAIN-MULTISIG.md](ON-CHAIN-MULTISIG.md) | The P2WSH design and what Bitcoin forces |
| [HUMAN-VERIFIED.md](HUMAN-VERIFIED.md) | What a palm approval does and does not prove |
