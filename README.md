# QuVault

A Bitcoin **testnet4** wallet whose key is sealed with post-quantum encryption and whose coins move only after a Veyns palm scan.

- **Creating the wallet needs a palm scan.** The key is generated on the server, sealed at once, and recorded against the palm-verified account that created it.
- **Every withdrawal needs its own palm scan**, bound to that exact transaction: these coins, this address, this amount, this fee. The statement Veyns shows is the statement that gets signed, and the signed plan is the only thing the server will sign with Bitcoin.
- **Receiving needs nothing.** The address is a normal bech32 testnet address.

Node 24, no build step.

## What "post-quantum" means here, exactly

The stored key is sealed with a hybrid envelope: **ML-KEM-768** (NIST FIPS 203) and **X25519** each produce a shared secret, both are mixed through HKDF-SHA256, and the result is an **AES-256-GCM** key. Opening it needs the server seed and a break of *both* schemes, so a quantum computer alone is not enough, and neither is a classical break of X25519.

What it does not do: Bitcoin signs with secp256k1, which a quantum computer would break **on-chain**, whatever the wallet did. That is Bitcoin's problem, not this wallet's. This protects the key while it sits in the database.

Custody, plainly: the server holds the key. The palm is the gate that releases it. Someone who took over the server and the seed could move coins without a palm. That is the trade-off of a wallet you can use from any phone, and it is why this is testnet only.

## Run it

```bash
npm install
npm run keygen     # prints WALLET_SEED
cp .env.example .env
node server.js
```

Fill in `.env`:

| Setting | What it is |
|---|---|
| `VEYNS_CLIENT_ID` | From the Veyns console. Register this exact origin, and the origin plus `/` as the redirect URI, with ES256. |
| `VEYNS_BACKEND_SECRET` | Backend credential from the console. Required: palm approvals go through it. |
| `WALLET_SEED` | From `npm run keygen`. Keep it and keep it secret: losing it loses every sealed key. |
| `REQUIRE_PALM_SIGNIN` | `true` also forces palm at sign-in. Spending always needs palm. |
| `CHAIN_API` | Defaults to `https://mempool.space/testnet4/api`. |
| `QUVAULT_DATABASE_URL` | Optional. Without it, data lives in `data/pgdata` (PGlite). Deliberately not `DATABASE_URL`, which on a dev machine often belongs to another project. |

Get test coins from a testnet4 faucet, send them to the address on the page, and they appear after one confirmation.

## How a withdrawal works

1. You enter an address and an amount. The server reads your confirmed coins and the current fee rate, then **plans** the spend: exact inputs, exact outputs, exact fee.
2. The plan is stored and turned into a Veyns action. Its digest covers the statement and every detail.
3. Veyns sends the request to your phone. You review it and scan your palm.
4. The server checks the signed decision: your account, this request, this challenge, `amr` contains `veyns:palm`, the digest matches the stored plan, and the scan is fresh.
5. Only then is the sealed key opened, the **stored plan** signed (coin selection never runs again) and the transaction broadcast. The approval row is claimed in one conditional update, so a decision can be used once and only once.
6. The key is wiped from memory, and the transaction id is recorded.

A failed broadcast is recorded as failed with the network's own message; no coins move.

## Deploy to Vercel

Same shape as the Handover app: `public/` on the CDN, all `/api/*` through one function (`api/handler.js`).

1. Push to a repository and import it at vercel.com/new.
2. Add Postgres (Neon) from the marketplace and connect it to Production. `DATABASE_URL` or `STORAGE_URL` both work.
3. Register the production address in the Veyns console.
4. Set `VEYNS_CLIENT_ID`, `VEYNS_BACKEND_SECRET` and `WALLET_SEED` as environment variables, marking the last two **Sensitive**, then redeploy.

## Test

```bash
npm test
```

Nine tests run the whole server against a fake Veyns issuer that signs real ES256 tokens and a fake Bitcoin API. They cover the sealed key (round trip, wrong seed, tampering), wallet creation only under a palm scan, refusal of a decision that is not a palm scan, a withdrawal that is planned before and signed only after approval, a decision carrying a different action, broadcasting exactly once, failed broadcasts, other people's approvals, and that the broadcast transaction matches the approved plan byte for byte.
