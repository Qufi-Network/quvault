# Palm

A digital asset vault where every payment needs a palm approval. Approvals go through Veyns
and are tied to the exact transaction being signed.

Runs on Bitcoin testnet4. Keys are created and kept in the browser, never on the server.

## Run locally

```bash
npm install
npm run keygen
cp .env.example .env
npm run build:client
npm start
```

Then open http://localhost:4970.

## Settings

Put these in `.env`:

- `VEYNS_CLIENT_ID` and `VEYNS_BACKEND_SECRET` from the Veyns console
- `WALLET_SEED` printed by `npm run keygen`
- `QUVAULT_DATABASE_URL` is optional; without it a local database is used

## Tests

```bash
npm test
npm run audit
npm run proof:palm-vault   # needs bitcoind installed
```

## Deploy

Deploys to Vercel. Add a Postgres database, register the site address in the Veyns console,
and set the settings above.

## Docs

Design and security notes are in the other `.md` files in this folder.
