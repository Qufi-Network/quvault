import { createApp } from '../src/app.js';

// Vercel serves public/ from its CDN and sends every /api/* request here (see vercel.json).
const env = process.env;
const productionHost = env.VERCEL_PROJECT_PRODUCTION_URL;

const app = createApp({
  publicOrigin: (env.PUBLIC_ORIGIN || (productionHost ? `https://${productionHost}` : 'http://localhost:3000')).replace(/\/$/, ''),
  issuer: (env.VEYNS_ISSUER || 'https://sandbox.id.veyns.io').replace(/\/$/, ''),
  clientId: env.VEYNS_CLIENT_ID || '',
  backendSecret: env.VEYNS_BACKEND_SECRET || '',
  walletSeed: env.WALLET_SEED || '',
  network: env.BITCOIN_NETWORK || 'testnet4',
  chainApi: env.CHAIN_API || 'https://mempool.space/testnet4/api',
  requirePalmSignin: env.REQUIRE_PALM_SIGNIN === 'true',
  databaseUrl: env.DATABASE_URL || env.STORAGE_URL || env.POSTGRES_URL || '',
  requireDatabaseUrl: true,
});

export default function handler(req, res) {
  // The rewrite passes the original path as __path; put it back so the app routes normally.
  const url = new URL(req.url, 'http://internal');
  const original = url.searchParams.get('__path');
  if (original !== null) {
    url.searchParams.delete('__path');
    req.url = `/api/${original}${url.search}`;
  }
  return app.handle(req, res);
}
