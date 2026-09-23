import { createApp } from '../src/app.js';

// Vercel serves public/ from its CDN and sends every /api/* request here (see vercel.json).
const env = process.env;
const productionHost = env.VERCEL_PROJECT_PRODUCTION_URL;

/**
 * Finds the Postgres connection however the database was connected: Neon on Vercel names the
 * variable after the prefix chosen at the time, so accept the usual names and then any variable
 * holding a postgres:// URL. Only names are ever reported, never values.
 */
function findDatabase(environment) {
  const preferred = ['DATABASE_URL', 'STORAGE_URL', 'POSTGRES_URL', 'STORAGE_DATABASE_URL', 'POSTGRES_PRISMA_URL'];
  const isPostgres = value => /^postgres(ql)?:\/\//.test(value ?? '');
  const pooled = name => !/UNPOOLED|NO_?SSL|NON_?POOLING|PRISMA/i.test(name);

  let chosen = preferred.find(name => isPostgres(environment[name]));
  chosen ??= Object.keys(environment).find(name => isPostgres(environment[name]) && pooled(name));
  chosen ??= Object.keys(environment).find(name => isPostgres(environment[name]));

  return {
    databaseUrl: chosen ? environment[chosen] : '',
    databaseVariable: chosen ?? null,
    // Names only, so a missing connection can be diagnosed from the outside without leaking anything.
    databaseCandidates: Object.keys(environment).filter(name => /POSTGRES|DATABASE|NEON|STORAGE/i.test(name)).sort(),
  };
}

const app = createApp({
  publicOrigin: (env.PUBLIC_ORIGIN || (productionHost ? `https://${productionHost}` : 'http://localhost:3000')).replace(/\/$/, ''),
  issuer: (env.VEYNS_ISSUER || 'https://sandbox.id.veyns.io').replace(/\/$/, ''),
  clientId: env.VEYNS_CLIENT_ID || '',
  backendSecret: env.VEYNS_BACKEND_SECRET || '',
  walletSeed: env.WALLET_SEED || '',
  // Absent in a normal deployment: without it, no request can open a legacy wallet's private
  // key at all. Setting it here puts that capability in the web process, which is the thing
  // the migration document tells operators not to do.
  legacySeed: env.QUVAULT_LEGACY_SEED || '',
  network: env.BITCOIN_NETWORK || 'testnet4',
  chainApi: env.CHAIN_API || 'https://mempool.space/testnet4/api',
  requirePalmSignin: env.REQUIRE_PALM_SIGNIN === 'true',
  ...findDatabase(env),
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
