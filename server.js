import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createApp } from './src/app.js';

const root = path.dirname(fileURLToPath(import.meta.url));
try {
  process.loadEnvFile(path.join(root, '.env'));
} catch {
  // No .env yet: the page explains what is still missing.
}

const env = process.env;
const port = Number(env.PORT || 4970);
const host = env.HOST || '127.0.0.1';
const publicOrigin = (env.PUBLIC_ORIGIN || `http://localhost:${port}`).replace(/\/$/, '');
const dataDir = path.resolve(root, env.DATA_DIR || 'data');
fs.mkdirSync(dataDir, { recursive: true });

const app = createApp({
  publicOrigin,
  issuer: (env.VEYNS_ISSUER || 'https://sandbox.id.veyns.io').replace(/\/$/, ''),
  clientId: env.VEYNS_CLIENT_ID || '',
  backendSecret: env.VEYNS_BACKEND_SECRET || '',
  walletSeed: env.WALLET_SEED || '',
  // Absent in a normal deployment: without it, no request can open a legacy wallet's private
  // key at all. Set it only on a process that is running the legacy migration.
  legacySeed: env.QUVAULT_LEGACY_SEED || '',
  network: env.BITCOIN_NETWORK || 'testnet4',
  chainApi: env.CHAIN_API || 'https://mempool.space/testnet4/api',
  requirePalmSignin: env.REQUIRE_PALM_SIGNIN === 'true',
  // Deliberately not DATABASE_URL: on a dev machine that often belongs to another project.
  databaseUrl: env.QUVAULT_DATABASE_URL || '',
  dataDir,
  publicDir: path.join(root, 'public'),
});

app.server.listen(port, host, () => {
  console.log(`QuVault is running at ${publicOrigin}`);
});
