/*
 * Counts the wallets whose key is still held on the server, so a migration can be planned
 * against facts rather than assumptions.
 *
 *   QUVAULT_ADMIN_DATABASE_URL="postgres://…" node scripts/legacy-inventory.js
 *   QUVAULT_ADMIN_DATABASE_URL="postgres://…" node scripts/legacy-inventory.js --json
 *   QUVAULT_ADMIN_DATABASE_URL="postgres://…" node scripts/legacy-inventory.js --addresses
 *
 * Read-only. It runs one SELECT — the one in src/legacy-inventory.js, which is also the one
 * the tests check — and nothing else. No UPDATE, no DELETE, and no code path that opens a
 * sealed key. It does not need WALLET_SEED and does not read it: counting rows does not
 * require a seed, and asking for one would put it somewhere it is not needed.
 *
 * Wallets are named by a stable redacted identifier. Full addresses appear only with
 * --addresses, for the operator who has to look a vault up on a block explorer.
 *
 * It never prints a sealed key, an unlock secret, a seed or any part of one.
 *
 * Deliberately NOT DATABASE_URL: on a development machine that variable often belongs to some
 * other project, and pointing this at the wrong database would produce a confident, wrong
 * answer. It must be named for this application.
 */
import pg from 'pg';
import { INVENTORY_SQL, summarise } from '../src/legacy-inventory.js';

const url = process.env.QUVAULT_ADMIN_DATABASE_URL;
const asJson = process.argv.includes('--json');
const showAddresses = process.argv.includes('--addresses');

if (!url) {
  console.error('Set QUVAULT_ADMIN_DATABASE_URL to the QuVault database you want to inventory.');
  console.error('Do not use DATABASE_URL: on a dev machine it often points at another project.');
  process.exit(1);
}
if (!/^postgres(ql)?:\/\//.test(url)) {
  console.error('That does not look like a postgres:// connection string.');
  process.exit(1);
}

const pool = new pg.Pool({ connectionString: url, max: 1, connectionTimeoutMillis: 15_000 });

try {
  const { rows: [where] } = await pool.query('SELECT current_database() AS name');
  const { rows } = await pool.query(INVENTORY_SQL);
  const report = { database: where.name, at: new Date().toISOString(), ...summarise(rows, { showAddresses }) };

  if (asJson) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(`database: ${report.database}`);
    console.log(`at:       ${report.at}\n`);
    for (const [name, value] of Object.entries(report.totals)) {
      console.log(`  ${name.padEnd(28)} ${value === null ? '(needs a chain lookup — not counted here)' : value}`);
    }
    if (report.legacyWallets.length) {
      console.log('\nlegacy wallets:');
      for (const w of report.legacyWallets) {
        console.log(`  ${w.id}  key:${w.holdsServerKey ? 'held' : 'gone'}  members:${w.members}  pending:${w.pendingOperations}  ${w.route}`);
      }
    } else {
      console.log('\nNo wallet in this database holds a key on the server.');
    }
    console.log('\nBalances are not counted here: that needs the chain, and this script only reads the database.');
  }
} finally {
  await pool.end();
}
