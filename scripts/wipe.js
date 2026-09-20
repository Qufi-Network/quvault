/*
 * Erases every vault in a QuVault database and leaves the schema standing, so the app comes
 * back up empty and the next sign-in starts at "Create your vault".
 *
 * This is storage administration, not a product feature: it is deliberately not reachable
 * from the running app, because a palm-approved erase is. Nothing here weakens that.
 *
 *   QUVAULT_ADMIN_DATABASE_URL="postgres://…" node scripts/wipe.js          # show what is there
 *   QUVAULT_ADMIN_DATABASE_URL="postgres://…" node scripts/wipe.js --yes    # erase it
 *
 * Put the URL in the environment rather than on the command line, so it does not end up in
 * your shell history. It is the same connection string the deployment uses; in Vercel it is
 * the one named STORAGE_DATABASE_URL.
 *
 * What this cannot bring back: the keys sealed for each vault, and therefore any coins those
 * vaults hold. Move anything you want to keep first.
 */
import pg from 'pg';

const url = process.env.QUVAULT_ADMIN_DATABASE_URL;
const confirmed = process.argv.includes('--yes');

if (!url) {
  console.error('Set QUVAULT_ADMIN_DATABASE_URL to the database you want to erase.');
  process.exit(1);
}
if (!/^postgres(ql)?:\/\//.test(url)) {
  console.error('That does not look like a postgres:// connection string.');
  process.exit(1);
}

// In the order the foreign keys allow: children first, parents last.
const TABLES = ['approvals', 'operations', 'accounts', 'members', 'wallets', 'sessions', 'login_nonces', 'users'];

const pool = new pg.Pool({ connectionString: url, max: 1, connectionTimeoutMillis: 15_000 });

try {
  const { rows: [host] } = await pool.query('SELECT current_database() AS name, inet_server_addr()::text AS address');
  console.log(`database: ${host.name}${host.address ? ` at ${host.address}` : ''}`);

  const counts = {};
  for (const table of TABLES) {
    const { rows } = await pool.query(`SELECT count(*)::int AS n FROM ${table}`);
    counts[table] = rows[0].n;
  }
  const wallets = await pool.query('SELECT address, custody, created_at FROM wallets ORDER BY created_at');
  console.log('\nrows:');
  for (const [table, n] of Object.entries(counts)) console.log(`  ${table.padEnd(13)} ${n}`);
  if (wallets.rows.length) {
    console.log('\nvaults that would be erased, and the coins go with them:');
    for (const wallet of wallets.rows) {
      console.log(`  ${wallet.address}  (${wallet.custody}, made ${new Date(Number(wallet.created_at) * 1000).toISOString().slice(0, 10)})`);
    }
  }

  if (!confirmed) {
    console.log('\nNothing was changed. Run it again with --yes to erase all of the above.');
    process.exit(0);
  }

  await pool.query('BEGIN');
  for (const table of TABLES) await pool.query(`DELETE FROM ${table}`);
  await pool.query('COMMIT');
  console.log('\nerased. The app will show "Create your vault" at the next sign-in.');
  console.log('Clear the site data in any browser that held a vault, or its stored key will');
  console.log('refer to a vault that no longer exists.');
} catch (error) {
  await pool.query('ROLLBACK').catch(() => {});
  console.error(`\nfailed: ${error.message}`);
  process.exitCode = 1;
} finally {
  await pool.end();
}
