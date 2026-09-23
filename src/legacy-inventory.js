/*
 * The legacy custody inventory: one query, one summary, used by both the operator script and
 * the test that proves it counts correctly.
 *
 * Keeping the SQL here rather than inside `scripts/legacy-inventory.js` is the whole point —
 * a test against a copy of the query would prove nothing about the query the operator runs.
 *
 * Read-only by construction: there is one statement and it is a SELECT.
 */
import crypto from 'node:crypto';

export const INVENTORY_SQL = `
  SELECT w.user_id, w.address, w.custody, (w.sealed_key IS NOT NULL) AS holds_key,
         w.created_at,
         (SELECT count(*) FROM members m WHERE m.wallet_user_id = w.user_id) AS members,
         (SELECT count(*) FROM operations o
           WHERE o.wallet_user_id = w.user_id AND o.status IN ('collecting', 'running')) AS pending,
         (SELECT count(*) FROM operations o WHERE o.wallet_user_id = w.user_id) AS operations
    FROM wallets w ORDER BY w.created_at`;

/**
 * A stable name for a wallet that is not its address.
 *
 * The same wallet gets the same identifier on every run, so two inventories can be compared.
 * An address cannot be recovered from it, though a known address can be checked against it —
 * which is what an operator needs and is all they need.
 */
export const walletId = address => `W-${crypto.createHash('sha256').update(address).digest('hex').slice(0, 12)}`;

/**
 * Turns the rows into the counts a migration is planned against.
 *
 * "Active" means the row still holds a key the server could open. A row that says server
 * custody but has no sealed key is a migration that stopped halfway; it is counted separately
 * because it needs looking at rather than sweeping.
 *
 * "Migratable automatically" means somebody can put a palm to it. A vault with no members has
 * nobody who can approve anything, so the normal flow cannot move it at all.
 */
export function summarise(rows, { showAddresses = false } = {}) {
  const legacy = rows.filter(r => r.custody === 'server');
  const active = legacy.filter(r => r.holds_key);
  const inactive = legacy.filter(r => !r.holds_key);
  const automatic = active.filter(r => Number(r.members) > 0);
  const manual = active.filter(r => Number(r.members) === 0);

  return {
    totals: {
      wallets: rows.length,
      custodyClient: rows.filter(r => r.custody === 'client').length,
      custodyServer: legacy.length,
      serverActive: active.length,
      serverInactive: inactive.length,
      serverWithPendingOperations: legacy.filter(r => Number(r.pending) > 0).length,
      migratableAutomatically: automatic.length,
      requiringManualRecovery: manual.length,
      // Balances need the chain, not the database. Left null rather than guessed at.
      serverWithBalances: null,
    },
    legacyWallets: legacy.map(r => ({
      id: walletId(r.address),
      ...(showAddresses ? { address: r.address } : {}),
      holdsServerKey: Boolean(r.holds_key),
      members: Number(r.members),
      operations: Number(r.operations),
      pendingOperations: Number(r.pending),
      createdAt: Number(r.created_at),
      route: Number(r.members) > 0 ? 'automatic: /api/wallet/upgrade' : 'manual recovery required',
    })),
  };
}
