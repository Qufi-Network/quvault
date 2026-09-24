# Legacy custody deletion gate

A gate for a **future destructive change**. Nothing is deleted in Phase 1.6, and nothing may be
deleted until every condition below is met with evidence rather than assumption.

**Current status: BLOCKED.** Condition 1 has not been attempted — the production database has
not been supplied — so conditions 2, 3 and 4 cannot be evaluated at all.

---

## What this gate governs

| Artefact | Where |
|---|---|
| `QUVAULT_LEGACY_SEED` | `src/app.js:200, 293, 300`; `server.js:28`; `api/handler.js:38` |
| `legacyVault()` | `src/app.js:292–305` |
| `sweepLegacyVault()` | `src/app.js:792–830` |
| `assertSweepAuthorization()` | `src/app.js:751–790` |
| `wallets.sealed_key` column | `src/db.js:27, 93` |
| `CUSTODY.LEGACY` branches | 8 sites in `src/app.js` |
| The `insertWallet` query | `src/app.js:63` — already unreachable |
| `legacyWallet()` test helper, `startWithMigration()` | `test/harness.js:256, 307` |

---

## The four states, and why the distinction matters

The brief asks these to be kept apart, and they are genuinely different claims:

**A — code is unreachable.** No execution path arrives at it. Provable by reading the code.

**B — code is disabled by configuration.** The path exists and would run, but a required input
is absent. Provable by reading the code plus the deployment's environment.

**C — production data no longer requires it.** No row in production depends on the capability.
Provable **only** by querying production.

**D — code and schema can safely be deleted.** Requires A **and** B **and** C, plus the
operational conditions below. Nothing may be claimed at D on the strength of A and B alone.

### Where each artefact stands today

| Artefact | A: unreachable | B: disabled by config | C: data no longer needs it | D: deletable |
|---|---|---|---|---|
| `insertWallet` query | **YES** — called from nowhere | n/a | unknown | **NO** (C unknown) |
| Legacy *spending* path | **YES** — `broadcastPlan` deleted in Phase 1; `requestWithdrawal` refuses legacy at the door; `runOperation` throws | n/a | n/a | **NO** — the code is gone, so there is nothing to delete |
| `sweepLegacyVault` | **NO** — reachable from two routes | **YES** where `QUVAULT_LEGACY_SEED` is unset | unknown | **NO** |
| `legacyVault()` | **NO** | **YES** | unknown | **NO** |
| `QUVAULT_LEGACY_SEED` | **NO** | n/a — it *is* the config | unknown | **NO** |
| `wallets.sealed_key` | **NO** — read by `sweepLegacyVault` | no | unknown | **NO** |
| `CUSTODY.LEGACY` branches | **NO** — they are the refusals | no | unknown | **NO** |

**Nothing is at D. Nothing is close to D, because C is entirely unknown.**

---

## The ten conditions

Each must be satisfied by evidence that can be produced on demand, not by recollection.

### 1. Production inventory completed

```bash
QUVAULT_ADMIN_DATABASE_URL="postgres://…" npm run inventory -- --json
```

**Evidence:** the JSON output, dated, with the database name it reports.
**Status: NOT MET.** Never run against production.

### 2. Zero active server-custody wallets

`totals.serverActive == 0` **and** `totals.custodyServer == 0`.

`serverActive` counts rows where `sealed_key IS NOT NULL`. While it is non-zero, a private key
exists in the database and deleting the code that can open it strands those coins permanently.

`serverInactive` — server custody with no sealed key — must also be zero or individually
explained. A row in that state is a migration that stopped halfway and needs looking at, not
sweeping.

**Status: NOT MET** (unknown).

### 3. Zero server-custody wallets with spendable balances

**This cannot be answered by the inventory command.** Balances live on the chain; the command
reads only the database and reports `serverWithBalances: null` rather than guessing.

**Procedure:** run `npm run inventory -- --addresses`, take the legacy addresses, query the
chain for each, and record confirmed and unconfirmed balances. An address with an unconfirmed
balance is **not** ready: the sweep refuses unconfirmed coins, deliberately, because the key
is about to be destroyed.

**Status: NOT MET** (unknown, and requires chain access as well as database access).

### 4. Zero pending migration operations

`totals.serverWithPendingOperations == 0`. An operation still `collecting` or `running` against
a legacy wallet is a migration in flight. Deleting the code underneath it fails it mid-way.

**Status: NOT MET** (unknown).

### 5. Every migrated wallet independently verified

For each wallet that was migrated, and recorded before deletion:

- the new address is `custody = 'client'` with `sealed_key IS NULL`;
- the sweep transaction is confirmed on chain, by txid;
- the balance at the old address is zero;
- the balance at the new address accounts for the swept amount less fees;
- the attestation lineage verifies against the new root (`attestation_root_seal`);
- the owner has confirmed they hold the twelve words.

The last one cannot be verified from the database and must be collected out of band. **It is
the condition most likely to be skipped and the most expensive to get wrong**: a migrated
wallet whose owner never wrote the phrase down is one browser-profile loss away from being
unrecoverable, and after deletion there is no server-side copy to fall back on.

**Status: NOT MET.**

### 6. No production route depends on legacy signing

Re-verify by code trace at the time of deletion, not by citing this document:

```bash
grep -rn "openSealed(" src/
grep -rn "sweepLegacyVault\|legacyVault()" src/
npm test
```

Expect `openSealed` only against `unlock_sealed` / `payload.unlockSealed`, and the legacy
tests in `test/legacy-closure.test.js` passing.

**Status: MET TODAY** for normal signing — no normal request path reaches a legacy key. It
must be re-checked at deletion time.

### 7. No recovery procedure depends on legacy signing

Distinct from condition 6, and easy to miss. `POST /api/wallet/reset` sweeps a legacy vault to
an address the owner gives — that is a **recovery** path, not a migration path, and it is the
only way an owner who does not want to migrate can still get their coins out.

Deleting `sweepLegacyVault` removes that escape hatch. Before deletion, either every legacy
wallet is migrated (condition 2), or an alternative recovery is documented and tested.

**Status: NOT MET** — no alternative recovery exists, so this rests entirely on condition 2.

### 8. Backup and recovery implications documented

- A database backup taken **before** deletion must be retained, and for how long stated.
- A backup containing `sealed_key` values is a backup containing private keys. It must be
  handled as key material: encrypted at rest, access logged, destruction scheduled.
- **`QUVAULT_LEGACY_SEED` must be retained for as long as any backup containing `sealed_key`
  exists**, or that backup is unreadable and the rollback in condition 9 is impossible.
- Whether the seed is destroyed with the backup, and by whom, must be written down.

**Status: NOT MET.**

### 9. Rollback window explicitly understood

**The deletion of a `sealed_key` column is not reversible from the application.** Restoring it
means restoring a database backup, which also rolls back every wallet, operation and approval
created since the backup.

Therefore:

- deletion happens in **two stages**, not one: first delete the *code* (`sweepLegacyVault`,
  `legacyVault`, `QUVAULT_LEGACY_SEED`) and leave the column; then, after an agreed quiet
  period with the inventory still at zero, drop the column;
- the quiet period is stated in advance, in days, and is long enough for a wallet that was
  missed to surface;
- during stage one the column is dead data and reachable by nobody, which is exactly the point.

**Status: NOT MET** — no window agreed.

### 10. Final database schema decision documented

Decide and record, before touching anything:

- `sealed_key` — dropped, or retained as `NULL`-only with a comment saying why;
- `custody` — retained (it still distinguishes client custody) or collapsed to a single value;
- whether `custody = 'server'` remains a legal value the schema will reject;
- what `walletView.protection` says once there is no legacy mode.

**Status: NOT MET.**

---

## Summary

| Condition | Status |
|---|---|
| 1. Production inventory completed | **NOT MET** — production not supplied |
| 2. Zero active server-custody wallets | **NOT MET** — unknown |
| 3. Zero with spendable balances | **NOT MET** — unknown; needs chain access too |
| 4. Zero pending migration operations | **NOT MET** — unknown |
| 5. Migrated wallets independently verified | **NOT MET** |
| 6. No production route depends on legacy signing | **MET TODAY**, re-verify at deletion |
| 7. No recovery procedure depends on it | **NOT MET** — reset is a recovery path |
| 8. Backup implications documented | **NOT MET** |
| 9. Rollback window understood | **NOT MET** — two-stage deletion proposed, not agreed |
| 10. Schema decision documented | **NOT MET** |

**Gate status: BLOCKED. Do not delete.**

One condition is met. The rest wait on a single input — production database access — and on
decisions that are the operator's to make, not this codebase's.
