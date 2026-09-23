# Legacy server custody: inventory, migration and proof

A QuVault wallet is in one of two custody modes. `client` means the key lives in the owner's
browser and the server holds only a sealed unlock secret. `server` — **legacy** — means the
server holds the whole private key.

This document says why the legacy mode exists, where it is still reachable, how to move a
wallet out of it, what to do when that fails, and how to prove afterwards that no server
signing path remains.

---

## 1. Why the legacy path exists

The first version of QuVault generated the wallet key on the server and sealed it with
ML-KEM-768 + X25519 + AES-256-GCM under `WALLET_SEED`. A palm approval released it for one
spend. That design put a complete private key inside the deployment, which means an operator
of the deployment could spend a customer's coins without any palm being involved.

Version 3 moved key generation into the browser. Wallets created since then are `client`
custody and the server has never held their key. The legacy rows are what remain from before
that change, and they are kept — not deleted — because deleting a row does not delete the
coins, it only removes the way back to them.

**No new legacy wallet can be created.** The INSERT that writes a server-custody row
(`insertWallet`) is no longer called from anywhere; every wallet created today goes through
`insertClientWallet`. The legacy population is closed and can only shrink.

---

## 2. Exactly where the legacy key is still reachable

One line in the whole codebase opens a legacy private key:

```
src/app.js:809    const privateKey = openSealed(wallet.sealed_key, legacyVault());
```

It sits inside `sweepLegacyVault`, which is reachable from exactly two handlers:

| Route | Purpose |
|---|---|
| `POST /api/wallet/upgrade` | move the vault into the owner's browser, sweeping the coins to the new key |
| `POST /api/wallet/reset` | erase the vault, sweeping the coins to an address the owner gives |

There is **no path from a withdrawal to that line**. `requestWithdrawal` refuses a legacy
wallet before any palm approvals are collected, and `runOperation` throws if anything else
reaches the point of moving coins.

Four things must all be true before that line executes:

1. **`legacySeed` is configured.** `legacyVault()` reads `QUVAULT_LEGACY_SEED`, which is a
   different variable from `WALLET_SEED` and is absent from an ordinary deployment. Where it
   is absent there is nothing to open the key with, and the request is refused with *"Legacy
   custody migration is not enabled on this deployment."*
2. **The operation hashes to its own digest.** `actionDigest(op.statement, op.details)` is
   recomputed and must equal `op.digest`. A row whose statement was edited after approval no
   longer matches.
3. **The quorum is recomputed from the policy**, not read from `op.required`, so a row
   claiming it needed one approval cannot lower the bar.
4. **Every approval is re-checked against Veyns.** Each approval's `request_id` is fetched
   from Veyns and must come back `approved` with `action.digest` equal to this operation's
   digest. Forging this means forging Veyns, not forging a database row.

`sweepLegacyVault` also cannot be used as a general spending path by construction: it takes no
amount and no output list, and builds the plan itself from the chain's view of the vault
immediately before signing. The only thing it can do is send everything to one address.

---

## 3. Inventory

`npm run inventory` runs one read-only SELECT — the query in `src/legacy-inventory.js`, which
is the same query the tests check — and reports:

| Count | Meaning |
|---|---|
| `wallets` | every row in the table |
| `custodyClient` | key in the owner's browser |
| `custodyServer` | legacy rows |
| `serverActive` | legacy rows that still hold a sealed key |
| `serverInactive` | legacy rows with no sealed key — a migration that stopped halfway |
| `serverWithPendingOperations` | legacy rows with an operation still collecting or running |
| `migratableAutomatically` | active legacy rows with at least one member who can approve |
| `requiringManualRecovery` | active legacy rows with nobody who can approve |
| `serverWithBalances` | **not counted** — that needs the chain, and this reads only the database |

```bash
QUVAULT_ADMIN_DATABASE_URL="postgres://…" npm run inventory
```

Notes on what it does and does not do:

- **It never prints a sealed key, an unlock secret or a seed.** It does not read `WALLET_SEED`
  and does not need it: counting rows does not require the ability to open anything.
- Wallets are named `W-` plus twelve characters of SHA-256 over the address. The identifier is
  stable across runs, so two inventories can be compared, and an address cannot be recovered
  from it. Full addresses appear only with `--addresses`, for the operator who has to look a
  vault up on a block explorer.
- **Deliberately not `DATABASE_URL`.** On a development machine that variable often belongs to
  another project, and pointing this at the wrong database would produce a confident, wrong
  answer.
- Balances are left `null` rather than guessed at. To count coins, take the addresses from an
  `--addresses` run and query the chain separately.

### The production population

**This has not been measured.** Producing it requires a connection to the production database,
which this work did not have. The number of legacy wallets in production is therefore unknown,
and nothing in this document should be read as claiming otherwise. Run the command above
against production to obtain it.

---

## 4. Migration procedure

### Automatic — the owner migrates their own vault

For any wallet in `migratableAutomatically`. The owner does this themselves from Settings.

1. The owner starts the move. A palm approval is raised for *"Move this vault into my browser
   and retire the key held on the server."*
2. The palm approvals are collected — as many as the account's rules require.
3. The browser generates a new key from its own CSPRNG plus server randomness plus ceremony
   jitter, stores it encrypted in IndexedDB, and reports only the address, the public key and
   a signed attestation registration.
4. The server re-verifies the authorisation (§2 above), opens the legacy key, sweeps every
   confirmed coin to the new address, and broadcasts.
5. In one transaction the row becomes `custody = 'client'`, `sealed_key = NULL`, and the new
   attestation lineage is recorded.
6. The owner writes down the twelve words.

**The operator must set `QUVAULT_LEGACY_SEED` for step 4 to be possible.** See §7 for what
that costs.

### Manual — a vault nobody can approve for

For any wallet in `requiringManualRecovery`: the row has no members, so no palm approval can
ever complete and the automatic route cannot run. These need the owner identified out of band
and a member re-attached before the automatic route becomes available. **Do not delete the
row.** The sealed key is the only way back to the coins.

---

## 5. Failure cases

| What happens | Why | What to do |
|---|---|---|
| *"Legacy custody migration is not enabled"* | `QUVAULT_LEGACY_SEED` is unset | Expected in normal running. Set it only on the process performing the migration. |
| *"A payment here is still waiting for its first confirmation"* | an unconfirmed UTXO cannot be swept, and the key is about to be retired | Wait for the confirmation and retry. Nothing has changed. |
| *"That request has been altered since it was approved"* | the operation no longer hashes to its digest | Do not retry. Investigate: something edited the row after it was approved. |
| *"Veyns does not record that approval as granted"* | the upstream decision is missing, expired or was never real | Do not retry. Investigate. |
| *"The palm decisions could not be re-checked with Veyns"* | Veyns is unreachable | Retry when it is reachable. The key was **not** opened — unverified is treated as refused. |
| *"The coins could not be moved"* | the chain refused the broadcast | Nothing has changed. The row still holds its key. Retry. |
| The sweep broadcasts but the database write fails | a crash between step 4 and step 5 | The coins are at the new address, the row still says `server`. See §6. |

---

## 6. Rollback

**The sweep is a Bitcoin transaction and cannot be rolled back.** Everything else can.

- **Before the broadcast:** there is nothing to roll back. No key was opened, or it was opened
  and zeroed without producing a transaction. The row is untouched.
- **After the broadcast, before the database write:** the coins are at the new address, which
  the owner's browser holds the key for, and the row still says `custody = 'server'`. This is
  the dangerous window and it is narrow. Recovery is to complete the row update by hand — the
  browser already has the key, so the money is not lost, but the row must be corrected or the
  vault will appear to be legacy while its coins are elsewhere. The inventory will show this
  as `serverActive` with a zero on-chain balance.
- **After the database write:** the migration is complete and there is nothing to roll back
  to. `sealed_key` is NULL and the old key no longer exists anywhere.

The only genuine loss case is a vault whose owner loses the twelve words after migrating. That
is what the phrase is for, and it is why step 6 of the procedure exists.

**Before migrating anything, take a database backup.** The rollback for a mistake in the row
update is the backup, not the application.

---

## 7. What enabling the migration costs

Setting `QUVAULT_LEGACY_SEED` on the web process puts the capability to open a legacy private
key into the same process as every ordinary request handler. **That is configuration, not
isolation, and this document will not describe it as isolation.** A vulnerability in any
handler, in that window, is a vulnerability with that capability in reach.

The honest posture, in order of preference:

1. **Leave it unset.** Then nothing served by the application can open a legacy key, whatever
   else goes wrong. This is the default, and the state of a fresh deployment.
2. **Set it for a migration window**, migrate, unset it. Keep the window short and watch the
   `custody.migration` security events.
3. **Do not leave it set permanently.** There is no benefit once the population is zero, and
   the inventory will tell you when that is.

Running the migration from a separate process with the variable set only for that process is
better still, and is the one form of this that is actually process isolation.

---

## 8. How to prove no server signing path remains

Four checks. The first three are mechanical; the fourth is the one that matters.

**One — the inventory is empty.**

```bash
QUVAULT_ADMIN_DATABASE_URL="postgres://…" npm run inventory
```

`serverActive` and `custodyServer` should both be `0`. While `serverActive` is `0` no legacy
key exists to open, whatever the code says.

**Two — one call site, and it is the migration.**

```bash
grep -rn "openSealed(" src/
```

Expect five results. Four open `unlock_sealed` or `payload.unlockSealed` — the unlock secret,
which is the palm gate's output and not a key. One opens `sealed_key`, at `src/app.js:809`,
inside `sweepLegacyVault`, through `legacyVault()`.

**Three — the audit sweep is clean.**

```bash
npm run audit
```

It checks that no tracked text file contains a control byte — a file with one is binary to
grep and is silently skipped, so a sweep over it reports a false zero — and that the page names
no key material.

**Four — the tests still hold the property.**

```bash
npm test
```

`test/legacy-closure.test.js` asserts, against a real database and a real HTTP server:

- a legacy wallet cannot start a withdrawal, even with the migration capability enabled;
- with `legacySeed` unset, a fully palm-approved upgrade still cannot open the key, and the row
  survives untouched;
- a fabricated operation row with invented approvals cannot move the coins — tested twice, once
  with a wrong digest and once with a **correct** digest, because `actionDigest` is
  deterministic and an attacker who can write rows can compute it;
- an operation edited after its approval is refused;
- an approval Veyns does not corroborate is refused;
- after a real migration the inventory reports `serverActive: 0`.

Once the inventory is permanently zero, delete `sweepLegacyVault`, the `legacySeed` option and
the `sealed_key` column. Until then, the property is "gated and proven", which is not the same
thing as "absent", and this document exists so the difference stays visible.
