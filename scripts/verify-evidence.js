/*
 * Verifies an exported evidence bundle, with no database and no running application.
 *
 *   node scripts/verify-evidence.js bundle.json
 *   node scripts/verify-evidence.js bundle.json --json
 *   curl .../api/evidence | node scripts/verify-evidence.js -        # from stdin
 *
 * This is what makes the evidence independent. It reads the bundle, recomputes every entry's
 * hash from the entry's own contents, checks that each commits to the one before it, and
 * reports what it found. Nothing is taken on trust from the exporting system — not the hashes,
 * not the head, not the count.
 *
 * WHAT A PASS MEANS. The bundle is internally consistent: no entry was edited and no entry was
 * removed from the middle, because either breaks the chain.
 *
 * WHAT A PASS DOES NOT MEAN. It does not mean the log is complete. Somebody who can write the
 * whole database can rewrite every entry and recompute the chain from the genesis, and this
 * script would pass that too. Detecting that needs an earlier dated export held somewhere the
 * operator does not control; compare the two, and an earlier export that disagrees with the
 * live log is the proof. See EVIDENCE.md.
 */
import fs from 'node:fs';
import { verifyBundle, summarisePayment, EVIDENCE } from '../src/evidence.js';

const args = process.argv.slice(2);
const asJson = args.includes('--json');
const source = args.find(a => a !== '--json');

if (!source) {
  console.error('Usage: node scripts/verify-evidence.js <bundle.json|-> [--json]');
  process.exit(2);
}

let raw;
try {
  raw = source === '-' ? fs.readFileSync(0, 'utf8') : fs.readFileSync(source, 'utf8');
} catch (error) {
  console.error(`Could not read ${source}: ${error.message}`);
  process.exit(2);
}

let bundle;
try {
  bundle = JSON.parse(raw);
  // The API wraps the bundle alongside its own verdict; accept either shape and ignore theirs.
  if (bundle.bundle) bundle = bundle.bundle;
} catch (error) {
  console.error(`That is not JSON: ${error.message}`);
  process.exit(2);
}

const result = verifyBundle(bundle);
const subjects = [...new Set((bundle.entries ?? []).map(e => e.subjectId).filter(Boolean))];
const payments = subjects.map(id => summarisePayment(bundle.entries, id));

if (asJson) {
  console.log(JSON.stringify({ result, payments }, null, 2));
  process.exit(result.ok ? 0 : 1);
}

console.log(`format      ${bundle.format}`);
console.log(`exported    ${bundle.exportedAt ? new Date(bundle.exportedAt * 1000).toISOString() : 'not stated'}`);
console.log(`entries     ${result.length}`);
console.log(`complete    ${bundle.complete === false ? 'no — a slice, not checked back to the genesis' : 'yes'}`);
console.log(`head        ${result.head ?? 'none'}`);
console.log(`chain       ${result.ok ? 'intact' : 'BROKEN'}`);

if (!result.ok) {
  console.log('\nproblems:');
  for (const problem of result.problems) console.log(`  ${problem}`);
}

if (payments.length) {
  console.log('\nwhat the log records, per subject — each fact present or absent, never inferred:');
  for (const p of payments) {
    const facts = [
      ['proposed', p.proposed], ['attempted', p.authorizationAttempted],
      ['granted', p.authorizationGranted], ['rejected', p.authorizationRejected],
      ['signed', p.signatureProduced], ['broadcast', p.broadcastAccepted],
      ['refused', p.broadcastRefused], ['confirmed', p.confirmed],
    ].filter(([, present]) => present).map(([name]) => name);
    console.log(`  ${p.subjectId}  ${facts.join(' · ') || 'no recognised facts'}`);
    if (p.signatureProduced && !p.broadcastAccepted && !p.broadcastRefused) {
      console.log('      signed, outcome unrecorded — the log does not say whether it reached the network');
    }
    console.log(`      sensor measurement: ${p.sensorMeasurement ? 'claimed' : 'none claimed'}`);
  }
}

const kinds = {};
for (const e of bundle.entries ?? []) kinds[e.kind] = (kinds[e.kind] ?? 0) + 1;
const unknown = Object.keys(kinds).filter(k => !Object.values(EVIDENCE).includes(k));
if (unknown.length) console.log(`\nunknown entry kinds: ${unknown.join(', ')}`);

console.log('\nA pass means the bundle is internally consistent: nothing was edited or removed');
console.log('from the middle. It does NOT mean the log is complete — an operator who can write');
console.log('the whole database can rewrite it and recompute the chain. Compare against an');
console.log('earlier export held outside their control. See EVIDENCE.md.');

process.exit(result.ok ? 0 : 1);
