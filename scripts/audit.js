/*
 * The repository security sweep, run as a command so it is repeatable rather than remembered.
 *
 *   node scripts/audit.js          # report, exit non-zero if something needs attention
 *   node scripts/audit.js --json
 *
 * Two jobs.
 *
 * FIRST: no tracked text file may contain control bytes. This is not tidiness. A file with a
 * raw NUL in it is "binary" to grep, ripgrep, most editors' search and most code review tools,
 * and is silently skipped — so a security sweep over such a file reports a confident zero
 * while never having read it. That happened here: src/authorization.js carried two NUL bytes
 * in a `join()` separator, and every sweep for `biometricVerified` missed the file that
 * defines it. A file that greps as binary is a file an audit does not read.
 *
 * SECOND: count the terms that matter, by area, so a number that moves gets noticed. It does
 * not judge the results — a human classifies them — but it makes the counts cheap to produce
 * and hard to skip.
 */
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const root = path.resolve(import.meta.dirname, '..');
const asJson = process.argv.includes('--json');

/** Only what git tracks: node_modules and build output are not ours to audit. */
const tracked = execFileSync('git', ['ls-files'], { cwd: root, encoding: 'utf8' })
  .split('\n').map(line => line.trim()).filter(Boolean);

const TEXT = /\.(js|mjs|cjs|json|md|css|html|txt|yml|yaml|example)$/i;
const isControl = byte => byte === 0 || byte < 9 || (byte > 13 && byte < 32);

/* ------------------------------------------------- nothing may hide from grep */

const opaque = [];
for (const file of tracked.filter(f => TEXT.test(f))) {
  const full = path.join(root, file);
  let bytes;
  try {
    bytes = fs.readFileSync(full);
  } catch {
    continue; // deleted but still indexed; not this script's problem
  }
  const at = bytes.findIndex(isControl);
  if (at !== -1) {
    opaque.push({ file, offset: at, byte: bytes[at], hint: bytes[at] === 0 ? 'NUL — write it as an escape instead' : 'control byte' });
  }
}

/* ------------------------------------------------------------- the term sweep */

const TERMS = [
  'privateKey', 'private_key', 'mnemonic', 'seed', 'WALLET_SEED', 'sealed_key', 'openSealed',
  'getPrivateKey', 'exportSeed', 'scanner', 'biometric', 'PAD', 'signTransaction', 'signMessage',
];

const AREAS = {
  server: f => f.startsWith('src/') || f.startsWith('api/') || f === 'server.js',
  client: f => f.startsWith('client/'),
  page: f => f.startsWith('public/') && f.endsWith('.js') && !f.startsWith('public/vendor/'),
  bundle: f => f.startsWith('public/vendor/'),
  test: f => f.startsWith('test/') || f.startsWith('scripts/'),
  docs: f => f.endsWith('.md'),
};

const counts = {};
for (const term of TERMS) counts[term] = Object.fromEntries(Object.keys(AREAS).map(a => [a, 0]));

for (const file of tracked.filter(f => TEXT.test(f))) {
  const area = Object.keys(AREAS).find(name => AREAS[name](file));
  if (!area) continue;
  let text;
  try {
    text = fs.readFileSync(path.join(root, file), 'utf8');
  } catch {
    continue;
  }
  for (const term of TERMS) {
    const found = text.split(term).length - 1;
    if (found) counts[term][area] += found;
  }
}

/*
 * The one hard assertion beyond the byte check: the page must never name these at all. It
 * holds a signer, not a key, and nothing in it should have a reason to say these words.
 */
const FORBIDDEN_IN_PAGE = ['privateKey', 'private_key', 'sealed_key', 'openSealed', 'getPrivateKey', 'exportSeed'];
const pageLeaks = FORBIDDEN_IN_PAGE.filter(term => counts[term].page > 0);

const report = { opaqueFiles: opaque, pageLeaks, counts, filesScanned: tracked.filter(f => TEXT.test(f)).length };

if (asJson) {
  console.log(JSON.stringify(report, null, 2));
} else {
  console.log(`scanned ${report.filesScanned} tracked text files\n`);
  console.log('term'.padEnd(18) + Object.keys(AREAS).map(a => a.padStart(8)).join(''));
  for (const term of TERMS) {
    console.log(term.padEnd(18) + Object.keys(AREAS).map(a => String(counts[term][a]).padStart(8)).join(''));
  }
  if (opaque.length) {
    console.log('\nFILES THAT GREP CANNOT READ — an audit over these reports a false zero:');
    for (const o of opaque) console.log(`  ${o.file} at byte ${o.offset}: ${o.hint}`);
  } else {
    console.log('\nEvery tracked text file is readable by grep.');
  }
  if (pageLeaks.length) {
    console.log(`\nTHE PAGE NAMES KEY MATERIAL: ${pageLeaks.join(', ')}`);
  } else {
    console.log('The page names no key material.');
  }
}

process.exit(opaque.length || pageLeaks.length ? 1 : 0);
