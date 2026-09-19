/*
 * Every element the page script reaches for has to exist in the page. A missing id fails
 * silently in a browser, so this check runs with the tests instead of waiting to be noticed.
 */
import { readFileSync } from 'node:fs';

const html = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
const script = readFileSync(new URL('../public/app.js', import.meta.url), 'utf8');

const inPage = new Set([...html.matchAll(/\bid="([\w-]+)"/g)].map(match => match[1]));
const used = new Set([...script.matchAll(/\$\('([\w-]+)'\)/g)].map(match => match[1]));
// Made by the script itself, not written into the page.
const made = new Set(['account-fiat']);

const missing = [...used].filter(id => !inPage.has(id) && !made.has(id));
const unused = [...inPage].filter(id => !used.has(id) && !html.includes(`for="${id}"`) && !html.includes(`aria-labelledby="${id}"`));

if (missing.length) {
  console.error(`Missing from index.html: ${missing.join(', ')}`);
  process.exit(1);
}
console.log(`${used.size} ids used, all present. Not referenced by the script: ${unused.join(', ') || 'none'}.`);
