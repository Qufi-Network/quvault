/*
 * Every element the page script reaches for has to exist in the page. A missing id fails
 * silently in a browser, so this check runs with the tests instead of waiting to be noticed.
 */
import { readFileSync } from 'node:fs';

const html = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
/* Both scripts the page loads, so an id either of them reaches for is checked. */
const script = ['../public/app.js', '../public/veyns.js']
  .map(file => readFileSync(new URL(file, import.meta.url), 'utf8'))
  .join('\n');

const inPage = new Set([...html.matchAll(/\bid="([\w-]+)"/g)].map(match => match[1]));
/*
 * Both the way ids are reached for: directly, and through a table the script then loops over.
 * The table form was missed once, and the page it broke stayed on "Loading…" with nothing but
 * a console error to say why, which is exactly what this check exists to prevent.
 */
const used = new Set([
  ...[...script.matchAll(/\$\('([\w-]+)'\)/g)].map(match => match[1]),
  ...[...script.matchAll(/\['([a-z][\w-]*)',\s*'(?:browser|palm)'\]/g)].map(match => match[1]),
]);
// Made by the script itself, not written into the page.
const made = new Set(['account-fiat']);

const missing = [...used].filter(id => !inPage.has(id) && !made.has(id));
const unused = [...inPage].filter(id => !used.has(id) && !html.includes(`for="${id}"`) && !html.includes(`aria-labelledby="${id}"`));

if (missing.length) {
  console.error(`Missing from index.html: ${missing.join(', ')}`);
  process.exit(1);
}
console.log(`${used.size} ids used, all present. Not referenced by the script: ${unused.join(', ') || 'none'}.`);
