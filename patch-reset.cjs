const fs = require('fs');

/* -------------------------------------------------------------- page */

let html = fs.readFileSync('public/index.html', 'utf8');
const swapHtml = (from, to) => {
  const n = html.split(from).length - 1;
  if (n !== 1) throw new Error(`html anchor found ${n} times: ${from.slice(0, 70)}`);
  html = html.replace(from, to);
};

swapHtml(
  `        <section class="lane">
          <header class="lane-head"><h2>Selected account</h2></header>`,
  `        <section class="lane">
          <header class="lane-head"><h2>Start over</h2><p class="quiet">Erase this vault and begin again.</p></header>
          <div class="card settings-card">
            <p class="quiet" id="reset-note"></p>
            <button class="btn ghost small danger" id="reset-vault" type="button">Erase this vault and start over</button>
            <p class="error" id="reset-error" role="alert"></p>
          </div>
        </section>

        <section class="lane">
          <header class="lane-head"><h2>Selected account</h2></header>`,
);

swapHtml(
  `  <dialog id="phrase"`,
  `  <dialog id="reset" aria-labelledby="reset-title">
    <form class="sheet" id="reset-form">
      <p class="eyebrow" id="reset-title">Erase this vault</p>
      <p class="statement">This cannot be undone.</p>
      <dl class="details" id="reset-details"></dl>
      <div id="reset-coins">
        <label for="reset-to">Send the coins here first <span class="optional">a testnet4 address</span></label>
        <input id="reset-to" autocomplete="off" spellcheck="false" placeholder="tb1…">
        <label class="check"><input type="checkbox" id="reset-accept"> <span>Or erase anyway, and let those coins go</span></label>
      </div>
      <p class="error" id="reset-dialog-error" role="alert"></p>
      <div class="sheet-foot">
        <button class="link" id="reset-cancel" type="button">Keep the vault</button>
        <button class="btn brand small" type="submit">Erase with a palm scan</button>
      </div>
    </form>
  </dialog>

  <dialog id="phrase"`,
);
fs.writeFileSync('public/index.html', html);

/* ------------------------------------------------------------ script */

const file = 'public/app.js';
let s = fs.readFileSync(file, 'utf8');
const swap = (from, to) => {
  const n = s.split(from).length - 1;
  if (n !== 1) throw new Error(`js anchor found ${n} times: ${from.slice(0, 70)}`);
  s = s.replace(from, to);
};

swap(
  `  async phrase(operation) {`,
  `  /** Erases the vault on the server and takes the key off this device with it. */
  async reset(operation) {
    const result = await api('/api/wallet/reset', { operationId: operation.id, ...(state.resetChoice ?? {}) });
    try {
      await clearRecord();
    } catch {
      // A browser that will not let go of its storage does not stop the vault being gone.
    }
    this.record = null;
    state.resetChoice = null;
    return result;
  },

  async phrase(operation) {`,
);

swap(
  `$('legacy-move').addEventListener('click', () => startMove($('legacy-error')));`,
  `$('legacy-move').addEventListener('click', () => startMove($('legacy-error')));

/* ------------------------------------------------------- starting over */

function openReset() {
  const data = state.data;
  if (!data?.wallet) return;
  const account = (data.accounts || []).find(item => item.network === 'bitcoin');
  const holding = Number(account?.amount ?? 0);
  const server = data.wallet.custody !== 'client';

  $('reset-error').textContent = '';
  $('reset-dialog-error').textContent = '';
  $('reset-to').value = '';
  $('reset-accept').checked = false;
  $('reset-details').replaceChildren(...detailRows({
    address: data.wallet.address,
    holds: \`\${account?.formatted ?? '0.00000000'} tBTC\`,
    accounts: (data.accounts || []).map(item => item.label).join(', '),
    signers: data.members.map(member => member.label).join(', '),
    erases: server
      ? 'the key held for this vault, its accounts, signers and history'
      : 'the key in this browser, its accounts, signers and history',
  }));
  $('reset-coins').hidden = holding <= 0;
  $('reset-to').hidden = !server;
  $('reset-to').previousElementSibling?.toggleAttribute('hidden', !server);
  $('reset').showModal();
}

$('reset-vault').addEventListener('click', openReset);
$('reset-cancel').addEventListener('click', () => $('reset').close());

$('reset-form').addEventListener('submit', async event => {
  event.preventDefault();
  $('reset-dialog-error').textContent = '';
  const sweepTo = $('reset-to').hidden ? '' : $('reset-to').value.trim();
  const accept = $('reset-accept').checked;
  if (!$('reset-coins').hidden && !sweepTo && !accept) {
    $('reset-dialog-error').textContent = 'Give an address for the coins, or tick the box to let them go.';
    return;
  }
  state.resetChoice = { ...(sweepTo ? { sweepTo } : {}), ...(accept ? { acceptLoss: true } : {}) };
  try {
    const { operation } = await api('/api/wallet/reset/approval', {});
    $('reset').close();
    openApproval(operation, 'Erasing the vault…');
  } catch (error) {
    $('reset-dialog-error').textContent = friendly(error);
  }
});`,
);

/* The sheet, the wait text, and what happens once the palms are in. */
swap(
  `    account: 'Adding the account…', recovery: 'Opening your phrase…', upgrade: 'Moving the vault into this browser…',`,
  `    account: 'Adding the account…', recovery: 'Opening your phrase…', upgrade: 'Moving the vault into this browser…',
  reset: 'Erasing the vault…',`,
);
swap(
  `    upgrade: 'Palm approval · moving the vault',`,
  `    upgrade: 'Palm approval · moving the vault',
    reset: 'Palm approval · erasing the vault',`,
);
swap(
  `    } else if (operation.kind === 'upgrade') {`,
  `    } else if (operation.kind === 'reset') {
      const { txid, sweptSats } = await device.reset(operation);
      toast(txid
        ? \`Vault erased. \${fmtSats(sweptSats)} sats were sent on first (\${shortId(txid)}).\`
        : 'Vault erased. Create a new one whenever you are ready.');
    } else if (operation.kind === 'upgrade') {`,
);

/* Settings says what starting over would cost, before anyone clicks it. */
swap(
  `  $('move-vault').hidden = !legacy;`,
  `  $('move-vault').hidden = !legacy;
  const held = (data.accounts || []).find(item => item.network === 'bitcoin');
  $('reset-note').textContent = legacy
    ? \`Erasing destroys the key this server holds for \${wallet.address}. Anything left at that address goes with it, so sweep it somewhere first.\`
    : \`Erasing removes the vault here and the key in this browser. Your twelve words are the only way back to \${wallet.address}, so send the coins on or write the words down first.\`;`,
);

fs.writeFileSync(file, s);
console.log('start over wired');
