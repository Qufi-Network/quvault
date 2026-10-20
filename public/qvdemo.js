/*
 * qvdemo.js — the "Request a demo" messaging panel. A small chat-style composer that routes the
 * message to the QuFi and Veyns teams. On send it echoes the note as a chat bubble and opens the
 * visitor's own mail client, addressed to info@qufi.network with info@veyns.io cc'd — so nothing
 * is sent from the page itself; the visitor sends it. CSP-safe: same-origin, no inline script.
 */
(() => {
  const modal = document.getElementById('qd-modal');
  if (!modal) return;
  const thread = document.getElementById('qd-thread');
  const form = document.getElementById('qd-form');
  let lastFocus = null;

  const val = id => { const el = document.getElementById(id); return el ? el.value.trim() : ''; };
  const bubble = (text, cls) => { const d = document.createElement('div'); d.className = 'qd-msg ' + cls; d.textContent = text; thread.appendChild(d); thread.scrollTop = thread.scrollHeight; return d; };

  function open() {
    lastFocus = document.activeElement;
    modal.hidden = false;
    document.body.style.overflow = 'hidden';
    const f = document.getElementById('qd-name');
    if (f) setTimeout(() => f.focus(), 50);
  }
  function close() {
    modal.hidden = true;
    document.body.style.overflow = '';
    if (lastFocus && lastFocus.focus) { try { lastFocus.focus(); } catch (_) {} }
  }

  function bind() {
    document.querySelectorAll('[data-qd-open], .qv-demo, .qv-final .qv-btn.primary').forEach(b => {
      if (b.dataset.qdBound) return; b.dataset.qdBound = '1';
      b.addEventListener('click', e => { e.preventDefault(); open(); });
    });
  }
  bind();
  modal.querySelectorAll('[data-qd-close]').forEach(b => b.addEventListener('click', close));
  document.addEventListener('keydown', e => { if (e.key === 'Escape' && !modal.hidden) close(); });

  form.addEventListener('submit', e => {
    e.preventDefault();
    const name = val('qd-name'), email = val('qd-email'), org = val('qd-org'), msg = val('qd-body');
    const note = msg || 'I would like to request a QuVault institutional demo.';
    bubble(note, 'qd-out');

    const subject = 'QuVault demo request' + (org ? ' — ' + org : '');
    const lines = [note, '', '—', name, email, org].filter(Boolean);
    const href = 'mailto:info@qufi.network?cc=info@veyns.io'
      + '&subject=' + encodeURIComponent(subject)
      + '&body=' + encodeURIComponent(lines.join('\n'));

    setTimeout(() => {
      bubble('Opening your mail app to send this to the QuFi and Veyns teams…', 'qd-in');
      window.location.href = href;
    }, 300);
    form.reset();
  });
})();
