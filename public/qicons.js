/*
 * qicons.js — the qufi.network icon system, rebuilt natively. Each icon is a 64x64 line drawing
 * whose strokes are dashed to their own length, so they draw themselves in when scrolled into
 * view, with their nodes arriving and the lit one pulsing — the same construction as the network's
 * own icons (components/classic/Icons.tsx). It injects an SVG into every <span class="qicon"
 * data-icon="name">, then draws it on view. Pure decoration.
 */
(() => {
  const L = (...d) => d, D = (cx, cy, r, pulse) => ({ cx, cy, r: r || 2.6, pulse: !!pulse });
  const ICONS = {
    // biometric — a vein/ridge drawing (original, in the same hand)
    palm: { l: L('M16 40 C16 27 23 19 32 19 C41 19 48 27 48 40', 'M22 42 C22 31 27 25 32 25 C37 25 42 31 42 42', 'M28 44 C28 36 30 31 32 31 C34 31 36 36 36 44', 'M32 31 v15'), d: [D(32, 22, 2, 1)] },
    core: { l: L('M8 24 L32 12 L56 24 L32 36 Z', 'M8 32 L32 44 L56 32', 'M8 40 L32 52 L56 40'), d: [D(32, 24, 3, 1)] },
    shield: { l: L('M32 8 L52 18 v14 c0 12 -9 20 -20 24 C21 52 12 44 12 32 V18 Z', 'M24 32 h16', 'M32 24 v16'), d: [D(32, 32, 2.2, 1)] },
    proof: { l: L('M10 14 h30 l14 14 v22 H10 Z', 'M40 14 v14 h14', 'M18 38 l6 6 12 -14'), d: [D(47, 21, 2)] },
    gate: { l: L('M22 10 v44', 'M42 10 v44', 'M6 32 h12', 'M46 32 h12'), d: [D(14, 32, 3, 1), D(54, 32, 2)] },
    buildings: { l: L('M6 44 h52', 'M14 44 v-10 h12 v10', 'M26 44 v-18 h12 v18', 'M38 44 v-13 h12 v13', 'M6 52 h52'), d: [D(20, 52, 2), D(32, 52, 2, 1), D(44, 52, 2)] },
    flows: { l: L('M8 18 C24 18 24 32 40 32 h14', 'M8 32 h46', 'M8 46 C24 46 24 32 40 32'), d: [D(54, 32, 3.2, 1), D(8, 18, 2), D(8, 32, 2), D(8, 46, 2)] },
    cube: { l: L('M32 10 L50 20 v20 L32 50 L14 40 V20 Z', 'M14 20 L32 30 L50 20', 'M32 30 v20'), d: [D(32, 30, 2.4, 1)] },
    doc: { l: L('M14 12 h26 l10 10 v30 H14 Z', 'M22 28 h20', 'M22 36 h14'), d: [D(45, 17, 2)] },
  };

  const NS = 'http://www.w3.org/2000/svg';
  function build(name) {
    const ic = ICONS[name] || ICONS.core;
    const svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('viewBox', '0 0 64 64'); svg.setAttribute('class', 'cx-icon'); svg.setAttribute('aria-hidden', 'true');
    let i = 0;
    ic.l.forEach(d => { const p = document.createElementNS(NS, 'path'); p.setAttribute('d', d); p.setAttribute('class', 'cx-line'); p.style.transitionDelay = (0.09 * i++) + 's'; svg.appendChild(p); });
    (ic.d || []).forEach(dt => { const c = document.createElementNS(NS, 'circle'); c.setAttribute('cx', dt.cx); c.setAttribute('cy', dt.cy); c.setAttribute('r', dt.r); c.setAttribute('class', 'cx-dot' + (dt.pulse ? ' cx-pulse' : '')); c.style.transitionDelay = (0.09 * i++) + 's'; svg.appendChild(c); });
    return svg;
  }

  document.querySelectorAll('span.qicon').forEach(h => { h.textContent = ''; h.appendChild(build(h.dataset.icon)); });

  const draw = s => s.classList.add('cx-drawn');
  if ('IntersectionObserver' in window) {
    const io = new IntersectionObserver(es => es.forEach(e => { if (e.isIntersecting) { draw(e.target); io.unobserve(e.target); } }), { rootMargin: '0px 0px -8% 0px' });
    document.querySelectorAll('span.qicon .cx-icon').forEach(s => io.observe(s));
  } else {
    document.querySelectorAll('span.qicon .cx-icon').forEach(draw);
  }
})();
