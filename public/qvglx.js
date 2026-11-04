/*
 * qvglx.js — the figure graphics that replace every icon. One <canvas class="qv-glx"> per concept,
 * each a distinct clean line drawing chosen by data-fx and relevant to its label. Rendered as thin
 * lines with small crisp nodes on an ordinary 2D canvas (so the page can carry many without hitting
 * the WebGL-context limit). Blue on light cards, white on the blue band (data-light switches it).
 * One shared loop; only on-screen figures draw. No glow, no pulsing. CSP-safe.
 */
(() => {
  const reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const TAU = Math.PI * 2;
  const SPIN = { lattice: 0.25, cube: 0.45, fingerprint: 0.32, scan: 0.3, swap: 0.5 }; // figures that turn fully

  function geom(mode) {
    const nodes = [], edges = [];
    const add = (x, y, lit) => { nodes.push([x, y, lit ? 1 : 0]); return nodes.length - 1; };
    const seg = (ax, ay, bx, by) => { edges.push(add(ax, ay), add(bx, by)); };
    const poly = (pts, close) => { const idx = pts.map(p => add(p[0], p[1], p[2])); for (let i = 0; i < idx.length - 1; i++) edges.push(idx[i], idx[i + 1]); if (close) edges.push(idx[idx.length - 1], idx[0]); return idx; };
    const arc = (cx, cy, r, a0, a1, n, ry) => { const p = []; ry = ry == null ? r : ry; for (let i = 0; i <= n; i++) { const a = a0 + (a1 - a0) * i / n; p.push([cx + Math.cos(a) * r, cy + Math.sin(a) * ry]); } return p; };
    const ring = (cx, cy, r, n, ry) => poly(arc(cx, cy, r, 0, TAU, n, ry).slice(0, n), true);

    switch (mode) {
      case 'fingerprint': { // biometric
        for (let k = 0; k < 4; k++) poly(arc(0, 0.18, 0.26 + k * 0.2, Math.PI * 1.18, Math.PI * -0.18, 16));
        add(0, 0.18, 1); break;
      }
      case 'people': { // multi-party control
        const hx = [-0.6, 0, 0.6]; const heads = [];
        hx.forEach((x, i) => { ring(x, -0.34, 0.15, 10); poly(arc(x, 0.1, 0.3, Math.PI * 1.08, Math.PI * -0.08, 10)); heads.push(add(x, -0.34, i === 1)); });
        edges.push(heads[0], heads[1], heads[1], heads[2]); break;
      }
      case 'check': { // independent verification
        poly([[-0.85, -0.6], [0.85, -0.6], [0.85, 0.62], [-0.85, 0.62]], true);
        seg(-0.85, -0.3, 0.85, -0.3);
        poly([[-0.32, 0.12], [-0.08, 0.36], [0.4, -0.12]]); add(-0.32, 0.12, 1); add(0.4, -0.12, 1); break;
      }
      case 'lattice': { // post quantum security
        const g = [], s = 3; for (let r = -s; r <= s; r++) { g[r] = []; for (let c = -s; c <= s; c++) g[r][c] = add(c * 0.28, r * 0.28, (r + c) % 3 === 0); }
        for (let r = -s; r <= s; r++) for (let c = -s; c < s; c++) edges.push(g[r][c], g[r][c + 1]);
        for (let c = -s; c <= s; c++) for (let r = -s; r < s; r++) edges.push(g[r][c], g[r + 1][c]); break;
      }
      case 'send': { // action requested — a transaction routed out
        poly([[-0.9, 0.3], [-0.3, 0.3], [0.2, -0.2]]); add(-0.9, 0.3, 1);
        poly([[0.2, -0.45], [0.62, -0.2], [0.2, 0.05]]); // arrow head
        seg(0.2, -0.2, 0.62, -0.2); break;
      }
      case 'rules': { // policy checked — policy rails with set points
        const y = [-0.45, 0, 0.45], px = [0.3, -0.25, 0.45];
        y.forEach((yy, i) => { seg(-0.85, yy, 0.85, yy); add(px[i], yy, 1); }); break;
      }
      case 'palm': { // palm authorisation — a hand
        poly([[-0.5, 0.85], [-0.55, 0.0], [-0.5, -0.2]]);
        [-0.4, -0.14, 0.12, 0.38].forEach((x, i) => { const top = -0.55 - (i === 1 || i === 2 ? 0.14 : 0); poly([[x - 0.08, -0.2], [x - 0.08, top], [x + 0.08, top], [x + 0.08, -0.2]]); });
        poly([[0.42, 0.1], [0.66, -0.12], [0.5, -0.3]]);
        poly([[-0.5, 0.85], [0.46, 0.85], [0.52, 0.1]]); add(0.0, 0.3, 1); break;
      }
      case 'cube': { // execution — a vault block
        const v = [[-.6, -.6, -.6], [.6, -.6, -.6], [.6, .6, -.6], [-.6, .6, -.6], [-.6, -.6, .6], [.6, -.6, .6], [.6, .6, .6], [-.6, .6, .6]];
        v.forEach(p => { const i = add(p[0], p[1], 0); nodes[i][3] = p[2]; });
        [[0, 1], [1, 2], [2, 3], [3, 0], [4, 5], [5, 6], [6, 7], [7, 4], [0, 4], [1, 5], [2, 6], [3, 7]].forEach(e => edges.push(e[0], e[1])); nodes[6][2] = 1; break;
      }
      case 'ledger': { // record — a signed document
        poly([[-0.8, -0.72], [0.55, -0.72], [0.8, -0.47], [0.8, 0.72], [-0.8, 0.72]], true);
        poly([[0.55, -0.72], [0.55, -0.47], [0.8, -0.47]]);
        [-0.3, -0.02, 0.26].forEach(y => seg(-0.6, y, 0.6, y));
        ring(0.4, 0.5, 0.16, 8); add(0.4, 0.5, 1); break;
      }
      case 'building': { // corporate treasury
        poly([[-0.85, -0.3], [0, -0.78], [0.85, -0.3]]);
        [-0.62, -0.3, 0.02, 0.34, 0.66].forEach(x => seg(x, -0.3, x, 0.55));
        seg(-0.85, -0.3, 0.85, -0.3); seg(-0.9, 0.55, 0.9, 0.55); add(0, -0.78, 1); break;
      }
      case 'shield': { // custody providers
        poly([[0, -0.85], [0.7, -0.5], [0.7, 0.1], [0, 0.85], [-0.7, 0.1], [-0.7, -0.5]], true);
        ring(0, -0.05, 0.16, 8); seg(0, -0.05, 0, 0.3); add(0, -0.05, 1); break;
      }
      case 'swap': { // exchanges
        poly(arc(0, 0, 0.62, Math.PI * 0.9, Math.PI * -0.35, 14));
        poly([[0.5, -0.5], [0.62, -0.22], [0.34, -0.3]]);
        poly(arc(0, 0, 0.62, Math.PI * 1.9, Math.PI * 0.65, 14));
        poly([[-0.5, 0.5], [-0.62, 0.22], [-0.34, 0.3]]); break;
      }
      case 'chart': { // funds and asset managers
        seg(-0.8, 0.6, 0.85, 0.6); seg(-0.8, 0.6, -0.8, -0.7);
        const h = [0.2, -0.05, -0.32, -0.62]; const xs = [-0.5, -0.12, 0.26, 0.64];
        poly(xs.map((x, i) => [x, h[i], 1])); break;
      }
      case 'key': { // post quantum cryptography
        ring(-0.4, 0, 0.3, 12); seg(-0.12, 0, 0.78, 0); seg(0.55, 0, 0.55, 0.26); seg(0.72, 0, 0.72, 0.22); add(-0.4, 0, 1); break;
      }
      case 'gate': { // policy enforcement
        seg(-0.45, -0.7, -0.45, 0.7); seg(0.45, -0.7, 0.45, 0.7);
        seg(-0.6, -0.7, 0.6, -0.7); add(-0.72, 0.1, 1); add(0.72, 0.1, 0); seg(-0.72, 0.1, -0.45, 0.1); seg(0.45, 0.1, 0.72, 0.1); break;
      }
      case 'scan': { // biometric authorisation (security)
        ring(0, 0, 0.3, 14); ring(0, 0, 0.6, 20);
        [[-0.9, 0], [0.9, 0], [0, -0.9], [0, 0.9]].forEach(p => seg(p[0] * 0.78, p[1] * 0.78, p[0], p[1]));
        ['tl', 'tr', 'br', 'bl'].forEach((c, i) => { const sx = i === 1 || i === 2 ? 1 : -1, sy = i >= 2 ? 1 : -1; poly([[sx * 0.9 - sx * 0.22, sy * 0.9], [sx * 0.9, sy * 0.9], [sx * 0.9, sy * 0.9 - sy * 0.22]]); });
        add(0, 0, 1); break;
      }
      case 'audit': { // independent verification (security) — a lens over a record
        ring(-0.1, -0.1, 0.42, 16); seg(0.2, 0.2, 0.68, 0.68);
        poly([[-0.28, -0.12], [-0.08, 0.1], [0.14, -0.26]]); add(-0.1, -0.1, 0); break;
      }
      default: { // mesh fallback
        const N = 26; for (let i = 0; i < N; i++) { const a = Math.random() * TAU, r = Math.sqrt(Math.random()) * 0.9; add(Math.cos(a) * r, Math.sin(a) * r, Math.random() < 0.2); }
        const seen = new Set();
        for (let i = 0; i < N; i++) { const d = []; for (let j = 0; j < N; j++) if (j !== i) d.push([Math.hypot(nodes[i][0] - nodes[j][0], nodes[i][1] - nodes[j][1]), j]); d.sort((a, b) => a[0] - b[0]); for (let k = 0; k < 2; k++) { const j = d[k][1], key = i < j ? i * 100 + j : j * 100 + i; if (!seen.has(key)) { seen.add(key); edges.push(i, j); } } }
      }
    }
    return { nodes, edges };
  }

  const items = [];
  document.querySelectorAll('canvas.qv-glx').forEach(c => {
    const ctx = c.getContext('2d'); if (!ctx) return;
    items.push({ c, ctx, mode: c.dataset.fx || 'mesh', light: c.hasAttribute('data-light'), g: geom(c.dataset.fx || 'mesh'), on: false, w: 1, h: 1, dpr: 1 });
  });

  function size(it) {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const r = it.c.getBoundingClientRect();
    const w = Math.max(1, Math.round(r.width * dpr)), h = Math.max(1, Math.round(r.height * dpr));
    if (it.c.width !== w || it.c.height !== h) { it.c.width = w; it.c.height = h; }
    it.w = w; it.h = h; it.dpr = dpr;
  }

  function project(it, n, t) {
    let x = n[0], y = n[1], z = n[3] || 0;
    if (it.mode === 'cube') { const a = t * 0.45, cr = Math.cos(a), sr = Math.sin(a); const nx = x * cr - z * sr, nz = x * sr + z * cr; const p = 1 / (2.5 - nz * 0.6); return [nx * p * 1.7, y * p * 1.7]; }
    if (it.mode === 'people' || it.mode === 'mesh') { x += Math.sin(t * 0.9 + n[1] * 5) * 0.035; y += Math.cos(t * 0.8 + n[0] * 5) * 0.035; }
    // figures in SPIN turn fully; every other figure gives a gentle sway so it is always alive
    const ang = SPIN[it.mode] != null ? t * SPIN[it.mode] : Math.sin(t * 0.7) * 0.05;
    const cr = Math.cos(ang), sr = Math.sin(ang);
    return [x * cr - y * sr, x * sr + y * cr];
  }

  function render(it, t) {
    const { ctx, w, h, dpr } = it;
    ctx.clearRect(0, 0, w, h);
    ctx.lineCap = 'round'; ctx.lineJoin = 'round';
    const S = Math.min(w, h) * 0.42, cx = w / 2, cy = h / 2;
    const pos = it.g.nodes.map(n => { const p = project(it, n, t); return [cx + p[0] * S, cy + p[1] * S]; });
    const col = it.light ? '21,94,239' : '255,255,255';
    const E = it.g.edges;
    ctx.lineWidth = Math.max(1, dpr);
    ctx.strokeStyle = 'rgba(' + col + ',' + (it.light ? 0.5 : 0.62) + ')';
    ctx.beginPath();
    for (let e = 0; e < E.length; e += 2) { const a = pos[E[e]], b = pos[E[e + 1]]; ctx.moveTo(a[0], a[1]); ctx.lineTo(b[0], b[1]); }
    ctx.stroke();
    for (let i = 0; i < pos.length; i++) {
      const p = pos[i], lit = it.g.nodes[i][2];
      ctx.fillStyle = 'rgba(' + col + ',' + (lit ? 0.95 : (it.light ? 0.7 : 0.78)) + ')';
      ctx.beginPath(); ctx.arc(p[0], p[1], (lit ? 2.3 : 1.4) * dpr, 0, TAU); ctx.fill();
    }
  }

  let raf = 0; const start = performance.now();
  function loop(now) { const t = reduce ? 1.4 : (now - start) / 1000; for (const it of items) if (it.on) render(it, t); if (!reduce) raf = requestAnimationFrame(loop); }
  if (items.length) {
    if ('IntersectionObserver' in window) {
      const io = new IntersectionObserver(es => es.forEach(e => { const it = items.find(x => x.c === e.target); if (it) { it.on = e.isIntersecting; if (it.on) size(it); } }), { rootMargin: '80px' });
      items.forEach(it => io.observe(it.c));
    } else items.forEach(it => { it.on = true; size(it); });
    window.addEventListener('resize', () => items.forEach(it => it.on && size(it)), { passive: true });
    document.addEventListener('visibilitychange', () => { if (document.hidden) cancelAnimationFrame(raf); else if (!reduce) raf = requestAnimationFrame(loop); });
    raf = requestAnimationFrame(loop);
  }
})();
