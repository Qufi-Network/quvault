/*
 * qvfx.js — the live graphics layer. Two jobs:
 *
 *  1. Every icon tile gets an animated node-field behind its mark: a little constellation of
 *     glowing particles that drift, link to their neighbours and pulse. White on the blue strip,
 *     blue on the light cards. It is additive 2D canvas (no WebGL-context limit), one shared
 *     animation loop, and only the tiles on screen are drawn — so twenty of them stay cheap.
 *
 *  2. Elements marked [data-reveal-up] rise into place the first time they enter the viewport.
 *     The rest state is visible, so nothing is ever gated behind the animation.
 *
 * Pure decoration, same-origin, CSP-safe.
 */
(() => {
  const reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // ---------------------------------------------------------------- icon node-fields
  const tiles = document.querySelectorAll('.qv-cap-ico, .qv-use-ico, .qv-sec-ico, .qv-step-ico');
  const sys = [];
  tiles.forEach(tile => {
    const c = document.createElement('canvas');
    c.className = 'qv-fx';
    c.setAttribute('aria-hidden', 'true');
    tile.insertBefore(c, tile.firstChild);
    const parts = [];
    const N = tile.classList.contains('qv-step-ico') ? 5 : 7;
    for (let i = 0; i < N; i++) parts.push({ x: Math.random(), y: Math.random(), vx: (Math.random() - .5) * .07, vy: (Math.random() - .5) * .07, r: .6 + Math.random() * .7 });
    const white = tile.classList.contains('qv-cap-ico');
    sys.push({ tile, c, ctx: c.getContext('2d'), parts, on: false, w: 1, h: 1, dpr: 1, col: white ? '255,255,255' : '42,120,246' });
  });

  function size(s) {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const r = s.tile.getBoundingClientRect();
    const w = Math.max(1, Math.round(r.width * dpr)), h = Math.max(1, Math.round(r.height * dpr));
    if (s.c.width !== w || s.c.height !== h) { s.c.width = w; s.c.height = h; }
    s.w = w; s.h = h; s.dpr = dpr;
  }

  let prev = performance.now();
  function frame(now) {
    const dt = Math.min(48, now - prev) / 1000; prev = now;
    const pulse = .6 + .4 * Math.sin(now / 620);
    for (const s of sys) {
      if (!s.on) continue;
      const { ctx, w, h, parts, col } = s;
      ctx.clearRect(0, 0, w, h);
      ctx.globalCompositeOperation = 'lighter';
      for (const p of parts) {
        p.x += p.vx * dt; p.y += p.vy * dt;
        if (p.x < .04 || p.x > .96) p.vx *= -1;
        if (p.y < .04 || p.y > .96) p.vy *= -1;
        p.x = Math.max(.04, Math.min(.96, p.x)); p.y = Math.max(.04, Math.min(.96, p.y));
      }
      const maxd = w * .55;
      for (let i = 0; i < parts.length; i++) for (let j = i + 1; j < parts.length; j++) {
        const a = parts[i], b = parts[j], dx = (a.x - b.x) * w, dy = (a.y - b.y) * h, d = Math.hypot(dx, dy);
        if (d < maxd) { ctx.strokeStyle = 'rgba(' + col + ',' + (.22 * (1 - d / maxd)) + ')'; ctx.lineWidth = s.dpr; ctx.beginPath(); ctx.moveTo(a.x * w, a.y * h); ctx.lineTo(b.x * w, b.y * h); ctx.stroke(); }
      }
      for (const p of parts) {
        const rad = p.r * s.dpr * 5, g = ctx.createRadialGradient(p.x * w, p.y * h, 0, p.x * w, p.y * h, rad);
        g.addColorStop(0, 'rgba(' + col + ',' + (.5 * pulse) + ')'); g.addColorStop(1, 'rgba(' + col + ',0)');
        ctx.fillStyle = g; ctx.beginPath(); ctx.arc(p.x * w, p.y * h, rad, 0, 6.283); ctx.fill();
      }
      ctx.globalCompositeOperation = 'source-over';
    }
    raf = requestAnimationFrame(frame);
  }
  let raf = 0;

  if (!reduce && sys.length) {
    if ('IntersectionObserver' in window) {
      const io = new IntersectionObserver(es => es.forEach(e => {
        const s = sys.find(x => x.tile === e.target); if (!s) return;
        s.on = e.isIntersecting; if (s.on) size(s);
      }), { rootMargin: '60px' });
      sys.forEach(s => io.observe(s.tile));
    } else { sys.forEach(s => { s.on = true; size(s); }); }
    window.addEventListener('resize', () => sys.forEach(s => s.on && size(s)), { passive: true });
    document.addEventListener('visibilitychange', () => { if (document.hidden) cancelAnimationFrame(raf); else raf = requestAnimationFrame(frame); });
    raf = requestAnimationFrame(frame);
  }

  // ---------------------------------------------------------------- reveal on scroll
  const ups = document.querySelectorAll('[data-reveal-up]');
  if ('IntersectionObserver' in window && !reduce) {
    const io2 = new IntersectionObserver(es => es.forEach(e => { if (e.isIntersecting) { e.target.classList.add('in'); io2.unobserve(e.target); } }), { rootMargin: '0px 0px -12% 0px' });
    ups.forEach(el => io2.observe(el));
  } else { ups.forEach(el => el.classList.add('in')); }
})();
