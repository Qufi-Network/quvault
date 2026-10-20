/*
 * qvsplash.js — a watercolour that blooms under the pointer with the smudge of a fingerprint inside.
 * As the mouse moves it lays down a soft blue pool and, barely-there within it, the broken ridges of
 * a pressed finger — like a smear of ink rather than a clean print — which then fade. The ridge shape
 * is fixed per stamp (no shimmer); everything is very low contrast. 2D canvas, transparent, calm when
 * the pointer is away. Pure decoration, CSP-safe.
 */
function qvSplash(canvas) {
  const ctx = canvas.getContext('2d'); if (!ctx) { canvas.style.display = 'none'; return; }
  const reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const TAU = Math.PI * 2;
  const host = canvas.parentElement;
  let w = 1, h = 1, dpr = 1;
  function size() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    const r = canvas.getBoundingClientRect();
    w = Math.max(1, Math.round(r.width * dpr)); h = Math.max(1, Math.round(r.height * dpr));
    if (canvas.width !== w || canvas.height !== h) { canvas.width = w; canvas.height = h; }
  }
  const prints = []; let px = 0, py = 0, has = false, last = 0;
  host.addEventListener('pointermove', e => { const r = host.getBoundingClientRect(); px = e.clientX - r.left; py = e.clientY - r.top; has = true; }, { passive: true });
  host.addEventListener('pointerleave', () => { has = false; }, { passive: true });

  function make() {
    const rings = [];
    for (let k = 0; k < 8; k++) rings.push({
      r: 6 + k * 4.4, a0: 0.12 + (Math.random() - .5) * 0.12, a1: 1.88 + (Math.random() - .5) * 0.12,
      aw: 0.11 + Math.random() * 0.07, lw: 0.8 + Math.random() * 0.6, yo: k * 0.5,
    });
    return { x: px * dpr, y: py * dpr, rot: (Math.random() - .5) * 0.7, scale: 0.9 + Math.random() * 0.4, life: 1, rings };
  }

  function stamp(s) {
    const al = s.life, sc = s.scale * dpr;
    ctx.save(); ctx.translate(s.x, s.y); ctx.rotate(s.rot);
    // ink bleeding into paper
    const br = 54 * sc, g = ctx.createRadialGradient(0, 0, 0, 0, 0, br);
    g.addColorStop(0, 'rgba(32,86,210,' + (0.10 * al) + ')'); g.addColorStop(0.58, 'rgba(40,96,220,' + (0.045 * al) + ')'); g.addColorStop(1, 'rgba(40,96,220,0)');
    ctx.fillStyle = g; ctx.beginPath(); ctx.arc(0, 0, br, 0, TAU); ctx.fill();
    // broken fingerprint ridges, inked
    ctx.lineCap = 'round';
    for (const rg of s.rings) {
      const r = rg.r * sc;
      ctx.strokeStyle = 'rgba(16,58,180,' + (rg.aw * al) + ')'; ctx.lineWidth = rg.lw * dpr;
      ctx.beginPath(); ctx.ellipse(0, rg.yo * sc, r * 0.82, r, 0, Math.PI * rg.a0, Math.PI * rg.a1); ctx.stroke();
    }
    // a denser ink pool where the finger pressed, blurring the ridges into a smear
    const sg = ctx.createRadialGradient(0, 2 * sc, 0, 0, 2 * sc, 26 * sc);
    sg.addColorStop(0, 'rgba(22,66,190,' + (0.09 * al) + ')'); sg.addColorStop(1, 'rgba(22,66,190,0)');
    ctx.fillStyle = sg; ctx.beginPath(); ctx.arc(0, 2 * sc, 26 * sc, 0, TAU); ctx.fill();
    ctx.restore();
  }

  function render(now) {
    size(); ctx.clearRect(0, 0, w, h);
    if (!reduce && has && now - last > 72) { last = now; prints.push(make()); if (prints.length > 16) prints.shift(); }
    for (const s of prints) { s.life -= 0.008; if (s.life > 0) stamp(s); }
    for (let i = prints.length - 1; i >= 0; i--) if (prints[i].life <= 0) prints.splice(i, 1);
    raf = requestAnimationFrame(render);
  }
  let raf = requestAnimationFrame(render);
  document.addEventListener('visibilitychange', () => { if (document.hidden) cancelAnimationFrame(raf); else raf = requestAnimationFrame(render); });
}
document.querySelectorAll('canvas.qv-splash').forEach(c => { try { qvSplash(c); } catch (_) {} });
