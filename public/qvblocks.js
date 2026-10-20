/*
 * qvblocks.js — a dark 3D block field receding to the horizon, drawn live on a 2D canvas (no
 * images, no extra WebGL context). A perspective grid of tiles, some raised into blocks, scrolls
 * slowly toward the viewer and fades into the deep-blue band behind it — the "flythrough" backdrop
 * for the closing call to action. Pure decoration, CSP-safe.
 */
function qvBlocks(canvas) {
  const ctx = canvas.getContext('2d'); if (!ctx) { canvas.style.display = 'none'; return; }
  const reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  let w = 1, h = 1, dpr = 1;
  function size() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    const r = canvas.getBoundingClientRect();
    w = Math.max(1, Math.round(r.width * dpr)); h = Math.max(1, Math.round(r.height * dpr));
    if (canvas.width !== w || canvas.height !== h) { canvas.width = w; canvas.height = h; }
  }
  const T = 1, COLS = 11, ROWS = 20, NEAR = 1.25, CH = 1.25;
  const rnd = i => { const x = Math.sin(i * 127.1) * 43758.5; return x - Math.floor(x); };
  let mx = 0, my = 0, tmx = 0, tmy = 0;
  window.addEventListener('pointermove', e => { tmx = e.clientX / window.innerWidth - 0.5; tmy = e.clientY / window.innerHeight - 0.5; }, { passive: true });

  function render(t) {
    size();
    mx += (tmx - mx) * 0.06; my += (tmy - my) * 0.06;   // eased mouse parallax
    ctx.clearRect(0, 0, w, h);
    const F = h * 1.15, horizon = h * 0.26 + my * h * 0.05, cx = w * 0.5 + mx * w * 0.14;
    const hg = ctx.createRadialGradient(cx, horizon, 0, cx, horizon, Math.max(w, h) * 0.6);
    hg.addColorStop(0, 'rgba(60,120,230,0.3)'); hg.addColorStop(1, 'rgba(60,120,230,0)');
    ctx.fillStyle = hg; ctx.fillRect(0, 0, w, h);
    const scrollTotal = t * 0.32, scroll = scrollTotal % T, base = Math.floor(scrollTotal / T);
    const proj = (x, d, hh) => [cx + F * x / d, horizon + F * (CH - hh) / d];
    const span = ROWS * T, ss = (lo, hi, x) => { const u = Math.max(0, Math.min(1, (x - lo) / (hi - lo))); return u * u * (3 - 2 * u); };
    for (let rz = ROWS; rz >= 0; rz--) {
      const d0 = NEAR + rz * T - scroll, d1 = d0 + T;
      if (d0 < 0.2) continue;
      const fog = Math.max(0, Math.min(1, 1 - (d0 - NEAR) / span)) * ss(0.3, 0.95, d0);
      if (fog <= 0.02) continue;
      for (let c = -COLS; c < COLS; c++) {
        const x0 = c * T, x1 = x0 + T, id = (rz + base) * 131 + (c + COLS) * 17;
        const raised = rnd(id) < 0.3, hh = raised ? 0.32 + rnd(id + 9) * 0.6 : 0, g = 0.09;
        const a = proj(x0 + g, d0 + g, hh), b = proj(x1 - g, d0 + g, hh), bb = proj(x1 - g, d1 - g, hh), aa = proj(x0 + g, d1 - g, hh);
        if (raised) {
          const af = proj(x0 + g, d0 + g, 0), bf = proj(x1 - g, d0 + g, 0);
          ctx.fillStyle = 'rgba(7,18,44,' + (0.78 * fog) + ')';
          ctx.beginPath(); ctx.moveTo(a[0], a[1]); ctx.lineTo(b[0], b[1]); ctx.lineTo(bf[0], bf[1]); ctx.lineTo(af[0], af[1]); ctx.closePath(); ctx.fill();
        }
        ctx.fillStyle = raised ? 'rgba(48,108,205,' + (0.36 * fog) + ')' : 'rgba(26,58,116,' + (0.14 * fog) + ')';
        ctx.strokeStyle = 'rgba(96,158,245,' + (0.28 * fog) + ')';
        ctx.lineWidth = dpr;
        ctx.beginPath(); ctx.moveTo(a[0], a[1]); ctx.lineTo(b[0], b[1]); ctx.lineTo(bb[0], bb[1]); ctx.lineTo(aa[0], aa[1]); ctx.closePath(); ctx.fill(); ctx.stroke();
      }
    }
  }

  const start = performance.now(); let raf = 0, on = true;
  function loop(now) { if (on) render(reduce ? 2 : (now - start) / 1000); if (!reduce) raf = requestAnimationFrame(loop); }
  if ('IntersectionObserver' in window) new IntersectionObserver(es => es.forEach(e => { on = e.isIntersecting; })).observe(canvas);
  if (window.ResizeObserver) new ResizeObserver(() => render(reduce ? 2 : (performance.now() - start) / 1000)).observe(canvas);
  document.addEventListener('visibilitychange', () => { if (document.hidden) cancelAnimationFrame(raf); else if (!reduce) raf = requestAnimationFrame(loop); });
  raf = requestAnimationFrame(loop);
}
document.querySelectorAll('canvas.qv-blocks').forEach(c => { try { qvBlocks(c); } catch (_) {} });
