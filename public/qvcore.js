/*
 * qvcore.js — a quantum verification core, drawn live in WebGL (no images). A lattice of nodes on
 * a slowly turning sphere, laced with its nearest links, around a bright pulsing centre. Blue on a
 * transparent canvas, so it integrates on light panels and glows on dark ones. Pure decoration: it
 * draws only points and lines, so it stays cheap, and the section reads with the canvas gone.
 *
 * CSP-safe: raw WebGL, same-origin, no libraries.
 */
function qvCore(canvas) {
  let gl;
  try { gl = canvas.getContext('webgl', { antialias: true, alpha: true, premultipliedAlpha: false }); } catch (_) {}
  if (!gl) { canvas.style.display = 'none'; return; }

  function sh(t, s) { const x = gl.createShader(t); gl.shaderSource(x, s); gl.compileShader(x); return gl.getShaderParameter(x, gl.COMPILE_STATUS) ? x : null; }
  function prog(v, f) { const vs = sh(gl.VERTEX_SHADER, v), fs = sh(gl.FRAGMENT_SHADER, f); if (!vs || !fs) return null; const p = gl.createProgram(); gl.attachShader(p, vs); gl.attachShader(p, fs); gl.linkProgram(p); return gl.getProgramParameter(p, gl.LINK_STATUS) ? p : null; }

  const lineP = prog('attribute vec2 aPos; attribute float aA; varying float vA; void main(){ gl_Position=vec4(aPos,0.,1.); vA=aA; }',
                     'precision mediump float; varying float vA; uniform vec3 uCol; void main(){ gl_FragColor=vec4(uCol, vA); }');
  const dotP = prog('attribute vec2 aPos; attribute float aS; attribute float aA; varying float vA; void main(){ gl_Position=vec4(aPos,0.,1.); gl_PointSize=aS; vA=aA; }',
                    'precision mediump float; varying float vA; uniform vec3 uCol; void main(){ float r=length(gl_PointCoord-0.5)*2.0; float a=smoothstep(1.0,0.2,r)*vA; if(a<0.01) discard; gl_FragColor=vec4(uCol,a); }');
  if (!lineP || !dotP) { canvas.style.display = 'none'; return; }

  const BLUE = [0.10, 0.39, 0.96], CYAN = [0.17, 0.66, 0.95];

  // ---- a Fibonacci sphere of nodes
  const N = 150, pts = [];
  const GA = Math.PI * (3 - Math.sqrt(5));
  for (let i = 0; i < N; i++) {
    const y = 1 - (i / (N - 1)) * 2;
    const r = Math.sqrt(Math.max(0, 1 - y * y));
    const th = GA * i;
    pts.push([Math.cos(th) * r, y, Math.sin(th) * r]);
  }
  // ---- links: each node to its three nearest, de-duplicated
  const edges = [], seen = new Set();
  for (let i = 0; i < N; i++) {
    const d = [];
    for (let j = 0; j < N; j++) if (j !== i) { const dx = pts[i][0] - pts[j][0], dy = pts[i][1] - pts[j][1], dz = pts[i][2] - pts[j][2]; d.push([dx * dx + dy * dy + dz * dz, j]); }
    d.sort((a, b) => a[0] - b[0]);
    for (let k = 0; k < 3; k++) { const j = d[k][1]; const key = i < j ? i * 1000 + j : j * 1000 + i; if (!seen.has(key)) { seen.add(key); edges.push(i, j); } }
  }

  const lineBuf = gl.createBuffer(), dotBuf = gl.createBuffer();
  const lineData = new Float32Array(edges.length * 3);
  const dotData = new Float32Array(N * 4);
  gl.enable(gl.BLEND); gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA); gl.clearColor(0, 0, 0, 0);

  let dpr = 1, asp = 1;
  function size() {
    dpr = Math.min(window.devicePixelRatio || 1, 1.6);
    const w = Math.max(1, Math.round(canvas.clientWidth * dpr)), h = Math.max(1, Math.round(canvas.clientHeight * dpr));
    if (canvas.width !== w || canvas.height !== h) { canvas.width = w; canvas.height = h; gl.viewport(0, 0, w, h); }
    asp = w / h;
  }
  let mx = 0, my = 0;
  window.addEventListener('pointermove', e => { mx = (e.clientX / window.innerWidth - 0.5); my = (e.clientY / window.innerHeight - 0.5); }, { passive: true });

  const R = 0.86;
  const proj = new Array(N);
  function project(p, ry, rx) {
    let x = p[0], y = p[1], z = p[2];
    const cy = Math.cos(ry), sy = Math.sin(ry); const x1 = x * cy - z * sy, z1 = x * sy + z * cy;
    const cx = Math.cos(rx), sx = Math.sin(rx); const y1 = y * cx - z1 * sx, z2 = y * sx + z1 * cx;
    const persp = 1 / (2.5 - z2 * 0.6);
    return [x1 * R * persp / asp, y1 * R * persp, z2, persp];
  }

  function drawLines(data, n, col) {
    gl.useProgram(lineP); gl.uniform3fv(gl.getUniformLocation(lineP, 'uCol'), col);
    gl.bindBuffer(gl.ARRAY_BUFFER, lineBuf); gl.bufferData(gl.ARRAY_BUFFER, data, gl.DYNAMIC_DRAW);
    const lp = gl.getAttribLocation(lineP, 'aPos'), la = gl.getAttribLocation(lineP, 'aA');
    gl.enableVertexAttribArray(lp); gl.enableVertexAttribArray(la);
    gl.vertexAttribPointer(lp, 2, gl.FLOAT, false, 12, 0); gl.vertexAttribPointer(la, 1, gl.FLOAT, false, 12, 8);
    gl.drawArrays(gl.LINES, 0, n);
  }

  function render(t) {
    gl.clear(gl.COLOR_BUFFER_BIT);
    const ry = t * 0.18 + mx * 0.7, rx = 0.26 + my * 0.45;
    const pulse = 0.5 + 0.5 * Math.sin(t * 2.0);
    for (let i = 0; i < N; i++) proj[i] = project(pts[i], ry, rx);

    // links — nearer the front, brighter
    for (let e = 0, o = 0; e < edges.length; e += 2) {
      const a = proj[edges[e]], b = proj[edges[e + 1]];
      const depth = ((a[2] + b[2]) * 0.5 + 1) * 0.5;      // 0 back .. 1 front
      const al = 0.04 + 0.30 * depth * depth;
      lineData[o++] = a[0]; lineData[o++] = a[1]; lineData[o++] = al;
      lineData[o++] = b[0]; lineData[o++] = b[1]; lineData[o++] = al;
    }
    drawLines(lineData, edges.length, BLUE);

    // nodes — size and alpha by depth, with a travelling shimmer
    for (let i = 0; i < N; i++) {
      const p = proj[i]; const depth = (p[2] + 1) * 0.5;
      const lit = 0.35 + 0.65 * depth;
      const sh2 = 0.6 + 0.4 * Math.sin(t * 1.6 + i * 0.5);
      dotData[i * 4] = p[0]; dotData[i * 4 + 1] = p[1];
      dotData[i * 4 + 2] = (1.4 + depth * 5.0) * dpr;
      dotData[i * 4 + 3] = lit * (0.5 + 0.5 * sh2);
    }
    gl.useProgram(dotP); gl.uniform3fv(gl.getUniformLocation(dotP, 'uCol'), BLUE);
    gl.bindBuffer(gl.ARRAY_BUFFER, dotBuf); gl.bufferData(gl.ARRAY_BUFFER, dotData, gl.DYNAMIC_DRAW);
    const dp = gl.getAttribLocation(dotP, 'aPos'), ds = gl.getAttribLocation(dotP, 'aS'), da = gl.getAttribLocation(dotP, 'aA');
    gl.enableVertexAttribArray(dp); gl.enableVertexAttribArray(ds); gl.enableVertexAttribArray(da);
    gl.vertexAttribPointer(dp, 2, gl.FLOAT, false, 16, 0); gl.vertexAttribPointer(ds, 1, gl.FLOAT, false, 16, 8); gl.vertexAttribPointer(da, 1, gl.FLOAT, false, 16, 12);
    gl.drawArrays(gl.POINTS, 0, N);

    // bright pulsing core at the centre
    const core = new Float32Array([0, 0, (16 + pulse * 10) * dpr, 0.5 + 0.4 * pulse]);
    gl.bindBuffer(gl.ARRAY_BUFFER, dotBuf); gl.bufferData(gl.ARRAY_BUFFER, core, gl.DYNAMIC_DRAW);
    gl.uniform3fv(gl.getUniformLocation(dotP, 'uCol'), CYAN);
    gl.enableVertexAttribArray(dp); gl.enableVertexAttribArray(ds); gl.enableVertexAttribArray(da);
    gl.vertexAttribPointer(dp, 2, gl.FLOAT, false, 16, 0); gl.vertexAttribPointer(ds, 1, gl.FLOAT, false, 16, 8); gl.vertexAttribPointer(da, 1, gl.FLOAT, false, 16, 12);
    gl.drawArrays(gl.POINTS, 0, 1);
  }

  const reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const start = performance.now();
  let raf = 0;
  function loop(now) { size(); render(reduce ? 2.2 : (now - start) / 1000); if (!reduce) raf = requestAnimationFrame(loop); }
  requestAnimationFrame(loop);
  if (window.ResizeObserver) new ResizeObserver(() => { size(); render(reduce ? 2.2 : (performance.now() - start) / 1000); }).observe(canvas);
  document.addEventListener('visibilitychange', () => { if (document.hidden) cancelAnimationFrame(raf); else if (!reduce) raf = requestAnimationFrame(loop); });
}

document.querySelectorAll('canvas.qv-gl').forEach(c => { try { if (c.getContext('webgl')) qvCore(c); } catch (_) {} });
