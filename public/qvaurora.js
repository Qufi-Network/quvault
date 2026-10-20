/*
 * qvaurora.js — a soft aurora of blue light drawn live in a fragment shader (no images). A handful
 * of gentle blobs drift behind the hero in the QuFi blue, pooling around the scan device on the
 * right and easing off behind the headline, so the scene reads as one lit surface. Transparent,
 * subtle, CSP-safe raw WebGL.
 */
function qvAurora(canvas) {
  let gl;
  try { gl = canvas.getContext('webgl', { antialias: true, alpha: true, premultipliedAlpha: false }); } catch (_) {}
  if (!gl) { canvas.style.display = 'none'; return; }

  const VS = 'attribute vec2 p; void main(){ gl_Position = vec4(p, 0.0, 1.0); }';
  const FS = [
    'precision highp float;',
    'uniform vec2 uRes; uniform float uT;',
    'float blob(vec2 p, vec2 c, float s){ float d = length((p - c) * vec2(1.0, 0.72)); return s / (d * d * 7.5 + s); }',
    'void main(){',
    '  vec2 uv = gl_FragCoord.xy / uRes;',
    '  float t = uT * 0.09;',
    '  float f = 0.0;',
    '  f += blob(uv, vec2(0.78 + 0.10 * sin(t),        0.40 + 0.12 * cos(t * 1.2)), 0.20);',
    '  f += blob(uv, vec2(0.62 + 0.13 * cos(t * 0.8),  0.62 + 0.10 * sin(t * 1.1)), 0.16);',
    '  f += blob(uv, vec2(0.92 + 0.08 * sin(t * 1.3),  0.60 + 0.10 * cos(t)),        0.15);',
    '  f += blob(uv, vec2(0.52 + 0.10 * sin(t * 0.6),  0.24 + 0.09 * cos(t * 0.9)), 0.12);',
    '  f += blob(uv, vec2(0.70 + 0.11 * cos(t * 1.5),  0.18 + 0.08 * sin(t * 1.3)), 0.11);',
    '  f = clamp(f, 0.0, 1.4);',
    '  vec3 deep = vec3(0.05, 0.22, 0.86); vec3 bright = vec3(0.30, 0.55, 1.0);',   // QuFi blue
    '  vec3 col = mix(deep, bright, clamp(f - 0.45, 0.0, 1.0));',
    '  float a = smoothstep(0.32, 1.0, f) * 0.5;',
    '  a *= 0.4 + 0.6 * smoothstep(0.0, 0.5, uv.x);',   // ease off behind the headline
    '  gl_FragColor = vec4(col, a);',
    '}',
  ].join('\n');

  function sh(t, s) { const x = gl.createShader(t); gl.shaderSource(x, s); gl.compileShader(x); return gl.getShaderParameter(x, gl.COMPILE_STATUS) ? x : null; }
  const vs = sh(gl.VERTEX_SHADER, VS), fs = sh(gl.FRAGMENT_SHADER, FS);
  if (!vs || !fs) { canvas.style.display = 'none'; return; }
  const prog = gl.createProgram(); gl.attachShader(prog, vs); gl.attachShader(prog, fs); gl.linkProgram(prog);
  if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) { canvas.style.display = 'none'; return; }

  const buf = gl.createBuffer(); gl.bindBuffer(gl.ARRAY_BUFFER, buf);
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
  const loc = gl.getAttribLocation(prog, 'p');
  const uRes = gl.getUniformLocation(prog, 'uRes'), uT = gl.getUniformLocation(prog, 'uT');
  gl.enable(gl.BLEND); gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA); gl.clearColor(0, 0, 0, 0);

  let W = 1, H = 1;
  function size() {
    const dpr = Math.min(window.devicePixelRatio || 1, 1.75);
    const w = Math.max(1, Math.round(canvas.clientWidth * dpr)), h = Math.max(1, Math.round(canvas.clientHeight * dpr));
    if (canvas.width !== w || canvas.height !== h) { canvas.width = w; canvas.height = h; gl.viewport(0, 0, w, h); }
    W = w; H = h;
  }
  function render(t) {
    gl.clear(gl.COLOR_BUFFER_BIT); gl.useProgram(prog);
    gl.uniform2f(uRes, W, H); gl.uniform1f(uT, t);
    gl.enableVertexAttribArray(loc); gl.bindBuffer(gl.ARRAY_BUFFER, buf); gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
    gl.drawArrays(gl.TRIANGLES, 0, 3);
  }
  const reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const start = performance.now(); let raf = 0;
  function loop(now) { size(); render(reduce ? 4 : (now - start) / 1000); if (!reduce) raf = requestAnimationFrame(loop); }
  requestAnimationFrame(loop);
  if (window.ResizeObserver) new ResizeObserver(() => { size(); render(reduce ? 4 : (performance.now() - start) / 1000); }).observe(canvas);
  document.addEventListener('visibilitychange', () => { if (document.hidden) cancelAnimationFrame(raf); else if (!reduce) raf = requestAnimationFrame(loop); });
}
document.querySelectorAll('canvas.qv-aurora').forEach(c => { try { if (c.getContext('webgl')) qvAurora(c); } catch (_) {} });
