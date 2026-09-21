/*
 * Veyns — the motion the marketing site runs on.
 *
 * This file is deliberately separate from app.js: nothing here can sign anybody in, and the
 * vault application does not depend on any of it. If this script never loads, the page is
 * still complete and still readable — every effect below starts from a state that is already
 * correct and only ever makes it richer.
 *
 * One scroll listener drives every scroll-linked effect through a single animation frame,
 * rather than each section installing a listener of its own.
 *
 * On inline styles: this origin sends script-src 'self' and style-src 'self', which refuses
 * a style="" attribute in markup but does not touch the CSSOM. Setting a custom property from
 * script is therefore allowed, and that is how scroll position reaches the stylesheet here.
 */

/*
 * First statement, before anything else can throw: tell the document that motion is running.
 *
 * Every rule that starts content at zero opacity is gated on this class, so until it is set
 * the whole site is simply visible. That ordering is the point. If this file fails to load, is
 * served stale from a cache, or throws on a line further down, the reader still gets the words
 * — they just do not animate. It was the other way round, and a script that never arrived took
 * every word on the site with it.
 */
document.documentElement.classList.add('vx-motion');

const $ = id => document.getElementById(id);
const clamp = (v, lo = 0, hi = 1) => (v < lo ? lo : v > hi ? hi : v);
const still = window.matchMedia('(prefers-reduced-motion: reduce)');

/*
 * The marketing surface is three pages sharing one document and one bar. All three are the
 * same light enterprise page: one dark hero, a white body, contained dark panels where
 * something is genuinely a system. All are hidden until the application decides which to put
 * up, so nothing here can be measured before that happens.
 */
const PAGES = ['view-signin', 'view-about', 'view-technology'].map($).filter(Boolean);
const showing = () => PAGES.find(page => !page.hidden) || null;

/* ------------------------------------------------------- scroll driver */

const drivers = [];
let queued = false;

/**
 * How far the page has travelled through an element, as 0 to 1.
 * 0 is the moment its top passes `start` down the viewport; 1 is when its bottom passes `end`.
 */
function travel(el, start = 0.86, end = 0.3) {
  const box = el.getBoundingClientRect();
  const span = box.height + window.innerHeight * (start - end);
  if (span <= 0) return 0;
  return clamp((window.innerHeight * start - box.top) / span);
}

const drive = (el, run, start, end) => { if (el) drivers.push({ el, run, start, end }); };

function frame() {
  queued = false;
  for (const { el, run, start, end } of drivers) run(travel(el, start, end), el);
}

function onScroll() {
  if (queued) return;
  queued = true;
  requestAnimationFrame(frame);
}

/* --------------------------------------------------------- line icons */

/*
 * Every icon draws itself rather than appearing. The dash length has to match the path it is
 * drawn on or the stroke either snaps in or never finishes, so it is measured here and handed
 * to the stylesheet; the timing and the trigger stay in CSS.
 */
function measureIcons() {
  for (const shape of document.querySelectorAll('.en-ico svg > *')) {
    const length = typeof shape.getTotalLength === 'function' ? shape.getTotalLength() : 0;
    if (length) shape.style.setProperty('--vx-len', Math.ceil(length));
  }
}
measureIcons();

/* ----------------------------------------------------------- arrival */

/*
 * Things arrive as they are reached. This only ever adds a class — the distance, the timing
 * and the stagger all live in the stylesheet.
 *
 * The rule that matters: content must never be left invisible by an effect. If no arrival has
 * been reported shortly after the page is up — a throttled tab, a browser that never fires the
 * observer, a frameless environment — the whole thing gives up and simply shows everything.
 */
function watchArrivals() {
  const targets = [...document.querySelectorAll('[data-reveal]:not(.in), [data-reveal-group]:not(.in)')];
  if (!targets.length) return;

  if (still.matches || !('IntersectionObserver' in window)) {
    for (const el of targets) el.classList.add('in');
    return;
  }

  /* Snapping rather than transitioning: without frames a transition never leaves its start. */
  const showAll = () => {
    document.documentElement.classList.add('reveal-off');
    for (const el of targets) el.classList.add('in');
  };

  /*
   * Scoped to the targets this call was handed, not to the document. Asking the document
   * whether anything anywhere had arrived meant that once the first page had shown itself,
   * every page opened after it lost its safety net.
   */
  const failsafe = setTimeout(() => {
    if (!targets.some(el => el.classList.contains('in'))) showAll();
  }, 1400);

  const seen = new IntersectionObserver((entries, observer) => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      clearTimeout(failsafe);
      entry.target.classList.add('in');
      observer.unobserve(entry.target); // it arrives once; it does not keep arriving
    }
  }, { rootMargin: '0px 0px -10% 0px', threshold: 0.1 });

  for (const el of targets) seen.observe(el);
}

/* ------------------------------------------------------------ the bar */

{
  const nav = $('marketing-top');
  if (nav) {
    /*
     * Every page opens on a dark hero, so the bar is transparent until the page moves and then
     * earns a ground of its own. The moment the page moves, not the moment the hero leaves:
     * the bar overlaps whatever runs beneath it the whole way down.
     *
     * Which ground depends on the page. The home page stays dark to the bottom; the enterprise
     * pages turn white below their hero, and the bar has to turn with them.
     *
     * This is deliberately NOT driven by the scroll handler. That handler runs inside an
     * animation frame, and somewhere frames are not delivered the bar would keep its
     * transparent state for the whole page — which on a white page means white type on white.
     * An observer reports whether a sentinel at the top of the page is still on screen, and
     * observers are not frame driven, so the bar stays legible even where nothing animates.
     */
    const paintLight = () => {
      const page = showing();
      nav.classList.toggle('light', !!page && page.classList.contains('en'));
    };

    const sentinels = PAGES.map(page => {
      const mark = document.createElement('span');
      mark.className = 'vx-nav-sentinel';
      mark.setAttribute('aria-hidden', 'true');
      page.prepend(mark);
      return mark;
    });

    if ('IntersectionObserver' in window && sentinels.length) {
      const watch = new IntersectionObserver(entries => {
        for (const entry of entries) {
          /* Only the sentinel of the page actually on show has anything to say. */
          if (entry.target.parentElement?.hidden) continue;
          paintLight();
          nav.classList.toggle('stuck', !entry.isIntersecting);
        }
      }, { threshold: 0 });
      for (const mark of sentinels) watch.observe(mark);
    }

    /* The scroll driver agrees with it, and covers the moment a page is first shown. */
    drive(nav, () => {
      paintLight();
      nav.classList.toggle('stuck', window.scrollY > 28);
    });
  }
}

/* ------------------------------------------------------- same-page links */

/*
 * Anchors that point at a section of this page are taken here rather than left to the
 * browser. Two reasons: the bar is sticky, so a plain jump parks the heading underneath it —
 * scroll-margin-top in the stylesheet answers that — and the movement should be smooth.
 *
 * Anything that is not a section of the page showing is left completely alone, so the link
 * that leads to the About page still leads to the About page.
 */
document.addEventListener('click', event => {
  const link = event.target.closest('a[href^="#"]');
  if (!link || event.metaKey || event.ctrlKey || event.shiftKey || event.button) return;

  const id = link.getAttribute('href').slice(1);
  const page = showing();
  if (!id || !page) return;

  const target = document.getElementById(id);
  if (!target || !page.contains(target)) return;

  event.preventDefault();
  history.replaceState(null, '', `#${id}`);

  if (still.matches) { target.scrollIntoView(); return; }

  const from = window.scrollY;
  target.scrollIntoView({ behavior: 'smooth', block: 'start' });
  /*
   * Smooth scrolling is driven by animation frames. Somewhere that delivers none — a
   * throttled tab, an embedded view, a browser that has decided to stop painting — it does
   * nothing at all and reports no error, and the link simply appears broken. So arrival is
   * checked, and if it never started, it is made to happen the blunt way.
   */
  setTimeout(() => {
    if (Math.abs(window.scrollY - from) < 4) target.scrollIntoView();
  }, 700);
});

/* ====================================================== the homepage */

{
  const hero = document.querySelector('.home-hero');
  const scene = $('home-scene');

  if (hero && scene && !still.matches) {
    /* The scene answers the pointer by a few pixels. Anything more reads as a gimmick. */
    let pending = false;
    hero.addEventListener('pointermove', event => {
      if (pending) return;
      pending = true;
      requestAnimationFrame(() => {
        pending = false;
        const box = hero.getBoundingClientRect();
        scene.style.setProperty('--en-px', ((event.clientX - box.left) / box.width - 0.5).toFixed(3));
        scene.style.setProperty('--en-py', ((event.clientY - box.top) / box.height - 0.5).toFixed(3));
      });
    });
    hero.addEventListener('pointerleave', () => {
      scene.style.setProperty('--en-px', 0);
      scene.style.setProperty('--en-py', 0);
    });

    /* Leaving the hero, the scene settles back rather than scrolling away flat. */
    drive(hero, progress => {
      scene.style.setProperty('--home-scale', (1 - progress * 0.06).toFixed(4));
    }, 1, 0);
  }

  /* An ambient drift of light over the scene, and only while the hero is on screen. */
  liveCanvas($('home-dust'), (paint, w, h) => {
    const motes = [];
    const count = Math.round(clamp((w * h) / 26000, 18, 54));
    for (let i = 0; i < count; i++) {
      motes.push({
        x: Math.random() * w, y: Math.random() * h,
        r: 0.5 + Math.random() * 1.2,
        drift: 0.06 + Math.random() * 0.22,
        sway: Math.random() * Math.PI * 2,
        alpha: 0.12 + Math.random() * 0.3,
      });
    }
    return () => {
      paint.clearRect(0, 0, w, h);
      for (const m of motes) {
        m.y -= m.drift;
        m.sway += 0.006;
        if (m.y < -4) { m.y = h + 4; m.x = Math.random() * w; }
        paint.beginPath();
        paint.arc(m.x + Math.sin(m.sway) * 6, m.y, m.r, 0, Math.PI * 2);
        paint.fillStyle = `rgba(120, 180, 255, ${m.alpha})`;
        paint.fill();
      }
    };
  });
}

/* --------------------------------------------- the five that must agree */

{
  const chain = $('home-chain');
  const links = chain ? [...chain.children] : [];
  if (chain && links.length) {
    drive(chain, progress => {
      const run = clamp(progress / 0.82);
      chain.style.setProperty('--home-chain', run.toFixed(3));
      const reached = Math.round(run * links.length);
      links.forEach((link, i) => link.classList.toggle('on', i < reached));
    }, 0.86, 0.5);
  }
}

/* ------------------------------------------------ the seven layers */

{
  const list = $('home-layers');
  const layers = list ? [...list.children] : [];
  if (list && layers.length) {
    drive(list, progress => {
      const reached = Math.round(clamp(progress / 0.84) * layers.length);
      layers.forEach((layer, i) => layer.classList.toggle('on', i < reached));
    }, 0.86, 0.5);
  }
}

/* -------------------------------------- the transaction, control by control */

{
  const panel = $('home-txn');
  const steps = $('home-steps');
  const verdict = $('home-verdict');
  const text = $('home-verdict-text');
  if (panel && steps && verdict && text) {
    const rows = [...steps.children];
    drive(panel, progress => {
      /* The last fifth is left for the verdict, so it does not land on the final check. */
      const reached = Math.floor(clamp(progress / 0.8) * rows.length);
      rows.forEach((row, i) => row.classList.toggle('on', i < reached));
      const done = reached >= rows.length;
      verdict.dataset.state = done ? 'allow' : 'waiting';
      text.textContent = done ? 'Authorized · executed · recorded' : 'Awaiting authorization';
    }, 0.88, 0.45);
  }
}

/* ------------------------------------------- the light in the dark panels */

/*
 * The same slow field behind each contained dark panel. Abstract on purpose: a network drawn
 * over a map would place nodes in named countries and imply operations nobody has claimed.
 */
const slowField = canvas => liveCanvas(canvas, (paint, w, h) => {
  const nodes = [];
  const count = Math.round(clamp((w * h) / 24000, 10, 32));
  for (let i = 0; i < count; i++) {
    nodes.push({ x: Math.random() * w, y: Math.random() * h, dx: (Math.random() - 0.5) * 0.14, dy: (Math.random() - 0.5) * 0.14 });
  }
  return () => {
    paint.clearRect(0, 0, w, h);
    for (const n of nodes) {
      n.x += n.dx; n.y += n.dy;
      if (n.x < 0 || n.x > w) n.dx *= -1;
      if (n.y < 0 || n.y > h) n.dy *= -1;
    }
    paint.lineWidth = 1;
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const d = Math.hypot(nodes[i].x - nodes[j].x, nodes[i].y - nodes[j].y);
        if (d > 165) continue;
        paint.strokeStyle = `rgba(110, 170, 245, ${(0.16 * (1 - d / 165)).toFixed(3)})`;
        paint.beginPath();
        paint.moveTo(nodes[i].x, nodes[i].y);
        paint.lineTo(nodes[j].x, nodes[j].y);
        paint.stroke();
      }
    }
    paint.fillStyle = 'rgba(150, 200, 255, .5)';
    for (const n of nodes) {
      paint.beginPath();
      paint.arc(n.x, n.y, 1.6, 0, Math.PI * 2);
      paint.fill();
    }
  };
});

slowField($('arch-net'));
slowField($('keys-net'));
slowField($('home-net'));

/* ----------------------------------------------------- the demo ask */

{
  const note = $('home-note');
  $('home-demo')?.addEventListener('click', () => {
    if (note) note.textContent = 'Technical demo booking is not connected yet — nothing has been sent.';
  });
}

/* ===================================================== the About page */

/**
 * A canvas that only draws while it is on screen, sized to the device and to its box.
 * Everything animated on these pages goes through this, so nothing is ever left running
 * behind a page nobody is looking at.
 */
function liveCanvas(canvas, setup) {
  if (!canvas || still.matches) return;
  const paint = canvas.getContext('2d');
  let w = 0, h = 0, running = false, draw = () => {};

  const fit = () => {
    const ratio = Math.min(window.devicePixelRatio || 1, 2);
    w = canvas.clientWidth;
    h = canvas.clientHeight;
    if (!w || !h) return false;
    canvas.width = Math.round(w * ratio);
    canvas.height = Math.round(h * ratio);
    paint.setTransform(ratio, 0, 0, ratio, 0, 0);
    draw = setup(paint, w, h);
    return true;
  };

  const tick = () => {
    if (!running) return;
    draw();
    requestAnimationFrame(tick);
  };
  const start = () => { if (!running && (w || fit())) { running = true; requestAnimationFrame(tick); } };
  const stop = () => { running = false; };

  fit();
  window.addEventListener('resize', () => { fit(); }, { passive: true });
  new IntersectionObserver(([entry]) => (entry.isIntersecting ? start() : stop())).observe(canvas);
  document.addEventListener('visibilitychange', () => (document.hidden ? stop() : start()));
}

/* ------------------------------------------------------- the About hero */

{
  const hero = document.querySelector('.en-hero');
  const scene = document.querySelector('.en-hero-scene');
  const figure = $('story-figure');

  /* The palm and the drawn building both answer the pointer, by about ten pixels. */
  const follow = (host, target) => {
    if (!host || !target || still.matches) return;
    let pending = false;
    host.addEventListener('pointermove', event => {
      if (pending) return;
      pending = true;
      requestAnimationFrame(() => {
        pending = false;
        const box = host.getBoundingClientRect();
        target.style.setProperty('--en-px', ((event.clientX - box.left) / box.width - 0.5).toFixed(3));
        target.style.setProperty('--en-py', ((event.clientY - box.top) / box.height - 0.5).toFixed(3));
      });
    });
    host.addEventListener('pointerleave', () => {
      target.style.setProperty('--en-px', 0);
      target.style.setProperty('--en-py', 0);
    });
  };

  follow(hero, scene);
  follow(figure, figure?.querySelector('.en-building'));
}

/* ------------------------------------------------ the architecture -------- */

{
  const arch = $('arch');
  const nodes = $('arch-nodes');
  const say = $('arch-say');

  /*
   * What each layer actually does, written to be true of this system rather than of a
   * brochure. Where something is not built yet it says so in the sentence.
   */
  const LAYERS = {
    human: 'A palm read by Veyns, bound to the exact transaction it approves. The approval carries '
      + 'the digest of that transaction, so it cannot be moved onto another one, and it is spent '
      + 'the moment it is used.',
    policy: 'Conditions evaluated before anything is signed: how much may move, how many people '
      + 'must agree, which destinations are permitted, and within which window.',
    crypto: 'ML-DSA-65 signs every authorisation under its own domain separated context. '
      + 'ML-KEM-768 and X25519 together establish the keys that seal the vault, so the seal holds '
      + 'even if one of the two is broken.',
    hardware: 'Keeping cryptographic operations inside protected hardware rather than in software. '
      + 'This is the direction of the architecture, not something running today.',
  };
  const REST = 'Select a layer to see what it does.';

  if (arch && nodes && say) {
    const buttons = [...nodes.querySelectorAll('button')];
    const web = $('arch-web');
    const core = $('arch-core');
    const out = arch.querySelector('.en-arch-out');
    let wires = [];

    /*
     * The wires are drawn from where things actually are. A fixed viewBox stretched over the
     * box cannot line up with a column of buttons whose height depends on how their labels
     * wrapped, so the geometry is measured and the paths rebuilt whenever the layout changes.
     */
    const rewire = () => {
      if (!web || !core || !out || web.clientWidth < 2) return;
      const box = arch.getBoundingClientRect();
      const at = el => {
        const r = el.getBoundingClientRect();
        return { l: r.left - box.left, r: r.right - box.left, y: r.top - box.top + r.height / 2 };
      };
      /*
       * The mark, not the cell it sits in. The cell is a whole grid column wide, so measuring
       * it puts the ends of every wire hundreds of pixels to the left of anything visible.
       */
      const c = at(core.querySelector('img') || core);
      const o = at(out);

      web.setAttribute('viewBox', `0 0 ${Math.round(box.width)} ${Math.round(box.height)}`);
      web.innerHTML = buttons.map(button => {
        const b = at(button);
        const bend = (c.l - b.r) * 0.55;
        return `<path class="en-wire" data-wire="${button.dataset.node}" `
          + `d="M${b.r.toFixed(1)} ${b.y.toFixed(1)} C${(b.r + bend).toFixed(1)} ${b.y.toFixed(1)} `
          + `${(c.l - bend).toFixed(1)} ${c.y.toFixed(1)} ${c.l.toFixed(1)} ${c.y.toFixed(1)}"/>`;
      }).join('')
        + `<path class="en-wire out" data-wire="out" d="M${c.r.toFixed(1)} ${c.y.toFixed(1)}H${o.l.toFixed(1)}"/>`;

      wires = [...web.querySelectorAll('.en-wire')];
      paint();
    };

    let chosen = null;

    /* Applied from `chosen` rather than from the event, so rebuilding the wires keeps the state. */
    function paint() {
      arch.toggleAttribute('data-live', !!chosen);
      for (const wire of wires) {
        const mine = wire.dataset.wire;
        wire.classList.toggle('hot', !!chosen && (mine === chosen || mine === 'out'));
      }
      for (const button of buttons) {
        button.setAttribute('aria-pressed', String(button.dataset.node === chosen));
      }
      say.textContent = chosen ? LAYERS[chosen] : REST;
    }

    const light = name => { chosen = name; paint(); };

    /* The layout settles late — fonts, wrapping, the view being shown at all — so it is redrawn
     * on every frame the driver runs, which is cheap because it only rebuilds when the box moved. */
    let was = '';
    drive(arch, () => {
      const box = arch.getBoundingClientRect();
      const now = `${Math.round(box.width)}x${Math.round(box.height)}`;
      if (now === was) return;
      was = now;
      rewire();
    });

    for (const button of buttons) {
      const { node } = button.dataset;
      /* Pointer and keyboard reach the same state, and clicking a lit one puts it out again. */
      button.addEventListener('click', () => {
        light(button.getAttribute('aria-pressed') === 'true' ? null : node);
      });
      button.addEventListener('pointerenter', () => light(node));
      button.addEventListener('focus', () => light(node));
    }
    nodes.addEventListener('pointerleave', () => {
      if (!buttons.some(b => b.matches(':focus-visible'))) light(null);
    });
  }
}

/* ------------------------------------------------------ the technology */

{
  const tabs = $('tech-tabs');
  const panel = $('tech-panel');
  const title = $('tech-title');
  const body = $('tech-body');
  const state = $('tech-state');

  /*
   * One visual with four states. Each says what is implemented and what is not, because the
   * page is aimed at people whose job is to check.
   */
  const TECH = {
    human: ['Human', 'Verified human authorization. A palm read by Veyns is bound to the exact '
      + 'transaction it approves, and the approval is spent the moment it is used.', 'live', 'Implemented'],
    policy: ['Policy', 'Programmable transaction controls: amount rules, how many people must '
      + 'approve, permitted destinations and the window in which they apply.', 'live', 'Implemented'],
    crypto: ['Cryptography', 'ML-DSA-65 for authorisation signatures under a domain separated '
      + 'context, and ML-KEM-768 alongside X25519 for key establishment.', 'live', 'Implemented'],
    keys: ['Key protection', 'Keeping private key material inside protected hardware, so an '
      + 'application asks for a signature rather than receiving the key. Designed for, not yet built.',
      'planned', 'Designed for'],
  };

  if (tabs && panel && title && body && state) {
    const buttons = [...tabs.querySelectorAll('button')];
    const arts = [...panel.querySelectorAll('.en-art')];

    const pick = (name, moveFocus) => {
      const [heading, said, mark, label] = TECH[name];
      for (const button of buttons) {
        const mine = button.dataset.tech === name;
        button.setAttribute('aria-selected', String(mine));
        button.tabIndex = mine ? 0 : -1;
        if (mine) {
          panel.setAttribute('aria-labelledby', button.id);
          if (moveFocus) button.focus();
        }
      }
      /* Re-adding the class restarts the trace, so switching back redraws rather than sitting. */
      for (const art of arts) art.classList.toggle('on', art.dataset.art === name);
      title.textContent = heading;
      body.textContent = said;
      state.dataset.state = mark;
      state.textContent = label;
    };

    for (const button of buttons) button.addEventListener('click', () => pick(button.dataset.tech));

    /* Arrow keys move between tabs, which is what a tablist is expected to do. */
    tabs.addEventListener('keydown', event => {
      const step = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 }[event.key];
      if (!step) return;
      event.preventDefault();
      const here = buttons.findIndex(b => b.getAttribute('aria-selected') === 'true');
      pick(buttons[(here + step + buttons.length) % buttons.length].dataset.tech, true);
    });

    pick('human');
  }
}

/* ------------------------------------------------------- the network */

/*
 * Deliberately abstract rather than a world map. A map would put nodes in named places and
 * imply operations there, which is a claim nobody has made.
 */
liveCanvas($('globe'), (paint, w, h) => {
  const points = [];
  const count = Math.round(clamp(w / 34, 14, 40));
  for (let i = 0; i < count; i++) {
    const a = (i / count) * Math.PI * 2 + Math.random() * 0.3;
    const r = 0.26 + Math.random() * 0.22;
    points.push({
      x: w * (0.5 + Math.cos(a) * r * 1.5),
      y: h * (0.5 + Math.sin(a) * r),
      phase: Math.random() * Math.PI * 2,
    });
  }
  /* A handful of paths, each carrying one travelling pulse. */
  const paths = [];
  for (let i = 0; i < Math.min(9, count); i++) {
    const a = points[Math.floor(Math.random() * points.length)];
    const b = points[Math.floor(Math.random() * points.length)];
    if (a !== b) paths.push({ a, b, t: Math.random(), speed: 0.0016 + Math.random() * 0.0026 });
  }

  let beat = 0;
  return () => {
    beat += 0.012;
    paint.clearRect(0, 0, w, h);

    paint.lineWidth = 1;
    for (const { a, b } of paths) {
      paint.strokeStyle = 'rgba(96, 150, 220, .16)';
      paint.beginPath();
      paint.moveTo(a.x, a.y);
      paint.quadraticCurveTo((a.x + b.x) / 2, (a.y + b.y) / 2 - h * 0.2, b.x, b.y);
      paint.stroke();
    }

    for (const p of points) {
      const lit = 0.3 + 0.3 * Math.sin(beat + p.phase);
      paint.fillStyle = `rgba(120, 180, 255, ${lit.toFixed(3)})`;
      paint.beginPath();
      paint.arc(p.x, p.y, 1.8, 0, Math.PI * 2);
      paint.fill();
    }

    for (const path of paths) {
      path.t += path.speed;
      if (path.t > 1) path.t = 0;
      const { a, b, t } = path;
      const cx = (a.x + b.x) / 2, cy = (a.y + b.y) / 2 - h * 0.2;
      const u = 1 - t;
      const x = u * u * a.x + 2 * u * t * cx + t * t * b.x;
      const y = u * u * a.y + 2 * u * t * cy + t * t * b.y;
      paint.fillStyle = 'rgba(150, 210, 255, .9)';
      paint.beginPath();
      paint.arc(x, y, 2.2, 0, Math.PI * 2);
      paint.fill();
    }
  };
});

/* A slower, sparser version of the same idea behind the closing panel. */
liveCanvas($('cta-net'), (paint, w, h) => {
  const nodes = [];
  const count = Math.round(clamp((w * h) / 22000, 10, 30));
  for (let i = 0; i < count; i++) {
    nodes.push({
      x: Math.random() * w,
      y: Math.random() * h,
      dx: (Math.random() - 0.5) * 0.16,
      dy: (Math.random() - 0.5) * 0.16,
    });
  }
  return () => {
    paint.clearRect(0, 0, w, h);
    for (const n of nodes) {
      n.x += n.dx; n.y += n.dy;
      if (n.x < 0 || n.x > w) n.dx *= -1;
      if (n.y < 0 || n.y > h) n.dy *= -1;
    }
    paint.lineWidth = 1;
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const d = Math.hypot(nodes[i].x - nodes[j].x, nodes[i].y - nodes[j].y);
        if (d > 160) continue;
        paint.strokeStyle = `rgba(110, 170, 245, ${(0.16 * (1 - d / 160)).toFixed(3)})`;
        paint.beginPath();
        paint.moveTo(nodes[i].x, nodes[i].y);
        paint.lineTo(nodes[j].x, nodes[j].y);
        paint.stroke();
      }
    }
    paint.fillStyle = 'rgba(150, 200, 255, .5)';
    for (const n of nodes) {
      paint.beginPath();
      paint.arc(n.x, n.y, 1.6, 0, Math.PI * 2);
      paint.fill();
    }
  };
});

/* --------------------------------------------------------- the journey */

{
  const line = $('timeline');
  const stages = line ? [...line.children] : [];
  if (line && stages.length) {
    drive(line, progress => {
      const run = clamp(progress / 0.8);
      line.style.setProperty('--en-run', run.toFixed(3));
      const reached = Math.round(run * stages.length);
      stages.forEach((stage, i) => stage.classList.toggle('on', i < reached));
    }, 0.84, 0.5);
  }
}

/* ------------------------------------------------------ the demo ask */

{
  const note = $('about-note');
  $('about-demo')?.addEventListener('click', () => {
    if (note) note.textContent = 'Demo booking is not connected yet — nothing has been sent.';
  });
}
/* ================================================== the Technology page */

/* -------------------------------------------------- the drawn module */

{
  const stack = $('tech-stack');
  const hero = document.querySelector('.tech-hero');
  if (stack && hero && !still.matches) {
    /* The layers separate as the page moves, which is the point being made about them. */
    drive(hero, progress => {
      stack.style.setProperty('--tech-spread', `${(22 + progress * 34).toFixed(1)}px`);
    }, 1, 0);

    /* And the whole stack turns a few degrees towards the pointer, so it reads as an object. */
    let pending = false;
    hero.addEventListener('pointermove', event => {
      if (pending) return;
      pending = true;
      requestAnimationFrame(() => {
        pending = false;
        const box = hero.getBoundingClientRect();
        stack.style.setProperty('--tech-rx', ((event.clientX - box.left) / box.width - 0.5).toFixed(3));
        stack.style.setProperty('--tech-ry', ((event.clientY - box.top) / box.height - 0.5).toFixed(3));
      });
    });
    hero.addEventListener('pointerleave', () => {
      stack.style.setProperty('--tech-rx', 0);
      stack.style.setProperty('--tech-ry', 0);
    });
  }
}

/* -------------------------------------------------- the seven steps */

{
  const flow = $('flow');
  const steps = flow ? [...flow.children] : [];
  if (flow && steps.length) {
    drive(flow, progress => {
      const run = clamp(progress / 0.82);
      flow.style.setProperty('--tech-run', run.toFixed(3));
      const reached = Math.round(run * steps.length);
      steps.forEach((step, i) => step.classList.toggle('on', i < reached));
    }, 0.84, 0.5);
  }
}

/* ------------------------------------------------------ the firewall */

{
  const wall = $('wall');
  const checks = $('checks');
  const verdict = $('verdict');
  const text = $('verdict-text');
  if (wall && checks && verdict && text) {
    const rows = [...checks.children];
    drive(wall, progress => {
      /* The last fifth is left for the verdict, so it does not land on the final check. */
      const reached = Math.floor(clamp(progress / 0.8) * rows.length);
      rows.forEach((row, i) => row.classList.toggle('on', i < reached));
      const done = reached >= rows.length;
      verdict.dataset.state = done ? 'allow' : 'waiting';
      text.textContent = done ? 'Policy satisfied · release to signing' : 'Evaluating policy';
    }, 0.88, 0.45);
  }
}

/* -------------------------------------------------- the policy builder */

{
  const form = $('builder2');
  const amount = $('pol-amount');
  const out = $('pol-amount-out');
  const asset = $('pol-asset');
  const dest = $('pol-dest');
  const rules = $('rules');
  const decision = $('decision');
  const label = $('decision-text');
  const why = $('decision-why');
  const approvals = $('rule-approvals');

  if (form && amount && out && asset && dest && rules && decision && label && why) {
    const LIMIT = 5_000_000;
    const PERMITTED = new Set(['USDC', 'BTC']);
    const money = n => `$${n.toLocaleString('en-US')}`;

    const settle = () => {
      const value = Number(amount.value);
      const which = asset.value;
      const whitelisted = dest.value === 'approved';
      /* More money, more people: the rule the vault actually implements. */
      const needed = value > 1_000_000 ? 3 : 2;

      out.textContent = money(value);
      if (approvals) approvals.textContent = `${needed} palms required`;

      const verdicts = {
        limit: value <= LIMIT,
        asset: PERMITTED.has(which),
        dest: whitelisted,
        approvals: true,
      };
      for (const row of rules.children) {
        const ok = verdicts[row.dataset.rule];
        row.classList.toggle('on', ok);
        row.classList.toggle('fail', !ok);
      }

      const broken = Object.entries(verdicts).filter(([, ok]) => !ok).map(([name]) => name);
      if (!broken.length) {
        decision.dataset.state = 'allow';
        label.textContent = 'Policy satisfied';
        why.textContent = `A ${money(value)} ${which} transfer to a whitelisted destination, `
          + `authorized by ${needed} palms.`;
        return;
      }
      decision.dataset.state = 'deny';
      label.textContent = 'Policy refuses';
      const said = {
        limit: `${money(value)} is over the ${money(LIMIT)} limit`,
        asset: `${which} is not a permitted asset`,
        dest: 'the destination is not on the whitelist',
      };
      why.textContent = `Refused before any key is reached for: ${broken.map(b => said[b]).join(', ')}.`;
    };

    for (const control of [amount, asset, dest]) control.addEventListener('input', settle);
    settle();
  }
}

/* ------------------------------------------------------ the agility */

{
  const art = $('agility-art');
  const eras = art ? [...art.querySelectorAll('.tech-eras li')] : [];
  if (art && eras.length) {
    drive(art, progress => {
      const reached = Math.round(clamp(progress / 0.8) * eras.length);
      eras.forEach((era, i) => era.classList.toggle('on', i < reached));
    }, 0.86, 0.55);
  }
}

/* --------------------------------------------------- the trust boundary */

{
  const zones = $('zones');
  const say = $('zone-say');

  /*
   * What crosses, and what does not. Written from what this system does rather than from what
   * a diagram implies, including the part that is not built yet.
   */
  const ZONES = {
    app: 'Treasury and custody systems ask for a transfer. What leaves this zone is an intent: '
      + 'an asset, an amount and a destination. No key material ever enters it, and nothing here '
      + 'can decide that a transfer is permitted.',
    plane: 'The control plane turns that intent into a plan, evaluates the policy against it, and '
      + 'collects the palms the policy demands. It is the only place that decides. What leaves it '
      + 'is a plan and an authorization bound to that plan by digest.',
    keys: 'Key material is sealed with ML-KEM-768 and X25519 and is unsealed only to sign one '
      + 'plan, in one window that closes behind it. Today that unsealing happens in the browser, '
      + 'not in dedicated hardware — which is the single most important thing on this page to be '
      + 'accurate about. Moving it behind hardware is what the architecture is designed for.',
    chain: 'What crosses into the network is a signed transaction and nothing else. No identity, '
      + 'no policy, no approver. The chain sees a valid spend; who authorized it stays in the '
      + 'evidence record on this side of the boundary.',
  };
  const REST = 'Select a zone to see what crosses its boundary, and what never does.';

  if (zones && say) {
    const buttons = [...zones.querySelectorAll('button')];
    const light = name => {
      for (const button of buttons) button.setAttribute('aria-pressed', String(button.dataset.zone === name));
      say.textContent = name ? ZONES[name] : REST;
    };
    for (const button of buttons) {
      const { zone } = button.dataset;
      button.addEventListener('click', () => {
        light(button.getAttribute('aria-pressed') === 'true' ? null : zone);
      });
      button.addEventListener('pointerenter', () => light(zone));
      button.addEventListener('focus', () => light(zone));
    }
  }
}

/* ------------------------------------------------- the binding demo */

/*
 * This one is real. The record is canonicalised and digested with SHA-256 in the browser, the
 * same way the vault does it, so changing a field genuinely changes the digest and genuinely
 * breaks the match against the approval that was given for the old one.
 *
 * What is not done here is the signature. That needs a palm.
 */
{
  const amount = $('bind-amount');
  const dest = $('bind-dest');
  const hash = $('bind-hash');
  const approvedOut = $('bind-approved');
  const state = $('bind-state');
  const label = $('bind-state-text');
  const again = $('bind-reapprove');

  /** Objects serialise with their keys in order, so the same record always gives the same bytes. */
  const canonical = value => {
    if (value === null || typeof value !== 'object') return JSON.stringify(value);
    if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
    return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  };

  const base64url = bytes => btoa(String.fromCharCode(...bytes))
    .replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');

  const digestOf = async record => {
    const bytes = new TextEncoder().encode(canonical(record));
    return base64url(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
  };

  const recordNow = () => ({
    vault: 'vault_8f42a1c9',
    asset: 'USDC',
    amount: (amount?.value || '').trim(),
    destination: (dest?.value || '').trim(),
    network: 'ethereum',
    policy: 'institutional-treasury-v3',
    nonce: '7c1d4e8b',
  });

  if (amount && dest && hash && approvedOut && state && label && crypto?.subtle) {
    let approved = null;

    const refresh = async () => {
      const now = await digestOf(recordNow());
      hash.textContent = now;
      approvedOut.textContent = approved ?? now;
      const matches = approved === null || approved === now;
      state.dataset.state = matches ? 'allow' : 'deny';
      label.textContent = matches
        ? 'Authorization matches this transaction'
        : 'Authorization invalid · the transaction changed';
      if (again) again.hidden = matches;
    };

    const fix = async () => { approved = await digestOf(recordNow()); await refresh(); };

    for (const field of [amount, dest]) field.addEventListener('input', refresh);
    again?.addEventListener('click', fix);
    /* The first digest computed is the one that was approved. */
    fix();
  }
}

/* --------------------------------------------- the closing panel */

liveCanvas($('tech-net'), (paint, w, h) => {
  const nodes = [];
  const count = Math.round(clamp((w * h) / 22000, 10, 30));
  for (let i = 0; i < count; i++) {
    nodes.push({ x: Math.random() * w, y: Math.random() * h, dx: (Math.random() - 0.5) * 0.14, dy: (Math.random() - 0.5) * 0.14 });
  }
  return () => {
    paint.clearRect(0, 0, w, h);
    for (const n of nodes) {
      n.x += n.dx; n.y += n.dy;
      if (n.x < 0 || n.x > w) n.dx *= -1;
      if (n.y < 0 || n.y > h) n.dy *= -1;
    }
    paint.lineWidth = 1;
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const d = Math.hypot(nodes[i].x - nodes[j].x, nodes[i].y - nodes[j].y);
        if (d > 150) continue;
        paint.strokeStyle = `rgba(110, 170, 245, ${(0.18 * (1 - d / 150)).toFixed(3)})`;
        paint.beginPath();
        paint.moveTo(nodes[i].x, nodes[i].y);
        paint.lineTo(nodes[j].x, nodes[j].y);
        paint.stroke();
      }
    }
    paint.fillStyle = 'rgba(150, 200, 255, .5)';
    for (const n of nodes) {
      paint.beginPath();
      paint.arc(n.x, n.y, 1.6, 0, Math.PI * 2);
      paint.fill();
    }
  };
});

{
  const note = $('tech-note');
  $('tech-demo')?.addEventListener('click', () => {
    if (note) note.textContent = 'Technical demo booking is not connected yet — nothing has been sent.';
  });
}
/* ===================================================== how things feel */

/**
 * A track of cards that browses with the pointer.
 *
 * The scroll position sets where the rail rests; moving the pointer across the section pushes
 * it further either way, and it eases back when the pointer leaves. Both are clamped to the
 * overflow, so the rail can never be pushed past its own ends.
 *
 * Only on a pointer that can hover and a screen wide enough to have overflow worth browsing.
 * A phone gets a rail it can swipe, which it is already better at.
 */
function pointerRail(view, track) {
  if (!view || !track || still.matches) return;
  const fine = window.matchMedia('(hover: hover) and (pointer: fine) and (min-width: 861px)');

  let base = 0;        // where the scroll has put it
  let bias = 0;        // where the pointer is pushing it
  let shown = 0;       // where it actually is, easing towards base + bias
  let running = false;

  const overflow = () => Math.max(0, track.scrollWidth - view.clientWidth);

  const ease = () => {
    const want = clamp(base + bias, 0, overflow());
    shown += (want - shown) * 0.12;
    if (Math.abs(want - shown) < 0.4) { shown = want; running = false; }
    track.style.setProperty('--vx-rail', Math.round(shown));
    if (running) requestAnimationFrame(ease);
  };
  const nudge = () => { if (!running) { running = true; requestAnimationFrame(ease); } };

  /* The scroll keeps setting the resting point, whether or not a pointer is anywhere near. */
  drive(view, progress => {
    if (!fine.matches) { track.style.setProperty('--vx-rail', 0); return; }
    base = progress * overflow();
    nudge();
  }, 1, 0);

  view.addEventListener('pointermove', event => {
    if (!fine.matches || event.pointerType !== 'mouse') return;
    const box = view.getBoundingClientRect();
    /* Half the overflow either way, so the pointer can reach both ends but not fling it. */
    bias = ((event.clientX - box.left) / box.width - 0.5) * overflow() * 0.9;
    nudge();
  });
  view.addEventListener('pointerleave', () => { bias = 0; nudge(); });
}

/**
 * Cards that answer the pointer: a few degrees of tilt towards it, a lift, and a soft light
 * that follows it across the face. Delegated per group rather than one listener per card.
 */
function tiltGroup(group, selector) {
  if (!group || still.matches) return;
  if (!window.matchMedia('(hover: hover) and (pointer: fine)').matches) return;

  for (const card of group.querySelectorAll(selector)) card.classList.add('vx-tilt');

  let pending = false;
  group.addEventListener('pointermove', event => {
    const card = event.target.closest(selector);
    if (!card || pending) return;
    pending = true;
    requestAnimationFrame(() => {
      pending = false;
      const box = card.getBoundingClientRect();
      const x = (event.clientX - box.left) / box.width;
      const y = (event.clientY - box.top) / box.height;
      card.style.setProperty('--tilt-x', (x - 0.5).toFixed(3));
      card.style.setProperty('--tilt-y', (y - 0.5).toFixed(3));
      card.style.setProperty('--sheen-x', `${(x * 100).toFixed(1)}%`);
      card.style.setProperty('--sheen-y', `${(y * 100).toFixed(1)}%`);
    });
  });

  /* Leaving a card has to reset that card, not whichever one the pointer happens to be over. */
  group.addEventListener('pointerout', event => {
    const card = event.target.closest(selector);
    if (!card || card.contains(event.relatedTarget)) return;
    card.style.setProperty('--tilt-x', 0);
    card.style.setProperty('--tilt-y', 0);
  });
}

{
  /* The rails. */
  pointerRail($('rail-view'), $('rail'));
  pointerRail($('int-view'), $('integrations'));

  /* The cards, everywhere there are cards. */
  const tilts = [
    ['.vx-cards', '.vx-card'],
    ['.vx-rail', 'li'],
    ['.vx-controls', 'li'],
    ['.en-pillars', 'li'],
    ['.en-values', 'li'],
    ['.en-caps', 'li'],
    ['.tech-integrations', 'li'],
    ['.tech-principles', 'li'],
  ];
  for (const [groupSelector, cardSelector] of tilts) {
    for (const group of document.querySelectorAll(groupSelector)) tiltGroup(group, cardSelector);
  }
}
/* ------------------------------------------------------- proximity */

/**
 * Hands every marker in a group how close the pointer is to it, 0 to 1, as a custom property.
 *
 * The glow is built from that number in the stylesheet, so it falls away smoothly with
 * distance instead of snapping on and off at a hover boundary — the whole row responds, the
 * nearest one most. This is what carries the sequence now that the connecting rules are gone.
 */
function proximity(group, selector, radius = 260) {
  if (!group || still.matches) return;
  if (!window.matchMedia('(hover: hover) and (pointer: fine)').matches) return;

  const marks = [...group.querySelectorAll(selector)];
  if (!marks.length) return;

  let pending = false;
  group.addEventListener('pointermove', event => {
    if (pending) return;
    pending = true;
    requestAnimationFrame(() => {
      pending = false;
      for (const mark of marks) {
        const box = mark.getBoundingClientRect();
        const gap = Math.hypot(
          event.clientX - (box.left + box.width / 2),
          event.clientY - (box.top + box.height / 2),
        );
        /* Squared falloff, so the nearest reads as clearly nearest rather than one of several. */
        const near = clamp(1 - gap / radius) ** 2;
        mark.style.setProperty('--near', near.toFixed(3));
      }
    });
  });

  group.addEventListener('pointerleave', () => {
    for (const mark of marks) mark.style.setProperty('--near', 0);
  });
}

for (const [group, mark] of [
  ['#flow', '.tech-step'],
  ['#home-chain', '.home-chain-node'],
  ['.home-strip', '.en-ico'],
  ['.home-layers', 'li'],
  ['#timeline', 'li'],
]) {
  for (const el of document.querySelectorAll(group)) proximity(el, mark);
}
/* ----------------------------------------------------------------- go */

window.addEventListener('scroll', onScroll, { passive: true });
window.addEventListener('resize', onScroll, { passive: true });

/*
 * This page starts hidden, because the application decides which view to put up once it knows
 * whether anybody is signed in. Nothing above can measure anything until then — a hidden
 * element has no box — so the whole lot is started again the moment the page is actually shown.
 */
function begin() {
  measureIcons();
  watchArrivals();
  frame();
}

/*
 * Either direction matters. Arriving, everything has to be measured and started; leaving, the
 * bar still has to be told, because it is shared with the page being moved to.
 */
let started = false;
for (const page of PAGES) {
  if (!page.hidden) { begin(); started = true; }
  new MutationObserver(() => (page.hidden ? frame() : begin()))
    .observe(page, { attributes: true, attributeFilter: ['hidden'] });
}
if (!started) frame();

/* Web fonts land late, and every measurement above depends on the layout they change. */
window.addEventListener('load', frame);
if (document.fonts?.ready) document.fonts.ready.then(frame);
