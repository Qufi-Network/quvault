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

const $ = id => document.getElementById(id);
const clamp = (v, lo = 0, hi = 1) => (v < lo ? lo : v > hi ? hi : v);
const still = window.matchMedia('(prefers-reduced-motion: reduce)');

/*
 * The marketing surface is two pages sharing one document and one bar: the dark home page and
 * the light enterprise pages. Both are hidden until the application decides which to put up.
 */
const PAGES = ['view-signin', 'view-about'].map($).filter(Boolean);
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
  for (const shape of document.querySelectorAll('.vx-ico svg > *, .en-ico svg > *')) {
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

  const failsafe = setTimeout(() => {
    if (!document.querySelector('[data-reveal].in, [data-reveal-group].in')) showAll();
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
     * Both marketing pages open on a dark hero, so the bar is transparent until the page
     * moves and then earns a ground of its own. The moment the page moves, not the moment
     * the hero leaves: the bar overlaps whatever runs beneath it the whole way down, and a
     * transparent bar over running content is unreadable.
     *
     * Which ground depends on the page. The home page stays dark to the bottom; the
     * enterprise pages turn white below their hero, and the bar has to turn with them.
     */
    drive(nav, () => {
      const page = showing();
      nav.classList.toggle('light', !!page && page.classList.contains('en'));
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

/* ----------------------------------------------------------- the hero */

{
  const hero = document.querySelector('.vx-hero');
  const scene = $('hero-scene');

  if (hero && scene && !still.matches) {
    /* The scene answers the pointer, by a few pixels. Anything more reads as a gimmick. */
    let pending = false;
    hero.addEventListener('pointermove', event => {
      if (pending) return;
      pending = true;
      requestAnimationFrame(() => {
        pending = false;
        const box = hero.getBoundingClientRect();
        scene.style.setProperty('--vx-px', ((event.clientX - box.left) / box.width - 0.5).toFixed(3));
        scene.style.setProperty('--vx-py', ((event.clientY - box.top) / box.height - 0.5).toFixed(3));
      });
    });
    hero.addEventListener('pointerleave', () => {
      scene.style.setProperty('--vx-px', 0);
      scene.style.setProperty('--vx-py', 0);
    });

    /* Leaving the hero, the scene settles back rather than scrolling away flat. */
    drive(hero, progress => {
      scene.style.setProperty('--vx-hero-scale', (1 - progress * 0.06).toFixed(4));
    }, 1, 0);
  }

  /* An ambient drift of light, only while the hero is actually on screen. */
  const canvas = $('hero-dust');
  if (canvas && !still.matches) {
    const paint = canvas.getContext('2d');
    const motes = [];
    let running = false;
    let width = 0;
    let height = 0;

    const fit = () => {
      const ratio = Math.min(window.devicePixelRatio || 1, 2);
      width = canvas.clientWidth;
      height = canvas.clientHeight;
      canvas.width = Math.round(width * ratio);
      canvas.height = Math.round(height * ratio);
      paint.setTransform(ratio, 0, 0, ratio, 0, 0);
    };

    const seed = () => {
      motes.length = 0;
      /* Tied to area, so a phone is not asked to draw a desktop's worth of them. */
      const count = Math.round(clamp((width * height) / 26000, 18, 54));
      for (let i = 0; i < count; i++) {
        motes.push({
          x: Math.random() * width,
          y: Math.random() * height,
          r: 0.5 + Math.random() * 1.2,
          drift: 0.06 + Math.random() * 0.22,
          sway: Math.random() * Math.PI * 2,
          alpha: 0.12 + Math.random() * 0.3,
        });
      }
    };

    const tick = () => {
      if (!running) return;
      paint.clearRect(0, 0, width, height);
      for (const m of motes) {
        m.y -= m.drift;
        m.sway += 0.006;
        if (m.y < -4) { m.y = height + 4; m.x = Math.random() * width; }
        paint.beginPath();
        paint.arc(m.x + Math.sin(m.sway) * 6, m.y, m.r, 0, Math.PI * 2);
        paint.fillStyle = `rgba(120, 180, 255, ${m.alpha})`;
        paint.fill();
      }
      requestAnimationFrame(tick);
    };

    const start = () => { if (!running) { running = true; requestAnimationFrame(tick); } };
    const stop = () => { running = false; };

    fit();
    seed();
    window.addEventListener('resize', () => { fit(); seed(); }, { passive: true });
    /* Off screen it stops, and a hidden tab stops it too. */
    new IntersectionObserver(([entry]) => (entry.isIntersecting ? start() : stop())).observe(canvas);
    document.addEventListener('visibilitychange', () => (document.hidden ? stop() : start()));
  }
}

/* -------------------------------------------- the request being verified */

{
  const steps = [...document.querySelectorAll('#txn-steps li')];
  const status = $('txn-status');
  const text = $('txn-status-text');

  if (steps.length && status && text) {
    drive($('txn-demo'), progress => {
      /* The last quarter is left for the verdict, so it does not land on the final step. */
      const reached = Math.floor(clamp(progress / 0.75) * steps.length);
      steps.forEach((step, i) => step.classList.toggle('on', i < reached));
      const done = reached >= steps.length;
      status.dataset.state = done ? 'done' : 'waiting';
      text.textContent = done ? 'Authorised by verified human' : 'Awaiting human verification';
    }, 0.9, 0.45);
  }
}

/* ------------------------------------------------ transaction authority */

{
  const card = $('authority');
  const links = [...document.querySelectorAll('#chain li')];
  const state = $('authority-state');

  if (card && links.length && state) {
    drive(card, progress => {
      const reached = Math.round(clamp(progress / 0.8) * links.length);
      links.forEach((link, i) => link.classList.toggle('on', i < reached));
      const done = reached >= links.length;
      card.classList.toggle('done', done);
      state.textContent = done ? 'Verified' : 'Verification required';
    }, 0.86, 0.5);
  }
}

/* -------------------------------------------------- the security stack */

{
  const list = $('layers');
  const layers = list ? [...list.children] : [];
  const count = $('stack-count');
  const note = $('stack-note');

  const NOTES = [
    'Scroll to assemble the boundary.',
    'A person is present, and the palm proves it.',
    'The person present is the person entitled to authorise.',
    'The terminal doing the asking is one the vault trusts.',
    'The signature will outlive classical cryptography.',
    'The policy decides what that signature may authorise.',
    'Complete. Nothing moves unless every control agrees.',
  ];

  if (list && layers.length) {
    drive(list, progress => {
      const reached = Math.round(clamp(progress / 0.86) * layers.length);
      layers.forEach((layer, i) => {
        layer.classList.toggle('seen', i < reached);
        layer.classList.toggle('on', i === reached - 1);
      });
      list.style.setProperty('--vx-stack', (reached / layers.length).toFixed(3));
      if (count) count.textContent = reached;
      if (note) note.textContent = NOTES[reached] || NOTES[0];
    }, 0.82, 0.55);
  }
}

/* ------------------------------------------------------- the portfolio */

/* The bars know their own width; the stylesheet only animates it once the panel has arrived. */
for (const bar of document.querySelectorAll('.vx-bar[data-w]')) {
  bar.style.setProperty('--vx-w', bar.dataset.w);
}

/* --------------------------------------- the controls and what they do */

{
  const rows = $('req-rows');
  const controls = $('controls');

  if (rows && controls) {
    const light = (name, on) => {
      const row = rows.querySelector(`[data-control="${name}"]`);
      if (row) row.classList.toggle('lit', on);
    };
    for (const control of controls.children) {
      const { control: name } = control.dataset;
      if (!name) continue;
      control.addEventListener('pointerenter', () => light(name, true));
      control.addEventListener('pointerleave', () => light(name, false));
      /* A keyboard reaches it too, so the control is focusable and behaves the same. */
      control.tabIndex = 0;
      control.addEventListener('focus', () => light(name, true));
      control.addEventListener('blur', () => light(name, false));
    }
  }
}

/* ------------------------------------------------ the authorisation trail */

{
  const trail = $('trail');
  const stops = trail ? [...trail.children] : [];

  if (trail && stops.length) {
    drive(trail, progress => {
      const run = clamp(progress / 0.8);
      trail.style.setProperty('--vx-trail', run.toFixed(3));
      const reached = Math.round(run * stops.length);
      stops.forEach((stop, i) => stop.classList.toggle('on', i < reached));
    }, 0.84, 0.5);
  }
}

/* --------------------------------------------------------- the use rail */

{
  const view = $('rail-view');
  const rail = $('rail');
  /*
   * On a wide screen the rail is carried by the scroll. On a narrow one it is something to
   * swipe, and the stylesheet says so, so the transform is left alone below that width.
   */
  const wide = window.matchMedia('(min-width: 861px)');

  if (view && rail) {
    drive(view, progress => {
      if (!wide.matches) { rail.style.setProperty('--vx-rail', 0); return; }
      const over = Math.max(0, rail.scrollWidth - view.clientWidth);
      rail.style.setProperty('--vx-rail', Math.round(progress * over));
    }, 1, 0);
  }
}

/* --------------------------------------------------- the migration path */

{
  const steps = [...document.querySelectorAll('#migration .vx-mig-steps li')];
  if (steps.length) {
    drive($('migration'), progress => {
      const reached = Math.round(clamp(progress / 0.8) * steps.length);
      steps.forEach((step, i) => step.classList.toggle('on', i < reached));
    }, 0.86, 0.55);
  }
}

/* --------------------------------------------------------- the moment */

{
  const moment = document.querySelector('.vx-moment');
  const scene = document.querySelector('.vx-moment-scene');
  if (moment && scene && !still.matches) {
    drive(moment, progress => {
      scene.style.setProperty('--vx-moment', (progress * 2 - 1).toFixed(3));
    }, 1, 0);
  }
}

/* ----------------------------------------------------- the policy engine */

{
  const form = $('builder');
  const state = $('builder-state');
  const label = $('builder-state-text');
  const note = $('builder-note');

  if (form && state && label && note) {
    const switches = [
      ['pol-biometric', 'a palm at signing'],
      ['pol-approvals', 'two approvals'],
      ['pol-device', 'a trusted device'],
      ['pol-window', 'business hours'],
    ];

    const settle = () => {
      const on = switches.filter(([id]) => $(id)?.checked);
      const names = on.map(([, what]) => what);
      /*
       * Said plainly rather than scored: a policy with nothing left in it is an open policy,
       * and calling that anything softer would be the wrong thing to teach on this page.
       */
      if (!on.length) {
        state.dataset.state = 'open';
        label.textContent = 'Policy open';
        note.textContent = 'No controls enforced. A $1.2M transfer to Treasury 04 would settle on a '
          + 'single signature, with nothing recorded about who authorised it.';
        return;
      }
      state.dataset.state = on.length === switches.length ? 'active' : 'reduced';
      label.textContent = on.length === switches.length ? 'Policy active' : 'Policy reduced';
      const list = names.length === 1 ? names[0]
        : `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`;
      note.textContent = `${on.length} of ${switches.length} controls enforced. A $1.2M transfer to `
        + `Treasury 04 at 14:20 would need ${list}.`;
    };

    for (const [id] of switches) $(id)?.addEventListener('change', settle);
    settle();
  }
}

/* ------------------------------------------------------ the demo asks */

/*
 * There is nowhere to send a demo request yet. Rather than take somebody's details into a
 * form that goes nowhere, the page says so — the same answer the vault gives everywhere else
 * it has not been connected to something real.
 */
{
  const note = $('cta-note');
  const say = message => { if (note) note.textContent = message; };
  $('demo-cta')?.addEventListener('click', () => say('Demo booking is not connected yet — nothing has been sent. Reach the team through your existing Veyns contact.'));
  $('talk-cta')?.addEventListener('click', () => say('Security contact is not connected yet — nothing has been sent.'));
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
