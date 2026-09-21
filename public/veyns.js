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
  for (const shape of document.querySelectorAll('.vx-ico svg > *')) {
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
     * The bar is transparent while it sits on the hero and earns a ground of its own the
     * moment the page moves. It has to be the moment the page moves and not the moment the
     * hero leaves: the bar overlaps whatever is beneath it the whole way down, and a
     * transparent bar over running content is unreadable.
     */
    const home = $('view-signin');
    /*
     * Transparent only while it is actually sitting on the hero. Anywhere else it needs a
     * ground of its own, including the About page, which is a light page — a bar of white
     * type on it is a bar of nothing at all.
     */
    drive(nav, () => nav.classList.toggle('stuck', window.scrollY > 28 || !home || home.hidden));
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
  const home = $('view-signin');
  if (!id || !home || home.hidden) return;

  const target = document.getElementById(id);
  if (!target || !home.contains(target)) return;

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

const home = document.getElementById('view-signin');
if (home) {
  if (!home.hidden) begin();
  /*
   * Either direction matters. Arriving, everything has to be measured and started; leaving,
   * the bar still has to be told, because it is shared with the page being moved to.
   */
  new MutationObserver(() => (home.hidden ? frame() : begin()))
    .observe(home, { attributes: true, attributeFilter: ['hidden'] });
} else {
  frame();
}

/* Web fonts land late, and every measurement above depends on the layout they change. */
window.addEventListener('load', frame);
if (document.fonts?.ready) document.fonts.ready.then(frame);
