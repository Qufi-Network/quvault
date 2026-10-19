# Image brief — the Veyns site

**What this is for.** The site has 13 sections below the hero and no photography in any of them;
every visual is a small inline icon. That is why the page reads as rows of identical boxes
however the colours are adjusted. This names exactly what to supply.

**It asks for seven images, not thirteen.** A page where every section carries a photograph is
as monotonous as one where none does. Six of the sections are better served by diagrams, which
are built in SVG and need nothing from you. The rhythm below alternates deliberately:
photograph, diagram, type, photograph.

---

## 1. Art direction — read this before the list

There is already a strong idea in `veyns-hero.webp`: **a human hand, veins traced in light,
against dark technological space.** Every image below should look like it came from the same
shoot or the same render session as that one. Seven unrelated stock photographs will look worse
than no photographs at all.

Hold these constant across the set:

| | |
|---|---|
| **Ground** | near-black, blue-cast. `#070a12` to `#0d1220`. Never a white or grey studio background. |
| **Light** | one cool source, `#1272ff` to `#4f9dff`, raking or emanating. Light should look like it is *travelling* — through veins, along an edge, down a surface. |
| **Subject** | hands, and the hardware a hand meets. People only as hands and forearms. |
| **Skin** | any and all. The product reads a palm; the set should not read as one demographic. Vary skin tone deliberately across the seven. |
| **Mood** | institutional and still. Not consumer-tech bright, not crypto-neon, no gold coins, no padlocks, no circuit-board clichés, no hooded figures. |
| **Negative space** | every image needs a quiet third where text will sit. Noted per image below. |

**Format:** WebP, quality ~82. **Colour:** sRGB. **No text baked into any image.**
Deliver the master too (PNG or TIFF) so crops can be re-cut without a second generation of loss.

---

## 2. The seven

Sizes are the largest the layout uses; supply at 2× that for retina.

### A — `veyns-palm-scan.webp` · the signature image
**Section:** `human`, "A human in the loop." · **This is the most important image on the site.**

An open palm held above, or just touching, a dark contactless reader. Vein pattern lit from
within the hand in cool blue, the reader throwing a soft pool of light upward onto the skin.
Shot slightly from the side so the gap between hand and device is readable — that gap is the
product.

- **Aspect** 4:3, **2400 × 1800**
- **Crop** hand occupies the right two-thirds; **left third dark and empty for the headline**
- **Must read at 420px wide.** Test it small before sending.

### B — `veyns-authorize.webp` · several hands, one decision
**Section:** `controls`, "Security policies built for how institutions operate."

Two or three different hands, clearly different people, presenting to readers in the same dark
room — a quorum. Either a row of readers or one reader with the others waiting, slightly out of
focus. **Different skin tones.** This picture carries the whole threshold idea.

- **Aspect** 16:9, **2800 × 1575**
- **Crop** full-bleed band; subjects low in the frame, **upper third dark for the headline**

### C — `veyns-device.webp` · the hardware, as an object
**Section:** `keys`, "The key never becomes an application object."

The reader alone on a dark surface, three-quarter view, like a product photograph for a
precision instrument. Edge-lit, one highlight along the top chamfer, long soft reflection
beneath. No hand. Still and expensive-looking.

- **Aspect** 1:1, **1800 × 1800**
- **Crop** object centred with generous margin; sits beside text, not behind it

### D — `veyns-vault.webp` · where value rests
**Section:** `uses`, "Built for organizations moving serious value."

The institutional note. A dark server aisle, a vault door, or a trading floor at night — shot
long, cool, almost empty of people. Depth and perspective matter more than the subject. This is
the one image in the set that is about *place* rather than hands, which is why it earns its spot.

- **Aspect** 21:9, **3200 × 1372**
- **Crop** wide band; strong one-point perspective; **centre must survive a dark overlay**

### E — `veyns-evidence.webp` · the record
**Section:** `home-evidence`, "Security should be verifiable."

A hand at a screen showing a long verified record — rows of monospace detail, a column of
confirmations. Shot over the shoulder at a shallow angle so the screen is legible but abstract.
Screen content must be **unreadable as specifics**: no real addresses, amounts or names.

- **Aspect** 3:2, **2400 × 1600**
- **Crop** screen on the right, **left side falls into shadow for text**

### F — `veyns-integration.webp` · it fits where you already are
**Section:** `home-integration`, "Designed to fit your existing security stack."

A reader connected into existing equipment — cabling into a rack, or the device beside a laptop
and an HSM. Deliberately mundane and real: this section's job is to say *this slots in*, and a
grounded photograph says it better than an icon of a plug.

- **Aspect** 16:10, **2400 × 1500**
- **Crop** object right of centre; **left for a bulleted list**

### G — `veyns-contact.webp` · the close
**Section:** `contact`, "Build the next generation of digital asset security."

A single hand entering frame from the edge, palm open toward the viewer, vein light at its
faintest — the quietest image in the set. It closes the page by echoing the hero.

- **Aspect** 16:9, **2400 × 1350**
- **Crop** hand enters from the right; **two-thirds empty dark space on the left for the form**

---

## 3. What needs nothing from you

Built in SVG and CSS, animated, no assets required:

| Section | What it becomes |
|---|---|
| `principles-strip` | five principles as a typographic band, not five outline circles |
| `home-approach` | a layered diagram: key, policy, human, evidence as stacked planes |
| `home-architecture` | the seven stages as a **horizontal flow**, not a 6-plus-orphan card grid |
| `transaction` | an animated sequence of a transaction being checked before signing |
| `quantum` | a timeline of the cryptographic lifecycle |
| `learn` | a type-led call to action |

Fixing `home-architecture` matters on its own: it currently renders seven equal cards that wrap
to six and a stranded seventh, which reads as broken rather than designed.

---

## 4. If you can only do two

**A** (`veyns-palm-scan`) and **B** (`veyns-authorize`). The palm and the quorum are the whole
product. With those two the page works; the other five make it feel finished.

---

## 5. What I will not do

I will not generate these. An invented image of a palm-vein reader would be a picture of a
device that does not exist, on a site selling that device — and the same rule applies to the
screens in **E**. If an asset cannot be supplied, tell me and that section ships as a diagram
instead of a photograph. That is a real option, not a failure.
