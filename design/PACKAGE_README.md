# QuVault Exact HTML + Assets

IMPORTANT:
This package contains two different implementation approaches.

## MODE A — PIXEL PERFECT

Use `EXACT_REFERENCE_HTML.html`.

It uses `reference/MASTER_REFERENCE.png` as the exact visual layer and places real HTML links as transparent hotspots over it.

This is the only approach that can guarantee the rendered pixels remain identical to the supplied reference.

## MODE B — REAL COMPONENT REBUILD

Use the individual PNG crops under `assets/` as visual building blocks and rebuild the layout in React/CSS.

The crops are exact pixels taken from the supplied rendered design. They are NOT regenerated replacements.

The transparent palm asset is also supplied separately.

## DO NOT

- regenerate artwork
- substitute stock imagery
- change the blue glow
- change the palm
- redesign the composition
- invent different icons
- alter the source reference

## Recommended Claude workflow

1. Open MASTER_REFERENCE.png.
2. Open every section reference.
3. Open every asset.
4. Read EXACT_REFERENCE_HTML.html.
5. If pixel identity is the priority, preserve the master reference as the visual layer.
6. If true DOM reconstruction is required, use the crops as immutable image assets and reproduce the surrounding geometry with CSS.
7. Render at 796px wide first.
8. Screenshot the result.
9. Pixel-compare it against MASTER_REFERENCE.png.
