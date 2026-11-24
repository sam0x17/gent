# Gent branding

Inkling is Gent's primary logo and app/MCP identity: a cream bean with a thick
black outline, two upright oval eyes, a tilted solid black top hat, and no mouth.
Classic is the browser favicon. Optical-size Inkling remains available for
downloads and comparison. Both marks were drawn as simple SVG
paths from the selected references; the SVGs contain no raster images or fonts.

Use `inkling-256.png` for the MCP server icon at
`https://mcp.gent.link/branding/inkling-256.png`, and `inkling.svg` for the primary
vector at `https://mcp.gent.link/branding/inkling.svg`. The 256px PNG is square,
transparent, and has a cream outside outline for visibility on light and dark
surfaces. These are intended serving paths; this asset package does not set up
hosting or metadata.

## Rights

Copyright © 2026 PrivacyTools LLC. The Gent logos and their artwork are reserved. See the [branding and third-party notices](../../NOTICE.md) for use with the client, in screenshots and in independent products. The build script is BSD-3-Clause software.

## Colors and padding

| Use | Color |
| --- | --- |
| Hat, eyes, body outline | Black `#000000` |
| Inkling body, Classic band, outside outline | Cream `#FFF9EC` |
| Preview dark surface only | Charcoal `#171717` |

The full-size Inkling and Classic SVGs use a 512 x 512 viewBox with about 32 units of minimum
padding. The dark variants add a 12-unit cream outside outline and expand the
viewBox to `-24 -24 560 560`, keeping clear padding around the outline. The
original Inkling and Classic PNGs use these outlined variants so they work on
either theme, with at least one fully transparent edge pixel even at 16px. The
artwork keeps its natural proportions inside the square; there is no background
rectangle or original raster canvas.

The Apple touch icon is the exception: it uses an opaque cream square and a
156px Inkling drawing centered within 180px. iOS applies its own corner mask.

## Optical-size Inkling favicon

`inkling-favicon.svg` is a separate 32 x 32 drawing for browser tabs. It uses a
slightly wider, more compact bean, a simplified brim, larger oval eyes, and a
stronger body outline. It preserves the cream body, tilted solid black hat,
offset upright eyes, and absence of a mouth. The primary Inkling master and its
app/MCP PNGs are unchanged.

At 16px the black body outline is 1px thick, each eye is 1.3 x 2.2px, and the
cream outside outline is 0.5px. Framing is tighter than the original. The 16px
render permits partially covered edge pixels with about 50% opacity or less; the
32px and 48px renders retain a fully transparent border. Each size is rendered
directly from this SVG, including the matching frames in `inkling-favicon.ico`.

Classic is the selected favicon. `favicon.svg` matches `classic-dark.svg`,
`favicon.ico` matches `classic.ico`, and every `favicon-*.png` matches its
`classic-*.png` counterpart. The optical Inkling files remain available for
comparison; the primary Inkling stays the app and MCP identity.

## Files

| File | Purpose |
| --- | --- |
| `inkling.svg` | Hand-authored primary master for light surfaces |
| `inkling-dark.svg` | Same mark with a cream outside outline for dark surfaces |
| `inkling-favicon.svg` | Independent optical-size Inkling candidate |
| `inkling-favicon-16.png`, `inkling-favicon-32.png`, `inkling-favicon-48.png` | Optical-size Inkling comparison PNGs |
| `inkling-favicon.ico` | Alternate optical-size Inkling ICO |
| `classic.svg` | Hand-authored Classic top-hat master |
| `classic-dark.svg` | Classic with the cream outside outline |
| `classic-16.png`, `classic-32.png`, `classic-48.png`, `classic-64.png` | Classic comparison icons, with the cream outside outline |
| `classic-128.png`, `classic-192.png`, `classic-256.png`, `classic-512.png` | Larger Classic downloads |
| `classic.ico` | Classic ICO with 16, 32, and 48px frames |
| `favicon.svg` | Default Classic with the outside outline, for either browser theme |
| `favicon.ico` | Default Classic; separate PNG-compressed 16, 32, and 48px frames |
| `favicon-16.png`, `favicon-32.png`, `favicon-48.png`, `favicon-64.png` | Default Classic browser icons |
| `favicon-128.png`, `favicon-192.png`, `favicon-256.png`, `favicon-512.png` | Larger Classic favicon downloads |
| `inkling-16.png`, `inkling-32.png`, `inkling-48.png`, `inkling-64.png` | Inkling at small sizes; also used in the favicon comparison |
| `inkling-128.png`, `inkling-192.png`, `inkling-256.png`, `inkling-512.png` | Primary Inkling app/MCP icons and downloads |
| `apple-touch-icon.png` | 180px opaque Inkling icon |
| `site.webmanifest` | Gent app manifest; relative references to Inkling at 192 and 512px |
| `build.py` | Rebuilds all derived assets and optional previews |
| `README.md` | Asset usage and build instructions |

The manifest icons have `purpose: any`. They are not maskable icons. Set the
application URL and scope during integration if needed; this package leaves
both unspecified. Serve the directory intact so the relative icon paths resolve.

Example HTML, assuming the directory is served at `/branding/`:

```html
<link rel="icon" href="/branding/favicon.ico" sizes="16x16 32x32 48x48">
<link rel="icon" href="/branding/favicon.svg" type="image/svg+xml" sizes="any">
<link rel="apple-touch-icon" href="/branding/apple-touch-icon.png" sizes="180x180">
<link rel="manifest" href="/branding/site.webmanifest">
```

## Rebuild and check

Run from the public repository root with Python 3.10+ and `uv`:

```sh
uv run --script assets/branding/build.py
uv run --script assets/branding/build.py --check
```

The script pins `resvg-py==0.5.0` and `pillow==12.0.0` in its inline dependency
metadata. `uv` installs them in its cache, outside the repository. `inkling.svg`,
`classic.svg`, and `inkling-favicon.svg` are the drawing sources. Edit the
appropriate master, then rebuild the derived SVGs, PNGs, ICOs, and manifest
together. The optical master contains its own outline and uses only local SVG
path references.

Each PNG is rendered directly at its target size with resvg. ICO frames use the
matching PNG pixels. The output contains no timestamps. `--check` regenerates
bytes in memory and compares every output without writing; it also checks PNG
dimensions and padding, all three frames in each ICO, Apple icon format, SVG
elements and local path references, and local manifest references. Exact byte
comparison requires the same pinned dependencies and platform.

From the enclosing workspace, generate or verify the visual previews:

```sh
uv run --script gent/assets/branding/build.py --preview-dir branding/inkling
uv run --script gent/assets/branding/build.py --preview-dir branding/inkling --check
```

`branding/inkling/contact-sheet.png` compares the large Inkling variants plus
the original Inkling, optical-size Inkling, and Classic on white and charcoal
at 16, 32, and 48 actual pixels. It also enlarges the 16px and 32px rasterizations
with nearest-neighbor scaling so individual pixels are visible.
`branding/inkling/preview.html` is a self-contained offline preview with the
same PNG bytes at their intended CSS
sizes; view it at 100% browser zoom. Preview labels use Pillow's bundled font.
