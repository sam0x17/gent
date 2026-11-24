#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["resvg-py==0.5.0", "pillow==12.0.0"]
# ///
"""Build Gent's icons from the primary and optical-size SVG masters."""

import argparse
from copy import deepcopy
from io import BytesIO
import json
from pathlib import Path
import xml.etree.ElementTree as ET

from PIL import Image, ImageDraw, ImageFont
import resvg_py


HERE = Path(__file__).resolve().parent
SIZES = (16, 32, 48, 64, 128, 192, 256, 512)
FAVICON_SIZES = (16, 32, 48)
PNG_SETS = {"inkling": SIZES, "classic": SIZES, "favicon": SIZES, "inkling-favicon": FAVICON_SIZES,
            "inkling-tray": (128,)}
ICO_SETS = ("favicon", "inkling-favicon", "classic")
COMPARISONS = (
    ("inkling", "Inkling / original"),
    ("inkling-favicon", "Inkling / optical size"),
    ("classic", "Classic / selected favicon"),
)
CREAM = "#fff9ec"
DARK = "#171717"
NS = "http://www.w3.org/2000/svg"
ET.register_namespace("", NS)


def outlined(svg: str) -> str:
    """Place a 12-unit outside rim behind the original ink."""
    root = ET.fromstring(svg)
    root.set("viewBox", "-24 -24 560 560")
    halo = ET.Element(f"{{{NS}}}g", {"aria-hidden": "true"})
    for shape in root:
        if shape.get("id") not in ("body", "hat"):
            continue
        rim = deepcopy(shape)
        rim.attrib.pop("id")
        rim.set("fill", CREAM)
        rim.set("stroke", CREAM)
        rim.set("stroke-width", str(int(shape.get("stroke-width", "0")) + 24))
        rim.set("stroke-linejoin", "round")
        halo.append(rim)
    root.insert(1, halo)
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode") + "\n"


def render(svg: str, size: int) -> Image.Image:
    # Render at the target size. No rescaling from a larger bitmap.
    data = resvg_py.svg_to_bytes(
        svg_string=svg, width=size, height=size, skip_system_fonts=True
    )
    return Image.open(BytesIO(data)).convert("RGBA")


def png(image: Image.Image) -> bytes:
    output = BytesIO()
    image.save(output, format="PNG", optimize=True)
    return output.getvalue()


def make_ico(artifacts: dict[str, bytes], name: str) -> bytes:
    # Supply each actual-size render to the ICO writer; never let it resize one.
    frames = [Image.open(BytesIO(artifacts[f"{name}-{size}.png"])) for size in reversed(FAVICON_SIZES)]
    output = BytesIO()
    frames[0].save(
        output, format="ICO", sizes=[(size, size) for size in FAVICON_SIZES], append_images=frames[1:]
    )
    return output.getvalue()


def build() -> tuple[dict[str, bytes], dict[str, str]]:
    masters = {name: (HERE / f"{name}.svg").read_text() for name in ("inkling", "classic", "inkling-favicon")}
    drawings = dict(masters)
    drawings.update({f"{name}-dark": outlined(masters[name]) for name in ("inkling", "classic")})
    tray = ET.fromstring(masters["inkling"])
    tray.set("viewBox", "6 0 500 500")
    drawings["inkling-tray"] = ET.tostring(tray, encoding="unicode") + "\n"
    drawings["favicon"] = drawings["classic-dark"]
    artifacts = {
        f"{name}.svg": svg.encode()
        for name, svg in drawings.items()
        if name not in masters
    }
    for name, sizes in PNG_SETS.items():
        drawing = f"{name}-dark" if name in ("inkling", "classic") else name
        for size in sizes:
            artifacts[f"{name}-{size}.png"] = png(render(drawings[drawing], size))

    for name in ICO_SETS:
        artifacts[f"{name}.ico"] = make_ico(artifacts, name)

    # iOS supplies its own rounded mask. Leave the square tile opaque.
    apple = Image.new("RGBA", (180, 180), CREAM)
    apple.alpha_composite(render(masters["inkling"], 156), (12, 12))
    artifacts["apple-touch-icon.png"] = png(apple.convert("RGB"))
    manifest = {
        "name": "Gent",
        "short_name": "Gent",
        "icons": [
            {"src": f"./inkling-{size}.png", "sizes": f"{size}x{size}",
             "type": "image/png", "purpose": "any"}
            for size in (192, 512)
        ],
        "theme_color": CREAM,
        "background_color": CREAM,
        "display": "standalone",
    }
    artifacts["site.webmanifest"] = (json.dumps(manifest, indent=2) + "\n").encode()
    return artifacts, drawings


def verify(artifacts: dict[str, bytes], drawings: dict[str, str]) -> None:
    for name, sizes in PNG_SETS.items():
        for size in sizes:
            icon = Image.open(BytesIO(artifacts[f"{name}-{size}.png"]))
            if icon.size != (size, size) or icon.mode != "RGBA":
                raise ValueError(f"Wrong dimensions or mode: {name}-{size}.png")
            alpha = icon.getchannel("A")
            box = alpha.getbbox()
            if not box:
                raise ValueError(f"Empty icon: {name}-{size}.png")
            if name == "inkling-favicon":
                # The tighter framing permits half-covered edge pixels at 16px.
                edges = ((0, 0, size, 1), (0, size - 1, size, size),
                         (0, 0, 1, size), (size - 1, 0, size, size))
                if any(alpha.crop(edge).getextrema()[1] > 128 for edge in edges):
                    raise ValueError(f"Insufficient optical icon padding: {size}")
            elif min(box[:2]) <= 0 or max(box[2:]) >= size:
                raise ValueError(f"Missing transparent padding: {name}-{size}.png")
    for name in ICO_SETS:
        ico = Image.open(BytesIO(artifacts[f"{name}.ico"]))
        if ico.ico.sizes() != {(size, size) for size in FAVICON_SIZES}:
            raise ValueError(f"Wrong ICO frames: {name}")
        for size in FAVICON_SIZES:
            expected = Image.open(BytesIO(artifacts[f"{name}-{size}.png"]))
            if ico.ico.getimage((size, size)).tobytes() != expected.tobytes():
                raise ValueError(f"ICO frame differs from its PNG: {name}-{size}")
    apple = Image.open(BytesIO(artifacts["apple-touch-icon.png"]))
    if apple.size != (180, 180) or apple.mode != "RGB":
        raise ValueError("Wrong Apple touch icon dimensions or mode")
    for icon in json.loads(artifacts["site.webmanifest"])["icons"]:
        if not icon["src"].startswith("./") or icon["src"][2:] not in artifacts:
            raise ValueError("Manifest must refer to local generated icons")
    for name, svg in drawings.items():
        root = ET.fromstring(svg)
        ids = {element.get("id") for element in root.iter() if element.get("id")}
        for element in root.iter():
            if element.tag.rsplit("}", 1)[-1] not in {"svg", "title", "g", "path", "ellipse", "defs", "use"}:
                raise ValueError(f"Unexpected SVG content: {name}")
            for key, value in element.attrib.items():
                if key.endswith("href") and (not value.startswith("#") or value[1:] not in ids):
                    raise ValueError(f"SVG reference must resolve within the drawing: {name}")


def contact_sheet(drawings: dict[str, str], artifacts: dict[str, bytes]) -> bytes:
    sheet = Image.new("RGB", (1040, 1188), "#e9e6df")
    draw = ImageDraw.Draw(sheet)
    font = ImageFont.load_default(size=15)
    small = ImageFont.load_default(size=13)
    heading = ImageFont.load_default(size=24)
    draw.text((24, 20), "Gent / The Inkling", fill=DARK, font=heading)
    draw.text((24, 54), "Primary identity: Inkling. Browser favicon: Classic.", fill=DARK, font=font)
    for x, background, name, label in (
        (24, "#fff", "inkling", "Inkling / light surface"),
        (528, DARK, "inkling-dark", "Inkling / dark surface"),
    ):
        draw.rounded_rectangle((x, 88, x + 488, 402), radius=12, fill=background)
        icon = render(drawings[name], 272)
        sheet.paste(icon, (x + 108, 96), icon)
        draw.text((x + 18, 374), label, fill=DARK if name == "inkling" else CREAM, font=font)
    draw.text((24, 424), "Actual pixels (16 / 32 / 48), then nearest-neighbor enlargements", fill=DARK, font=font)
    columns = ((252, 16, 1), (356, 32, 1), (468, 48, 1), (652, 16, 6), (852, 32, 3))
    for x, size, scale in columns:
        label = f"{size}px" if scale == 1 else f"{size}px at {scale}x"
        draw.text((x - 8, 454), label, fill=DARK, font=small)
    for index, (name, label, background) in enumerate(
        (name, label, background) for background in ("#fff", DARK) for name, label in COMPARISONS
    ):
        y = 480 + index * 112
        draw.rectangle((24, y, 1016, y + 104), fill=background)
        draw.text((40, y + 43), label, fill=DARK if background == "#fff" else CREAM, font=font)
        for x, size, scale in columns:
            icon = Image.open(BytesIO(artifacts[f"{name}-{size}.png"]))
            if scale != 1:
                icon = icon.resize((size * scale, size * scale), Image.Resampling.NEAREST)
            sheet.paste(icon, (x + (64 - icon.width) // 2, y + (104 - icon.height) // 2), icon)
    draw.text((24, 1162), "Optical Inkling: tighter framing, larger eyes, stronger outline. All icons retain transparent backgrounds.", fill=DARK, font=small)
    return png(sheet)


def preview_html(artifacts: dict[str, bytes], drawings: dict[str, str]) -> bytes:
    # Embed the final bytes so the preview works from any local path or offline.
    import base64

    def uri(data: bytes, mime: str) -> str:
        return f"data:{mime};base64," + base64.b64encode(data).decode()

    rows = []
    for theme in ("light", "dark"):
        for name, label in COMPARISONS:
            icons = "".join(
                f'<figure><img width="{size}" height="{size}" alt="{label}, {size} pixels" '
                f'src="{uri(artifacts[f"{name}-{size}.png"], "image/png")}">'
                f'<figcaption>{size}px</figcaption></figure>'
                for size in FAVICON_SIZES
            )
            rows.append(f'<section class="{theme}"><h2>{label}</h2><div class="sizes">{icons}</div></section>')
    heroes = "".join(
        f'<section class="{theme}"><img class="hero" width="272" height="272" '
        f'alt="Inkling on a {theme} surface" src="{uri(drawings[name].encode(), "image/svg+xml")}"></section>'
        for theme, name in (("light", "inkling"), ("dark", "inkling-dark"))
    )
    return ("""<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Gent branding preview</title>
<style>
*{box-sizing:border-box}body{margin:0;padding:28px;background:#e9e6df;color:#171717;font:16px system-ui,sans-serif}
main{max-width:1040px;margin:auto}h1{margin:0 0 12px}h2{font-size:16px;margin:0 0 20px}
.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}
.comparisons{grid-template-columns:repeat(3,minmax(0,1fr))}
section{padding:24px;border-radius:12px;min-width:0}.light{background:white}.dark{background:#171717;color:#fff9ec}
.hero{display:block;max-width:100%;height:auto;margin:auto}.sizes{display:flex;align-items:end;gap:16px;flex-wrap:wrap}
figure{margin:0;min-width:48px}figure img{display:block}figcaption{margin-top:12px;font-size:12px}
.note{margin:24px 0;line-height:1.5}@media(max-width:820px){.comparisons{grid-template-columns:1fr}}@media(max-width:620px){.grid{grid-template-columns:1fr}body{padding:16px}}
</style><main><h1>Gent / The Inkling</h1>
<p class="note">Inkling is the primary logo and app identity. Classic is the selected browser favicon. Optical-size Inkling remains available for comparison.</p>
<div class="grid">""" + heroes + """</div>
<p class="note">Compare the original Inkling, optical-size Inkling, and Classic at 16, 32 and 48 CSS pixels. Optical Inkling uses tighter framing, larger eyes, and a stronger body outline. All three include a cream outside outline. Use 100% browser zoom to compare their intended display sizes.</p>
<div class="grid comparisons">""" + "".join(rows) + "</div></main></html>\n").encode()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="compare generated bytes without writing")
    parser.add_argument("--preview-dir", type=Path, help="also build contact-sheet.png and preview.html here")
    args = parser.parse_args()
    artifacts, drawings = build()
    verify(artifacts, drawings)
    outputs = {HERE / name: data for name, data in artifacts.items()}
    if args.preview_dir:
        outputs[args.preview_dir / "contact-sheet.png"] = contact_sheet(drawings, artifacts)
        outputs[args.preview_dir / "preview.html"] = preview_html(artifacts, drawings)
    stale = []
    for path, data in outputs.items():
        if args.check:
            if not path.is_file() or path.read_bytes() != data:
                stale.append(str(path))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    if stale:
        raise SystemExit("Missing or stale output:\n" + "\n".join(stale))
    print(f"{'Verified' if args.check else 'Built'} {len(outputs)} files; dimensions, padding, ICO frames and manifest references passed.")


if __name__ == "__main__":
    main()
