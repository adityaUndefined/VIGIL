#!/usr/bin/env python3
"""Generate VIGIL extension icons (16/32/48/128 px).

The extension's icons are generated from the project's existing favicon.svg
rather than shipping a large binary blob. This is a DEV-TIME utility only —
the generated PNGs are committed with the extension, so most users never need
to run it. Requires Pillow:  pip install pillow
"""
from PIL import Image, ImageDraw

SIZE = 512
# Professional light cybersecurity palette — no neon, no gradients.
BG = "#0F3D91"        # deep VIGIL blue badge background
ACCENT = "#FFFFFF"    # shield stroke + glyph
SHIELD = "#2563EB"    # primary VIGIL blue shield

img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
draw = ImageDraw.Draw(img)

# Rounded-square badge so the icon reads cleanly on both light and dark toolbars.
draw.rounded_rectangle([8, 8, SIZE - 8, SIZE - 8], radius=112, fill=BG)

# Shield silhouette (roughly half the badge width, centered slightly high).
cx = SIZE / 2
top = 108
left, right = cx - 150, cx + 150
tip = 400
shield = [
    (cx, top),
    (right, top + 64),
    (right, 244),
    (cx, tip),
    (left, 244),
    (left, top + 64),
]
draw.polygon(shield, fill=SHIELD)
draw.line(shield + [shield[0]], fill=ACCENT, width=22, joint="curve")

# Shield check mark — reads as "protection verified" at 16px.
check = [(cx - 70, 250), (cx - 18, 306), (cx + 86, 190)]
draw.line(check, fill=ACCENT, width=34, joint="curve")

img.save("icon_dev_512.png")
for size in (16, 32, 48, 128):
    img.resize((size, size), Image.LANCZOS).save(f"icons/icon{size}.png")

print("icons generated:", ", ".join(f"icons/icon{s}.png" for s in (16, 32, 48, 128)))
