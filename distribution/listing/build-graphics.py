#!/usr/bin/env python3
"""Derive the Play Store graphics from the artwork in graphics/source/.

Play wants exact dimensions, so the derived files are generated rather than hand-cropped:
re-run this after changing the source artwork or the wording on the feature graphic.

    python3 distribution/listing/build-graphics.py

Requires Pillow.
"""
import pathlib
import sys

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    sys.exit("Pillow is required: pip install Pillow")

BASE = pathlib.Path(__file__).parent / "en-US" / "graphics"
SRC = BASE / "source"

PAPER = (232, 230, 225)
BRASS = (201, 162, 39)

TITLE = "Easy PGP"
TAGLINE = "PGP without the command line"

# Menlo is a system font on macOS; Andale Mono is the fallback. Both are monospaced, which
# matches the landing page and the armor-block motif the artwork is built on.
FONTS = [
    ("/System/Library/Fonts/Menlo.ttc", 1, 0),
    ("/System/Library/Fonts/Supplemental/Andale Mono.ttf", None, None),
]


def font(size, bold=False):
    for path, bold_idx, regular_idx in FONTS:
        idx = bold_idx if bold else regular_idx
        try:
            if idx is None:
                return ImageFont.truetype(path, size)
            return ImageFont.truetype(path, size, index=idx)
        except OSError:
            continue
    sys.exit("No usable monospaced font found; edit FONTS for this machine.")


def build_icon():
    """512x512, square and opaque. Play applies its own corner mask, so do not pre-round."""
    src = Image.open(SRC / "icon-2048.jpeg").convert("RGB")
    out = src.resize((512, 512), Image.LANCZOS).convert("RGBA")
    out.save(BASE / "icon-512.png", "PNG")
    return "icon-512.png", out.size


def build_feature_graphic():
    """1024x500 with the wordmark set into the space the artwork leaves free."""
    src = Image.open(SRC / "feature-graphic-2976x1440.jpeg").convert("RGB")
    w, h = src.size
    # Trim width from the right, where the artwork is empty, rather than scaling non-uniformly.
    cropped = src.crop((0, 0, min(int(round(h * 1024 / 500)), w), h))
    out = cropped.resize((1024, 500), Image.LANCZOS)

    d = ImageDraw.Draw(out)
    # x=400 clears the key; y values sit the block above the dashed armor rule at y=400.
    d.text((400, 196), TITLE, font=font(92, bold=True), fill=PAPER, anchor="ls")
    d.text((400, 316), TAGLINE, font=font(31), fill=BRASS, anchor="ls")

    out.save(BASE / "feature-graphic-1024x500.png", "PNG")
    return "feature-graphic-1024x500.png", out.size


if __name__ == "__main__":
    for name, size in (build_icon(), build_feature_graphic()):
        print(f"  {name}: {size[0]}x{size[1]}")
