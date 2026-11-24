"""Synthetic chart and image widgets shared by the Linux dashboard fixtures."""
import base64

import gi

gi.require_version("GdkPixbuf", "2.0")
from gi.repository import GdkPixbuf


def image_uri(fmt, size=(320, 80), reverse=False):
    width, height = size
    image = GdkPixbuf.Pixbuf.new(GdkPixbuf.Colorspace.RGB, False, 8, width, height)
    red, blue = 0xc83228ff, 0x2048bcff
    image.fill(blue if reverse else red)
    right = image.new_subpixbuf(width // 2, 0, width - width // 2, height)
    right.fill(red if reverse else blue)
    saved, data = image.save_to_bufferv(fmt.lower(), [], [])
    assert saved
    return f"data:image/{fmt.lower()};base64," + base64.b64encode(data).decode("ascii")


def chart_widgets():
    categories = [{"label": name, "value": n} for name, n in [("Build", 3), ("Test", 5), ("Ship", 2)]]
    return [
        {"id": "trend", "kind": "graph", "label": "Sample history", "value": [1, 8, 3], "unit": "ms"},
        {"id": "counts", "kind": "bar", "label": "Stage counts", "value": categories},
        {"id": "share", "kind": "pie", "label": "Stage share", "value": categories},
        {"id": "profile", "kind": "radar", "label": "Stage profile", "value": categories},
        {"id": "runs", "kind": "scatter", "label": "Run times", "value": [[1, 1], [2, 8], [3, 3]],
         "x_unit": "jobs", "unit": "ms"},
    ]
