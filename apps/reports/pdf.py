"""Minimal dependency-free PDF writer (Helvetica text reports).

Produces a valid multi-page PDF using only the standard library (zlib), so
PDF report generation works in air-gapped environments.  For richer layouts
a reportlab-based renderer can replace this module without API changes.
"""
from __future__ import annotations

import zlib

PAGE_W, PAGE_H = 595, 842          # A4 in points
MARGIN = 50
LINE_HEIGHT = 13
CHARS_PER_LINE = 100


def _esc(text: str) -> str:
    return (text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")
                .encode("latin-1", "replace").decode("latin-1"))


def _wrap(text: str, width: int = CHARS_PER_LINE) -> list[str]:
    words = text.split()
    lines, cur = [], ""
    for w in words:
        while len(w) > width:
            lines.append(w[:width])
            w = w[width:]
        if not cur:
            cur = w
        elif len(cur) + 1 + len(w) <= width:
            cur += " " + w
        else:
            lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines or [""]


def render_pdf(blocks: list[tuple[str, str]], title: str) -> bytes:
    """blocks: list of (style, text) where style is h1/h2/h3/body/bullet/kv."""
    # paginate
    pages: list[list[tuple[str, str]]] = []
    current: list[tuple[str, str]] = []
    y = PAGE_H - MARGIN
    for style, text in blocks:
        text = text.replace("\u2192", "->").replace("\u2019", "'").replace("\u201c", '"') \
                   .replace("\u201d", '"').replace("\u2013", "-").replace("\u2022", "-")
        wrapped = _wrap(text)
        lh = LINE_HEIGHT + (4 if style.startswith("h") else 0)
        if y - lh * len(wrapped) < MARGIN:
            pages.append(current)
            current = []
            y = PAGE_H - MARGIN
        for line in wrapped:
            current.append((style, line))
            y -= lh
        y -= 4 if style.startswith("h") else 1
    if current:
        pages.append(current)

    # content streams
    streams = []
    for page in pages:
        ops = ["BT"]
        y = PAGE_H - MARGIN
        for style, line in page:
            if style == "h1":
                font, size = "/F2", 16
            elif style == "h2":
                font, size = "/F2", 13
            elif style == "h3":
                font, size = "/F2", 11
            elif style == "kv":
                font, size = "/F1", 9
            elif style == "bullet":
                font, size = "/F1", 9.5
            else:
                font, size = "/F1", 9.5
            y -= LINE_HEIGHT + (4 if style.startswith("h") else 0)
            prefix = "  - " if style == "bullet" else ""
            ops.append(f"{font} {size} Tf")
            ops.append(f"1 0 0 1 {MARGIN} {y:.1f} Tm")
            ops.append(f"({_esc(prefix + line)}) Tj")
            y -= 1 if not style.startswith("h") else 4
        ops.append("ET")
        streams.append("\n".join(ops).encode("latin-1"))

    objects: list[bytes] = []

    def add(obj: bytes) -> int:
        objects.append(obj)
        return len(objects)

    catalog_id = 1
    pages_id = 2
    font1_id = 3
    font2_id = 4
    page_ids = []
    content_ids = []
    n_pages = max(1, len(streams))
    for i in range(n_pages):
        page_ids.append(5 + i * 2)
        content_ids.append(6 + i * 2)

    placeholders = 4 + n_pages * 2
    objs: dict[int, bytes] = {}
    objs[catalog_id] = f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode()
    kids = " ".join(f"{p} 0 R" for p in page_ids)
    objs[pages_id] = (f"<< /Type /Pages /Kids [{kids}] /Count {n_pages} >>").encode()
    objs[font1_id] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
    objs[font2_id] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>"
    for i, stream in enumerate(streams):
        compressed = zlib.compress(stream)
        objs[content_ids[i]] = (f"<< /Length {len(compressed)} /Filter /FlateDecode >>".encode()
                                + b"\nstream\n" + compressed + b"\nendstream")
        objs[page_ids[i]] = (f"<< /Type /Page /Parent {pages_id} 0 R "
                             f"/MediaBox [0 0 {PAGE_W} {PAGE_H}] "
                             f"/Resources << /Font << /F1 {font1_id} 0 R /F2 {font2_id} 0 R >> >> "
                             f"/Contents {content_ids[i]} 0 R >>").encode()

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}
    for i in range(1, placeholders + 1):
        offsets[i] = len(out)
        out += f"{i} 0 obj\n".encode() + objs[i] + b"\nendobj\n"
    xref_pos = len(out)
    out += f"xref\n0 {placeholders + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for i in range(1, placeholders + 1):
        out += f"{offsets[i]:010d} 00000 n \n".encode()
    out += (f"trailer\n<< /Size {placeholders + 1} /Root {catalog_id} 0 R >>\n"
            f"startxref\n{xref_pos}\n%%EOF").encode()
    return bytes(out)
