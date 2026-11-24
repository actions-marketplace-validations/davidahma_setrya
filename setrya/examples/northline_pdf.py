"""Read and write the bounded single-page PDF used by the Northline fixture."""

import re

_CONTENT = re.compile(rb"(?m)^4 0 obj\n<< /Length ([1-9][0-9]{0,3}) >>\nstream\n")
_LINE = re.compile(rb"\(((?:[ -'*-\[\]-~]|\\[()\\]){1,240})\) Tj\n")
_ESCAPE = re.compile(rb"\\([()\\])")
_PREAMBLE = b"BT\n/F1 14 Tf\n50 740 Td\n"
_STEP = b"0 -28 Td\n"
_DRAW_BAR = b"ET\n0.12 0.37 0.63 rg\n50 640 170 16 re f\n"


def render_pdf(lines):
    """Render the chart labels and a vector bar into a real single-page PDF."""
    if len(lines) != 3 or any(not 0 < len(line) <= 120 or not line.isascii() or not line.isprintable()
                              for line in lines):
        raise ValueError("The synthetic chart must provide three bounded ASCII labels.")
    escaped = [line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)").encode("ascii")
               for line in lines]
    stream = _PREAMBLE + _STEP.join(b"(" + line + b") Tj\n" for line in escaped) + _DRAW_BAR
    entries = (
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
         b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>"),
        b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"endstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    )
    result = bytearray(b"%PDF-1.4\n")
    positions = []
    for index, entry in enumerate(entries, start=1):
        positions.append(len(result))
        result.extend(f"{index} 0 obj\n".encode("ascii") + entry + b"\nendobj\n")
    xref = len(result)
    result.extend(b"xref\n0 6\n0000000000 65535 f \n")
    for position in positions:
        result.extend(f"{position:010d} 00000 n \n".encode("ascii"))
    result.extend(f"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii"))
    return bytes(result)


MAX_PDF_BYTES = 4096


def read_pdf_labels(raw):
    """Decode only the generated format and fail closed on unfamiliar bytes."""
    if len(raw) > MAX_PDF_BYTES:
        raise ValueError("The synthetic PDF exceeds its fixture budget.")
    match = _CONTENT.search(raw)
    if match is None:
        raise ValueError("The synthetic PDF content stream is unreadable.")
    start = match.end()
    stream = raw[start:start + int(match[1])]
    if not stream.startswith(_PREAMBLE) or not stream.endswith(_DRAW_BAR):
        raise ValueError("The synthetic PDF drawing instructions are unreadable.")
    lines = []
    for operand in stream[len(_PREAMBLE):-len(_DRAW_BAR)].split(_STEP):
        line = _LINE.fullmatch(operand)
        if line is None:
            raise ValueError("A label in the synthetic PDF is unreadable.")
        lines.append(_ESCAPE.sub(rb"\1", line[1]).decode("ascii"))
    if render_pdf(lines) != raw:
        raise ValueError("The synthetic PDF objects or cross-reference table differ.")
    return tuple(lines)
