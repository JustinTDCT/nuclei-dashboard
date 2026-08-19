"""Page-buffered PDF rendering. Memory is bounded to the current page, not the report size."""

from __future__ import annotations

import tempfile
from collections.abc import Iterable, Sequence
from typing import Any

from fastapi.responses import StreamingResponse
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas

from app.reporting.csv_export import safe_filename

LEFT = 0.55 * inch
RIGHT = letter[0] - 0.55 * inch
TOP = letter[1] - 0.65 * inch
BOTTOM = 0.65 * inch
ROW_HEIGHT = 11
HEADER_HEIGHT = 13
USABLE_WIDTH = RIGHT - LEFT


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _clip_text(c: canvas.Canvas, text: str, width: float, font: str = "Times-Roman", size: float = 6) -> str:
    if c.stringWidth(text, font, size) <= width:
        return text
    ellipsis = "…"
    while text and c.stringWidth(text + ellipsis, font, size) > width:
        text = text[:-1]
    return text + ellipsis if text else ""


class _PdfWriter:
    def __init__(
        self,
        spool,
        *,
        title: str,
        scope: str,
        generated_at: str,
        timezone_label: str,
        columns: Sequence[str],
    ):
        self.spool = spool
        self.c = canvas.Canvas(spool, pagesize=letter)
        self.c.setTitle(title)
        self.c.setAuthor("Nuclei Dashboard")
        self.title = title
        self.scope = scope
        self.generated_at = generated_at
        self.timezone_label = timezone_label
        self.columns = list(columns)
        self.page = 1
        self.y = TOP
        self.table_open = False
        self.col_width = USABLE_WIDTH / max(len(self.columns), 1) if self.columns else USABLE_WIDTH
        self._header()

    def _header(self) -> None:
        self.c.setFont("Times-Roman", 8)
        self.c.drawString(LEFT, letter[1] - 0.4 * inch, "Nuclei Dashboard")
        self.c.drawRightString(RIGHT, letter[1] - 0.4 * inch, self.title)
        self.y = TOP

    def _footer(self) -> None:
        self.c.setFont("Times-Roman", 7)
        self.c.drawString(LEFT, 0.4 * inch, f"{self.scope}  ·  {self.generated_at}  ·  {self.timezone_label}")
        self.c.drawRightString(RIGHT, 0.4 * inch, f"Page {self.page}")

    def _new_page(self) -> None:
        self._footer()
        self.c.showPage()
        self.page += 1
        self._header()
        if self.table_open:
            self._table_header()

    def _need(self, height: float) -> None:
        if self.y - height < BOTTOM:
            self._new_page()

    def paragraph(self, text: str, *, font: str = "Times-Roman", size: float = 8, leading: float | None = None) -> None:
        leading = leading or size + 2
        self.c.setFont(font, size)
        line = ""
        for word in _text(text).split() or [""]:
            trial = f"{line} {word}".strip()
            if self.c.stringWidth(trial, font, size) <= USABLE_WIDTH:
                line = trial
                continue
            self._need(leading)
            self.c.setFont(font, size)
            self.c.drawString(LEFT, self.y - size, line)
            self.y -= leading
            line = word
        self._need(leading)
        self.c.setFont(font, size)
        self.c.drawString(LEFT, self.y - size, line)
        self.y -= leading

    def _table_header(self) -> None:
        self._need(HEADER_HEIGHT)
        self.c.setFillColorRGB(0.06, 0.09, 0.16)
        self.c.rect(LEFT, self.y - HEADER_HEIGHT + 2, USABLE_WIDTH, HEADER_HEIGHT, fill=1, stroke=0)
        self.c.setFillColorRGB(1, 1, 1)
        self.c.setFont("Times-Bold", 6)
        for idx, column in enumerate(self.columns):
            x = LEFT + idx * self.col_width
            label = _clip_text(self.c, column.replace("_", " "), self.col_width - 2, "Times-Bold", 6)
            self.c.drawString(x + 1, self.y - 8, label)
        self.c.setFillColorRGB(0, 0, 0)
        self.y -= HEADER_HEIGHT

    def start_table(self) -> None:
        if not self.columns:
            return
        self.table_open = True
        self._table_header()

    def row(self, row: dict[str, Any]) -> None:
        self._need(ROW_HEIGHT)
        if int((TOP - self.y) / ROW_HEIGHT) % 2 == 1:
            self.c.setFillColorRGB(0.97, 0.98, 0.99)
            self.c.rect(LEFT, self.y - ROW_HEIGHT + 2, USABLE_WIDTH, ROW_HEIGHT, fill=1, stroke=0)
            self.c.setFillColorRGB(0, 0, 0)
        self.c.setFont("Times-Roman", 6)
        for idx, column in enumerate(self.columns):
            x = LEFT + idx * self.col_width
            label = _clip_text(self.c, _text(row.get(column, "")), self.col_width - 2)
            self.c.drawString(x + 1, self.y - 8, label)
        self.y -= ROW_HEIGHT

    def finish(self) -> None:
        self._footer()
        self.c.save()
        self.spool.seek(0)


def render_pdf(
    *,
    title: str,
    scope: str,
    generated_at: str,
    timezone_label: str,
    filters: dict[str, Any],
    summary: dict[str, Any] | None,
    columns: Sequence[str],
    rows: Iterable[dict[str, Any]],
    disclaimer: str | None = None,
):
    spool = tempfile.SpooledTemporaryFile(max_size=2_000_000)
    writer = _PdfWriter(
        spool,
        title=title,
        scope=scope,
        generated_at=generated_at,
        timezone_label=timezone_label,
        columns=columns,
    )
    writer.paragraph(title, font="Times-Bold", size=16, leading=20)
    writer.paragraph(f"Scope: {scope}")
    writer.paragraph(f"Generated: {generated_at} ({timezone_label})")
    filter_text = ", ".join(f"{key}={value}" for key, value in filters.items() if value not in (None, "", False)) or "none"
    writer.paragraph(f"Filters: {filter_text}")
    writer.y -= 4
    if summary:
        writer.paragraph("Summary", font="Times-Bold", size=11, leading=14)
        for key, value in summary.items():
            writer.paragraph(f"{key}: {value}")
        writer.y -= 4
    if disclaimer:
        writer.paragraph(disclaimer, size=8)
        writer.y -= 4
    writer.start_table()
    any_rows = False
    for row in rows:
        any_rows = True
        writer.row(row)
    if not any_rows:
        writer.paragraph("No rows in authorized scope.")
    writer.finish()
    return spool


def pdf_response(filename: str, spool) -> StreamingResponse:
    name = safe_filename(filename)
    if not name.lower().endswith(".pdf"):
        name = f"{name}.pdf"

    def chunks():
        try:
            while True:
                block = spool.read(65536)
                if not block:
                    break
                yield block
        finally:
            spool.close()

    return StreamingResponse(
        chunks(),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )
