"""Server-side PDF rendering from the canonical report dataset."""

from __future__ import annotations

import io
import tempfile
from collections.abc import Sequence
from typing import Any

from fastapi.responses import StreamingResponse
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.reporting.csv_export import safe_filename


def _style_sheet():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Meta", parent=styles["Normal"], fontSize=8, textColor=colors.HexColor("#334155")))
    styles.add(ParagraphStyle(name="Disclaimer", parent=styles["Normal"], fontSize=8, textColor=colors.HexColor("#7c2d12")))
    styles.add(ParagraphStyle(name="Cell", parent=styles["Normal"], fontSize=7, leading=9))
    return styles


def _header_footer(title: str, scope: str, generated: str, timezone_label: str):
    def _draw(canvas, doc):
        canvas.saveState()
        canvas.setFont("Times-Roman", 8)
        canvas.drawString(0.6 * inch, letter[1] - 0.4 * inch, "Nuclei Dashboard")
        canvas.drawRightString(letter[0] - 0.6 * inch, letter[1] - 0.4 * inch, title)
        canvas.setFont("Times-Roman", 7)
        canvas.drawString(0.6 * inch, 0.4 * inch, f"{scope}  ·  {generated}  ·  {timezone_label}")
        canvas.drawRightString(letter[0] - 0.6 * inch, 0.4 * inch, f"Page {doc.page}")
        canvas.restoreState()

    return _draw


def build_pdf_bytes(
    *,
    title: str,
    scope: str,
    generated_at: str,
    timezone_label: str,
    filters: dict[str, Any],
    summary: dict[str, Any] | None,
    columns: Sequence[str],
    rows: Sequence[dict[str, Any]],
    disclaimer: str | None = None,
) -> bytes:
    styles = _style_sheet()
    spool = tempfile.SpooledTemporaryFile(max_size=2_000_000)
    doc = SimpleDocTemplate(
        spool,
        pagesize=letter,
        leftMargin=0.55 * inch,
        rightMargin=0.55 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.6 * inch,
        title=title,
        author="Nuclei Dashboard",
    )
    story = [
        Paragraph(title, styles["Title"]),
        Paragraph(f"Scope: {scope}", styles["Meta"]),
        Paragraph(f"Generated: {generated_at} ({timezone_label})", styles["Meta"]),
        Paragraph(
            "Filters: "
            + (", ".join(f"{key}={value}" for key, value in filters.items() if value not in (None, "", False)) or "none"),
            styles["Meta"],
        ),
        Spacer(1, 8),
    ]
    if summary:
        story.append(Paragraph("Summary", styles["Heading2"]))
        for key, value in summary.items():
            if isinstance(value, dict):
                story.append(Paragraph(f"<b>{key}</b>: {value}", styles["Meta"]))
            else:
                story.append(Paragraph(f"<b>{key}</b>: {value}", styles["Meta"]))
        story.append(Spacer(1, 8))
    if disclaimer:
        story.append(Paragraph(disclaimer, styles["Disclaimer"]))
        story.append(Spacer(1, 8))
    if columns and rows:
        header = [Paragraph(str(col).replace("_", " "), styles["Cell"]) for col in columns]
        data = [header]
        for row in rows:
            data.append([Paragraph(str(row.get(col, "") or ""), styles["Cell"]) for col in columns])
        table = Table(data, repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Times-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 7),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ]
            )
        )
        story.append(table)
    elif not rows:
        story.append(Paragraph("No rows in authorized scope.", styles["Meta"]))
    doc.build(story, onFirstPage=_header_footer(title, scope, generated_at, timezone_label), onLaterPages=_header_footer(title, scope, generated_at, timezone_label))
    spool.seek(0)
    return spool.read()


def pdf_response(filename: str, content: bytes) -> StreamingResponse:
    name = safe_filename(filename)
    if not name.lower().endswith(".pdf"):
        name = f"{name}.pdf"
    return StreamingResponse(
        io.BytesIO(content),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )
