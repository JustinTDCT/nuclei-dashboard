"""Offset pagination for staff collection GETs.

S3D uses the existing HistoryPage envelope. This is not keyset iteration;
report and compatibility CSV exports use app.reporting.keyset.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from app.schemas import HistoryPage

LIST_PAGE_DEFAULT = 50
LIST_PAGE_MAX = 200


def paginate_query(query, *, order_by, limit: int, offset: int):
    total = query.count()
    clauses = order_by if isinstance(order_by, (tuple, list)) else (order_by,)
    rows = query.order_by(None).order_by(*clauses).offset(offset).limit(limit).all()
    return total, rows


def as_page(
    rows: Sequence[Any],
    *,
    total: int,
    limit: int,
    offset: int,
    serialize: Callable[[Any], Any] | None = None,
) -> HistoryPage:
    items = [serialize(row) for row in rows] if serialize is not None else list(rows)
    return HistoryPage(items=items, total=total, limit=limit, offset=offset)
