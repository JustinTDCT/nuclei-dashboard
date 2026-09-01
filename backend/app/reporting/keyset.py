"""Deterministic keyset iteration for report and compatibility CSV exports.

Export walks bounded batches with a seek predicate on the same ORDER BY
keys the former full-load exporter used. Do not use OFFSET. Do not keep
the whole result in the Session: serialize a batch, then expunge it.
Staff HistoryPage / preview offset pages stay in app.pagination.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator, Sequence
from typing import Any

from sqlalchemy import and_, or_

EXPORT_BATCH_SIZE = 200
EXPORT_BATCH_MAX = 2000


def export_batch_size() -> int:
    raw = os.environ.get("REPORT_EXPORT_BATCH_SIZE", str(EXPORT_BATCH_SIZE))
    try:
        value = int(raw)
    except ValueError:
        value = EXPORT_BATCH_SIZE
    return max(1, min(value, EXPORT_BATCH_MAX))


class KeyCol:
    """One ORDER BY column in a keyset. Last key must be unique (usually id)."""

    def __init__(
        self,
        column,
        *,
        descending: bool = False,
        value: Callable[[Any], Any] | None = None,
    ):
        self.column = column
        self.descending = descending
        self._value = value

    def read(self, row: Any) -> Any:
        if self._value is not None:
            return self._value(row)
        key = getattr(self.column, "key", None)
        if key and hasattr(row, key):
            return getattr(row, key)
        mapping = getattr(row, "_mapping", None)
        if mapping is not None and key in mapping:
            return mapping[key]
        raise AttributeError(f"cannot read keyset value for {self.column}")


def cursor_values(keys: Sequence[KeyCol], row: Any) -> tuple[Any, ...]:
    return tuple(key.read(row) for key in keys)


def seek_clause(keys: Sequence[KeyCol], cursor: Sequence[Any]):
    """Next-page predicate matching ORDER BY keys (mixed ASC/DESC).

    For (k0 ASC, k1 ASC) after (c0, c1):
      (k0 > c0) OR (k0 = c0 AND k1 > c1)
    DESC inverts that step's comparison.
    """
    if len(keys) != len(cursor):
        raise ValueError("keyset cursor length must match keys")
    clauses = []
    for index, key in enumerate(keys):
        step = key.column < cursor[index] if key.descending else key.column > cursor[index]
        prefix = [keys[prior].column == cursor[prior] for prior in range(index)]
        clauses.append(and_(*prefix, step) if prefix else step)
    return or_(*clauses)


def apply_seek(query, keys: Sequence[KeyCol], cursor: Sequence[Any] | None):
    if cursor is None:
        return query
    return query.filter(seek_clause(keys, cursor))


def iter_keyset_batches(
    query,
    keys: Sequence[KeyCol],
    *,
    session,
    batch_size: int | None = None,
) -> Iterator[list[Any]]:
    """Yield successive ORM/row batches. Caller serializes, then expunge_all()."""
    del session  # documented for callers; filtering does not mutate this session
    size = batch_size if batch_size is not None else export_batch_size()
    size = max(1, min(int(size), EXPORT_BATCH_MAX))
    cursor = None
    while True:
        page = apply_seek(query, keys, cursor).limit(size).all()
        if not page:
            return
        yield page
        if len(page) < size:
            return
        cursor = cursor_values(keys, page[-1])


def map_keyset(
    query,
    keys: Sequence[KeyCol],
    *,
    session,
    serialize_batch: Callable[[list[Any]], Sequence[Any]],
    batch_size: int | None = None,
) -> Iterator[Any]:
    for batch in iter_keyset_batches(query, keys, session=session, batch_size=batch_size):
        mapped = list(serialize_batch(batch))
        session.expunge_all()
        yield from mapped
