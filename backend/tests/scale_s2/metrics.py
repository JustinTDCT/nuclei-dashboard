"""SQL, timing, RSS, and payload metrics for S2A. No production hooks."""

from __future__ import annotations

import json
import resource
import sys
import time
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Iterator

from sqlalchemy import event
from sqlalchemy.orm import Session

_DML_PREFIXES = ("SELECT", "INSERT", "UPDATE", "DELETE")


def rss_bytes() -> int:
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        return int(usage)
    return int(usage) * 1024


def encoded_payload_bytes(rows: list[Any]) -> int:
    payload = []
    for row in rows:
        if hasattr(row, "model_dump"):
            payload.append(row.model_dump())
        else:
            payload.append(row)
    return len(json.dumps(payload, default=str, separators=(",", ":")).encode("utf-8"))


def classify_sql(statement: str) -> tuple[str, str]:
    compact = " ".join((statement or "").split())
    upper = compact.upper()
    op = "OTHER"
    for prefix in (*_DML_PREFIXES, "BEGIN", "COMMIT", "ROLLBACK"):
        if upper.startswith(prefix):
            op = prefix
            break
    table = ""
    if op == "SELECT":
        table = _token_after(upper, " FROM ")
    elif op == "INSERT":
        table = _token_after(upper, " INTO ")
    elif op == "UPDATE":
        table = _token_after(upper, "UPDATE ")
    elif op == "DELETE":
        table = _token_after(upper, " FROM ")
    table = table.split()[0] if table else ""
    table = table.strip("\"'`").split(".")[-1]
    return op, table.lower()


def _token_after(upper: str, marker: str) -> str:
    idx = upper.find(marker)
    if idx < 0:
        return ""
    return upper[idx + len(marker) :].lstrip()


@dataclass
class StageMetrics:
    name: str
    wall_ms: float = 0.0
    statements: int = 0
    selects: int = 0
    inserts: int = 0
    updates: int = 0
    deletes: int = 0
    flushes: int = 0
    peak_rss_bytes: int = 0
    transaction_ms: float = 0.0
    request_bytes: int = 0
    by_table: Counter = field(default_factory=Counter)


@dataclass
class IngestMetrics:
    path: str
    workload: str
    stages: list[StageMetrics] = field(default_factory=list)
    by_table: Counter = field(default_factory=Counter)
    samples: list[dict[str, str]] = field(default_factory=list)
    peak_api_rss_bytes: int = 0
    peak_agent_rss_bytes: int = 0
    agent_held_row_count: int = 0
    device_request_bytes: int = 0
    finding_request_bytes: int = 0
    coverage_request_bytes: int = 0
    largest_transaction_ms: float = 0.0
    wall_ms: float = 0.0
    prefetch_identifier_rows: int = 0
    prefetch_address_rows: int = 0
    prefetch_device_rows: int = 0

    @property
    def select_count(self) -> int:
        return sum(stage.selects for stage in self.stages)

    @property
    def insert_count(self) -> int:
        return sum(stage.inserts for stage in self.stages)

    @property
    def update_count(self) -> int:
        return sum(stage.updates for stage in self.stages)

    @property
    def delete_count(self) -> int:
        return sum(stage.deletes for stage in self.stages)

    @property
    def flush_count(self) -> int:
        return sum(stage.flushes for stage in self.stages)

    @property
    def sql_statement_count(self) -> int:
        return sum(stage.statements for stage in self.stages)

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "workload": self.workload,
            "wall_ms": round(self.wall_ms, 3),
            "sql_statement_count": self.sql_statement_count,
            "select_count": self.select_count,
            "insert_count": self.insert_count,
            "update_count": self.update_count,
            "delete_count": self.delete_count,
            "flush_count": self.flush_count,
            "peak_api_rss_bytes": self.peak_api_rss_bytes,
            "peak_agent_rss_bytes": self.peak_agent_rss_bytes,
            "agent_held_row_count": self.agent_held_row_count,
            "device_request_bytes": self.device_request_bytes,
            "finding_request_bytes": self.finding_request_bytes,
            "coverage_request_bytes": self.coverage_request_bytes,
            "prefetch_identifier_rows": self.prefetch_identifier_rows,
            "prefetch_address_rows": self.prefetch_address_rows,
            "prefetch_device_rows": self.prefetch_device_rows,
            "largest_transaction_ms": round(self.largest_transaction_ms, 3),
            "stages": [
                {
                    "name": stage.name,
                    "wall_ms": round(stage.wall_ms, 3),
                    "statements": stage.statements,
                    "selects": stage.selects,
                    "inserts": stage.inserts,
                    "updates": stage.updates,
                    "deletes": stage.deletes,
                    "flushes": stage.flushes,
                    "peak_rss_bytes": stage.peak_rss_bytes,
                    "transaction_ms": round(stage.transaction_ms, 3),
                    "request_bytes": stage.request_bytes,
                }
                for stage in self.stages
            ],
            "sql_by_table": [
                {"op": op, "table": table, "count": count}
                for (op, table), count in self.by_table.most_common(40)
            ],
            "stage_sql_by_table": {
                stage.name: [
                    {"op": op, "table": table, "count": count}
                    for (op, table), count in stage.by_table.most_common(20)
                ]
                for stage in self.stages
            },
            "hot_samples": self.samples[:20],
        }


class SqlProbe:
    """Session-scoped SQL/flush/transaction probe. Attach only around ingest."""

    def __init__(self, session: Session):
        self.session = session
        self.statements = 0
        self.selects = 0
        self.inserts = 0
        self.updates = 0
        self.deletes = 0
        self.flushes = 0
        self.by_table: Counter = Counter()
        self.samples: list[dict[str, str]] = []
        self._tx_started: float | None = None
        self.transaction_ms = 0.0
        self._attached = False

    def attach(self) -> None:
        if self._attached:
            return
        event.listen(self.session, "after_flush", self._on_flush)
        event.listen(self.session, "after_begin", self._on_begin)
        event.listen(self.session, "after_commit", self._on_commit)
        event.listen(self.session, "after_rollback", self._on_rollback)
        bind = self.session.get_bind()
        event.listen(bind, "before_cursor_execute", self._on_execute)
        self._attached = True

    def detach(self) -> None:
        if not self._attached:
            return
        event.remove(self.session, "after_flush", self._on_flush)
        event.remove(self.session, "after_begin", self._on_begin)
        event.remove(self.session, "after_commit", self._on_commit)
        event.remove(self.session, "after_rollback", self._on_rollback)
        bind = self.session.get_bind()
        event.remove(bind, "before_cursor_execute", self._on_execute)
        self._attached = False

    def snapshot_stage(self) -> dict[str, int]:
        return {
            "statements": self.statements,
            "selects": self.selects,
            "inserts": self.inserts,
            "updates": self.updates,
            "deletes": self.deletes,
            "flushes": self.flushes,
        }

    def _on_execute(self, _conn, _cursor, statement, _parameters, _context, _executemany) -> None:
        op, table = classify_sql(statement or "")
        self.statements += 1
        if op == "SELECT":
            self.selects += 1
        elif op == "INSERT":
            self.inserts += 1
        elif op == "UPDATE":
            self.updates += 1
        elif op == "DELETE":
            self.deletes += 1
        if table:
            self.by_table[(op, table)] += 1
        if len(self.samples) < 80:
            self.samples.append({"op": op, "table": table, "sql": " ".join((statement or "").split())[:240]})

    def _on_flush(self, _session, _ctx) -> None:
        self.flushes += 1

    def _on_begin(self, _session, _transaction, _connection) -> None:
        self._tx_started = time.perf_counter()

    def _on_commit(self, _session) -> None:
        if self._tx_started is None:
            return
        self.transaction_ms = max(self.transaction_ms, (time.perf_counter() - self._tx_started) * 1000)
        self._tx_started = None

    def _on_rollback(self, _session) -> None:
        self._tx_started = None


class MetricsCollector:
    def __init__(self, *, path: str, workload: str, session: Session):
        self.metrics = IngestMetrics(path=path, workload=workload)
        self.probe = SqlProbe(session)
        self._wall_started = 0.0

    def start(self) -> None:
        self.probe.attach()
        self._wall_started = time.perf_counter()
        self.metrics.peak_api_rss_bytes = rss_bytes()
        self._stage_table_before = Counter()

    def finish(self) -> IngestMetrics:
        self.metrics.wall_ms = (time.perf_counter() - self._wall_started) * 1000
        self.metrics.peak_api_rss_bytes = max(self.metrics.peak_api_rss_bytes, rss_bytes())
        self.metrics.by_table = self.probe.by_table
        self.metrics.samples = list(self.probe.samples)
        self.metrics.largest_transaction_ms = max(
            [self.probe.transaction_ms, *(stage.transaction_ms for stage in self.metrics.stages)],
            default=0.0,
        )
        self.probe.detach()
        return self.metrics

    @contextmanager
    def stage(self, name: str, *, request_bytes: int = 0) -> Iterator[StageMetrics]:
        before = self.probe.snapshot_stage()
        tables_before = Counter(self.probe.by_table)
        tx_before = self.probe.transaction_ms
        started = time.perf_counter()
        row = StageMetrics(name=name, request_bytes=request_bytes)
        try:
            yield row
        finally:
            after = self.probe.snapshot_stage()
            row.wall_ms = (time.perf_counter() - started) * 1000
            row.statements = after["statements"] - before["statements"]
            row.selects = after["selects"] - before["selects"]
            row.inserts = after["inserts"] - before["inserts"]
            row.updates = after["updates"] - before["updates"]
            row.deletes = after["deletes"] - before["deletes"]
            row.flushes = after["flushes"] - before["flushes"]
            measured_tx = max(0.0, self.probe.transaction_ms - tx_before)
            row.transaction_ms = measured_tx if measured_tx > 1.0 else row.wall_ms
            row.peak_rss_bytes = rss_bytes()
            row.by_table = self.probe.by_table - tables_before
            self.metrics.peak_api_rss_bytes = max(self.metrics.peak_api_rss_bytes, row.peak_rss_bytes)
            self.metrics.stages.append(row)
