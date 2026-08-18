"""Scan schedules with IANA timezones and DST-safe next occurrence."""

from __future__ import annotations

from calendar import monthrange
from datetime import datetime, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo

from app.models import (
    SCHEDULE_CRON,
    SCHEDULE_DAILY,
    SCHEDULE_LEGACY_INTERVAL,
    SCHEDULE_MANUAL,
    SCHEDULE_MONTHLY,
    SCHEDULE_TYPES,
    SCHEDULE_WEEKLY,
)
from app.timezones import coerce_timezone, is_valid_iana_timezone

_CRON_RANGES = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 6))


class ScheduleError(ValueError):
    def __init__(self, detail: str):
        self.detail = detail
        super().__init__(detail)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def normalize_schedule_config(
    raw: dict[str, Any] | None,
    *,
    interval_minutes: int | None = None,
    allow_legacy: bool = True,
) -> dict[str, Any]:
    data = dict(raw or {})
    if not data:
        if interval_minutes and interval_minutes > 0:
            if not allow_legacy:
                raise ScheduleError("New scans cannot use legacy interval schedules")
            return {"type": SCHEDULE_LEGACY_INTERVAL, "interval_minutes": int(interval_minutes)}
        return {"type": SCHEDULE_MANUAL}
    schedule_type = str(data.get("type") or SCHEDULE_MANUAL)
    if schedule_type not in SCHEDULE_TYPES:
        raise ScheduleError("Invalid schedule type")
    if schedule_type == SCHEDULE_LEGACY_INTERVAL:
        if not allow_legacy:
            raise ScheduleError("New scans cannot use legacy interval schedules")
        minutes = int(data.get("interval_minutes") or interval_minutes or 0)
        if minutes <= 0:
            raise ScheduleError("Legacy interval requires interval_minutes > 0")
        return {"type": SCHEDULE_LEGACY_INTERVAL, "interval_minutes": minutes}
    if schedule_type == SCHEDULE_MANUAL:
        return {"type": SCHEDULE_MANUAL}
    hour = _int_field(data.get("hour"), 0, 23, "hour")
    minute = _int_field(data.get("minute"), 0, 59, "minute")
    if schedule_type == SCHEDULE_DAILY:
        return {"type": SCHEDULE_DAILY, "hour": hour, "minute": minute}
    if schedule_type == SCHEDULE_WEEKLY:
        weekday = _int_field(data.get("weekday"), 0, 6, "weekday")
        return {"type": SCHEDULE_WEEKLY, "weekday": weekday, "hour": hour, "minute": minute}
    if schedule_type == SCHEDULE_MONTHLY:
        day = _int_field(data.get("day"), 1, 31, "day")
        return {"type": SCHEDULE_MONTHLY, "day": day, "hour": hour, "minute": minute}
    expression = str(data.get("expression") or "").strip()
    parse_cron(expression)
    return {"type": SCHEDULE_CRON, "expression": expression}


def _int_field(value: Any, minimum: int, maximum: int, name: str) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ScheduleError(f"Invalid {name}") from exc
    if number < minimum or number > maximum:
        raise ScheduleError(f"{name} must be between {minimum} and {maximum}")
    return number


def parse_cron(expression: str) -> list[set[int]]:
    parts = expression.split()
    if len(parts) != 5:
        raise ScheduleError("Cron expression must have 5 fields: minute hour day month weekday")
    parsed: list[set[int]] = []
    for part, (lo, hi) in zip(parts, _CRON_RANGES, strict=True):
        parsed.append(_parse_cron_field(part, lo, hi))
    return parsed


def _parse_cron_field(field: str, lo: int, hi: int) -> set[int]:
    values: set[int] = set()
    for chunk in field.split(","):
        if not chunk:
            raise ScheduleError(f"Invalid cron field: {field}")
        step = 1
        base = chunk
        if "/" in chunk:
            base, step_raw = chunk.split("/", 1)
            if not step_raw.isdigit() or int(step_raw) <= 0:
                raise ScheduleError(f"Invalid cron step: {chunk}")
            step = int(step_raw)
        if base in {"*", "?"}:
            start, end = lo, hi
        elif "-" in base:
            left, right = base.split("-", 1)
            if not left.isdigit() or not right.isdigit():
                raise ScheduleError(f"Invalid cron range: {chunk}")
            start, end = int(left), int(right)
        elif base.isdigit():
            start = end = int(base)
        else:
            raise ScheduleError(f"Invalid cron field: {chunk}")
        if start < lo or end > hi or start > end:
            raise ScheduleError(f"Cron value out of range: {chunk}")
        values.update(range(start, end + 1, step))
    if not values:
        raise ScheduleError(f"Cron field matched nothing: {field}")
    return values


def next_occurrence(
    schedule: dict[str, Any],
    *,
    tz_name: str,
    after: datetime,
) -> datetime | None:
    if schedule.get("type") == SCHEDULE_MANUAL:
        return None
    zone = ZoneInfo(coerce_timezone(tz_name))
    after_utc = after if after.tzinfo else after.replace(tzinfo=timezone.utc)
    after_local = after_utc.astimezone(zone)
    schedule_type = schedule["type"]
    if schedule_type == SCHEDULE_LEGACY_INTERVAL:
        minutes = int(schedule["interval_minutes"])
        return after_utc + timedelta(minutes=minutes)
    if schedule_type == SCHEDULE_DAILY:
        return _next_clock(after_local, zone, hour=schedule["hour"], minute=schedule["minute"])
    if schedule_type == SCHEDULE_WEEKLY:
        return _next_weekly(after_local, zone, schedule["weekday"], schedule["hour"], schedule["minute"])
    if schedule_type == SCHEDULE_MONTHLY:
        return _next_monthly(after_local, zone, schedule["day"], schedule["hour"], schedule["minute"])
    fields = parse_cron(schedule["expression"])
    return _next_cron(after_local, zone, fields)


def _aware_local(year: int, month: int, day: int, hour: int, minute: int, zone: ZoneInfo) -> datetime | None:
    try:
        return datetime(year, month, day, hour, minute, tzinfo=zone)
    except ValueError:
        return None


def _next_clock(after_local: datetime, zone: ZoneInfo, *, hour: int, minute: int) -> datetime:
    candidate = _aware_local(after_local.year, after_local.month, after_local.day, hour, minute, zone)
    if candidate is None or candidate <= after_local:
        nxt = (after_local + timedelta(days=1)).date()
        candidate = _aware_local(nxt.year, nxt.month, nxt.day, hour, minute, zone)
        if candidate is None:
            nxt = nxt + timedelta(days=1)
            candidate = datetime(nxt.year, nxt.month, nxt.day, hour, minute, tzinfo=zone)
    return candidate.astimezone(timezone.utc)


def _next_weekly(after_local: datetime, zone: ZoneInfo, weekday: int, hour: int, minute: int) -> datetime:
    days_ahead = (weekday - after_local.weekday()) % 7
    probe = after_local
    for _ in range(14):
        day = (probe + timedelta(days=days_ahead if probe is after_local else 0)).date()
        if probe is not after_local:
            day = probe.date()
        candidate = _aware_local(day.year, day.month, day.day, hour, minute, zone)
        if candidate is not None and candidate > after_local and candidate.weekday() == weekday:
            return candidate.astimezone(timezone.utc)
        probe = (probe + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        days_ahead = (weekday - probe.weekday()) % 7
        probe = probe + timedelta(days=days_ahead)
    raise ScheduleError("Unable to compute weekly occurrence")


def _next_monthly(after_local: datetime, zone: ZoneInfo, day: int, hour: int, minute: int) -> datetime:
    year, month = after_local.year, after_local.month
    for _ in range(36):
        last = monthrange(year, month)[1]
        use_day = min(day, last)
        candidate = _aware_local(year, month, use_day, hour, minute, zone)
        if candidate is not None and candidate > after_local:
            return candidate.astimezone(timezone.utc)
        if month == 12:
            year, month = year + 1, 1
        else:
            month += 1
    raise ScheduleError("Unable to compute monthly occurrence")


def _next_cron(after_local: datetime, zone: ZoneInfo, fields: list[set[int]]) -> datetime:
    cursor = (after_local.replace(second=0, microsecond=0) + timedelta(minutes=1)).replace(tzinfo=None)
    minutes, hours, days, months, weekdays = fields
    for _ in range(366 * 24 * 60):
        if (
            cursor.month in months
            and cursor.day in days
            and cursor.hour in hours
            and cursor.minute in minutes
            and cursor.weekday() in weekdays
        ):
            candidate = _aware_local(cursor.year, cursor.month, cursor.day, cursor.hour, cursor.minute, zone)
            if candidate is not None and candidate > after_local:
                return candidate.astimezone(timezone.utc)
        cursor += timedelta(minutes=1)
    raise ScheduleError("Unable to compute cron occurrence")


def next_future_after_catchup(
    schedule: dict[str, Any],
    *,
    tz_name: str,
    now: datetime,
    due: datetime,
) -> datetime | None:
    """Advance past the due occurrence so downtime creates at most one catch-up run."""
    nxt = next_occurrence(schedule, tz_name=tz_name, after=due)
    while nxt is not None and nxt <= now:
        nxt = next_occurrence(schedule, tz_name=tz_name, after=nxt)
    return nxt


def effective_scan_timezone(site_timezone: str | None, global_timezone: str | None, scope: str) -> str:
    if scope == "lan" and site_timezone and is_valid_iana_timezone(site_timezone):
        return site_timezone
    return coerce_timezone(global_timezone)
