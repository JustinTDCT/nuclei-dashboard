from zoneinfo import ZoneInfo, ZoneInfoNotFoundError, available_timezones

from fastapi import HTTPException

FALLBACK_TIMEZONE = "UTC"


def is_valid_iana_timezone(value: str) -> bool:
    if not value or not isinstance(value, str):
        return False
    try:
        ZoneInfo(value)
    except (ZoneInfoNotFoundError, ValueError):
        return False
    return True


def validate_iana_timezone(value: str | None, *, allow_empty: bool = False) -> str | None:
    if value is None or not str(value).strip():
        if allow_empty:
            return None
        raise HTTPException(status_code=400, detail="Timezone is required")
    name = str(value).strip()
    if not is_valid_iana_timezone(name):
        raise HTTPException(status_code=400, detail=f"Invalid IANA timezone: {name}")
    return name


def coerce_timezone(value: str | None) -> str:
    if value and is_valid_iana_timezone(value):
        return value
    return FALLBACK_TIMEZONE


def effective_timezone(site_timezone: str | None, global_timezone: str | None) -> str:
    if site_timezone and is_valid_iana_timezone(site_timezone):
        return site_timezone
    return coerce_timezone(global_timezone)


def list_iana_timezones() -> list[str]:
    zones = set(available_timezones())
    zones.add(FALLBACK_TIMEZONE)
    return sorted(zones)
