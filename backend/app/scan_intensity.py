"""Intensity presets, resolved numeric controls, and Admin caps.

Only ProjectDiscovery flags that the runtime actually passes are modeled:
Naabu: -rate, -c, -timeout (ms), -retries
httpx: -rl, -t, -timeout (s), -retries
Nuclei: -rl, -c, -timeout (s), -retries
"""

from __future__ import annotations

from typing import Any

from app.models import INTENSITY_CUSTOM, INTENSITY_HIGH, INTENSITY_LOW, INTENSITY_NORMAL, INTENSITY_PRESETS

INTENSITY_KEYS = (
    "naabu_rate",
    "naabu_concurrency",
    "naabu_timeout_ms",
    "naabu_retries",
    "httpx_rate",
    "httpx_threads",
    "httpx_timeout",
    "httpx_retries",
    "nuclei_rate",
    "nuclei_concurrency",
    "nuclei_timeout",
    "nuclei_retries",
)

PRESETS: dict[str, dict[str, int]] = {
    INTENSITY_LOW: {
        "naabu_rate": 400,
        "naabu_concurrency": 20,
        "naabu_timeout_ms": 800,
        "naabu_retries": 1,
        "httpx_rate": 50,
        "httpx_threads": 20,
        "httpx_timeout": 12,
        "httpx_retries": 1,
        "nuclei_rate": 50,
        "nuclei_concurrency": 10,
        "nuclei_timeout": 12,
        "nuclei_retries": 1,
    },
    INTENSITY_NORMAL: {
        "naabu_rate": 2500,
        "naabu_concurrency": 50,
        "naabu_timeout_ms": 400,
        "naabu_retries": 1,
        "httpx_rate": 150,
        "httpx_threads": 50,
        "httpx_timeout": 10,
        "httpx_retries": 1,
        "nuclei_rate": 150,
        "nuclei_concurrency": 25,
        "nuclei_timeout": 10,
        "nuclei_retries": 1,
    },
    INTENSITY_HIGH: {
        "naabu_rate": 4000,
        "naabu_concurrency": 75,
        "naabu_timeout_ms": 250,
        "naabu_retries": 0,
        "httpx_rate": 300,
        "httpx_threads": 80,
        "httpx_timeout": 8,
        "httpx_retries": 0,
        "nuclei_rate": 300,
        "nuclei_concurrency": 50,
        "nuclei_timeout": 8,
        "nuclei_retries": 0,
    },
}

DEFAULT_CAPS = {
    "scan_cap_naabu_rate": 5000,
    "scan_cap_naabu_concurrency": 100,
    "scan_cap_naabu_timeout_ms": 10000,
    "scan_cap_naabu_retries": 5,
    "scan_cap_httpx_rate": 500,
    "scan_cap_httpx_threads": 150,
    "scan_cap_httpx_timeout": 30,
    "scan_cap_httpx_retries": 5,
    "scan_cap_nuclei_rate": 500,
    "scan_cap_nuclei_concurrency": 100,
    "scan_cap_nuclei_timeout": 30,
    "scan_cap_nuclei_retries": 5,
}

CAP_KEY_FOR_CONTROL = {key: f"scan_cap_{key}" for key in INTENSITY_KEYS}


class IntensityError(ValueError):
    def __init__(self, detail: str):
        self.detail = detail
        super().__init__(detail)


def caps_from_settings(settings: dict[str, Any] | None) -> dict[str, int]:
    data = dict(DEFAULT_CAPS)
    if settings:
        for key, default in DEFAULT_CAPS.items():
            try:
                data[key] = int(settings.get(key, default))
            except (TypeError, ValueError) as exc:
                raise IntensityError(f"Invalid intensity cap {key}") from exc
            if data[key] < 0:
                raise IntensityError(f"Intensity cap {key} cannot be negative")
    return data


def resolve_intensity(raw: dict[str, Any] | None, caps: dict[str, int]) -> dict[str, Any]:
    data = dict(raw or {})
    preset = str(data.get("preset") or INTENSITY_NORMAL)
    if preset not in INTENSITY_PRESETS:
        raise IntensityError("Intensity preset must be low, normal, high, or custom")
    if preset == INTENSITY_CUSTOM:
        resolved = dict(PRESETS[INTENSITY_NORMAL])
        for key in INTENSITY_KEYS:
            if key in data and data[key] is not None:
                resolved[key] = _as_int(key, data[key])
    else:
        resolved = dict(PRESETS[preset])
    _assert_within_caps(resolved, caps)
    return {"preset": preset, "resolved": resolved}


def _as_int(key: str, value: Any) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise IntensityError(f"Invalid intensity value for {key}") from exc
    if number < 0:
        raise IntensityError(f"Intensity value {key} cannot be negative")
    return number


def _assert_within_caps(resolved: dict[str, int], caps: dict[str, int]) -> None:
    for key, value in resolved.items():
        cap_key = CAP_KEY_FOR_CONTROL[key]
        cap = caps.get(cap_key)
        if cap is not None and value > cap:
            raise IntensityError(f"{key}={value} exceeds Admin cap {cap}")


def assert_resolved_within_caps(resolved: dict[str, Any], caps: dict[str, int]) -> None:
    _assert_within_caps({key: int(resolved[key]) for key in INTENSITY_KEYS}, caps)
