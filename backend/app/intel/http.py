"""Bounded outbound HTTP for intelligence sources.

TLS verification is mandatory. Secrets must never appear in logs.
"""

from __future__ import annotations

import logging
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable

log = logging.getLogger(__name__)

DEFAULT_CONNECT_TIMEOUT = 10
DEFAULT_READ_TIMEOUT = 45
DEFAULT_MAX_BYTES = 32 * 1024 * 1024
REDACT_HEADERS = frozenset({"apikey", "authorization", "x-api-key"})


class IntelligenceHttpError(Exception):
    def __init__(self, detail: str, *, status_code: int | None = None, permanent: bool = False):
        self.detail = detail
        self.status_code = status_code
        self.permanent = permanent
        super().__init__(detail)


@dataclass(frozen=True)
class HttpResponse:
    status_code: int
    body: bytes
    headers: dict[str, str]


FetchFn = Callable[..., HttpResponse]


def _safe_headers(headers: dict[str, str] | None) -> dict[str, str]:
    safe: dict[str, str] = {}
    for key, value in (headers or {}).items():
        if key.lower() in REDACT_HEADERS:
            safe[key] = "<redacted>"
        else:
            safe[key] = value
    return safe


def fetch_url(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: tuple[float, float] = (DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT),
    max_bytes: int = DEFAULT_MAX_BYTES,
    method: str = "GET",
) -> HttpResponse:
    request = urllib.request.Request(url, method=method, headers=headers or {})
    context = ssl.create_default_context()
    try:
        with urllib.request.urlopen(request, timeout=sum(timeout), context=context) as response:
            status = int(getattr(response, "status", 200) or 200)
            raw_headers = {str(key): str(value) for key, value in response.headers.items()}
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = response.read(64 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise IntelligenceHttpError(
                        f"Response from {url} exceeded {max_bytes} bytes",
                        status_code=status,
                        permanent=True,
                    )
                chunks.append(chunk)
            return HttpResponse(status_code=status, body=b"".join(chunks), headers=raw_headers)
    except IntelligenceHttpError:
        raise
    except urllib.error.HTTPError as exc:
        body = b""
        try:
            body = exc.read(4096)
        except Exception:  # noqa: BLE001
            body = b""
        permanent = exc.code is not None and 400 <= exc.code < 500 and exc.code != 429
        raise IntelligenceHttpError(
            f"HTTP {exc.code} from intelligence source",
            status_code=exc.code,
            permanent=permanent,
        ) from exc
    except Exception as exc:  # noqa: BLE001 — surface as a source failure
        raise IntelligenceHttpError(f"Intelligence request failed: {exc.__class__.__name__}") from exc


def request_with_retry(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: tuple[float, float] = (DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT),
    max_bytes: int = DEFAULT_MAX_BYTES,
    fetch: FetchFn = fetch_url,
    retries: int = 3,
    backoff_seconds: float = 2.0,
    sleep: Callable[[float], None] = time.sleep,
) -> HttpResponse:
    attempt = 0
    last_error: IntelligenceHttpError | None = None
    while attempt <= retries:
        try:
            log.info("Intelligence HTTP GET %s", url)
            response = fetch(url, headers=headers, timeout=timeout, max_bytes=max_bytes)
            if response.status_code == 429 or 500 <= response.status_code < 600:
                raise IntelligenceHttpError(
                    f"HTTP {response.status_code} from intelligence source",
                    status_code=response.status_code,
                    permanent=False,
                )
            if response.status_code >= 400:
                raise IntelligenceHttpError(
                    f"HTTP {response.status_code} from intelligence source",
                    status_code=response.status_code,
                    permanent=400 <= response.status_code < 500,
                )
            return response
        except IntelligenceHttpError as exc:
            last_error = exc
            if exc.permanent or attempt >= retries:
                log.warning(
                    "Intelligence HTTP failed url=%s status=%s headers=%s",
                    url,
                    exc.status_code,
                    _safe_headers(headers),
                )
                raise
            delay = backoff_seconds * (2**attempt)
            if exc.status_code == 429:
                delay = max(delay, 6.0)
            log.warning(
                "Retrying intelligence HTTP url=%s status=%s attempt=%s",
                url,
                exc.status_code,
                attempt + 1,
            )
            sleep(delay)
            attempt += 1
    assert last_error is not None
    raise last_error
