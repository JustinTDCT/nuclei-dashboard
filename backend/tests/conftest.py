"""Test environment bootstrap.

Starts an isolated PostgreSQL (Docker) unless TEST_DATABASE_URL is set.
Never uses the application default database URL.
"""

from __future__ import annotations

import os
import subprocess
import time
from collections.abc import Iterator

import pytest
from sqlalchemy import create_engine, text

_CONTAINER_NAME = "nuclei-phase0-test-pg"
_DEFAULT_TEST_URL = "postgresql://nuclei:nuclei@127.0.0.1:55432/nuclei_test"
_STARTED_CONTAINER = False
POSTGRES_AVAILABLE = False
POSTGRES_SKIP_REASON = "PostgreSQL is not available for Phase 0 tests"


def _wait_ready(url: str, timeout: float = 45.0) -> None:
    engine = create_engine(url, pool_pre_ping=True)
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            engine.dispose()
            return
        except Exception as exc:  # noqa: BLE001 — retry until timeout
            last = exc
            time.sleep(0.5)
    engine.dispose()
    raise RuntimeError(f"PostgreSQL not ready at {url}: {last}")


def _start_postgres() -> str:
    global _STARTED_CONTAINER
    url = os.environ.get("TEST_DATABASE_URL", "").strip()
    if url:
        _wait_ready(url)
        return url

    subprocess.run(["docker", "rm", "-f", _CONTAINER_NAME], check=False, capture_output=True)
    result = subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            _CONTAINER_NAME,
            "-e",
            "POSTGRES_USER=nuclei",
            "-e",
            "POSTGRES_PASSWORD=nuclei",
            "-e",
            "POSTGRES_DB=nuclei_test",
            "-p",
            "55432:5432",
            "postgres:16-alpine",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    _STARTED_CONTAINER = True
    if not result.stdout.strip():
        raise RuntimeError("docker run did not return a container id")
    _wait_ready(_DEFAULT_TEST_URL)
    return _DEFAULT_TEST_URL


try:
    _url = _start_postgres()
    os.environ["DATABASE_URL"] = _url
    POSTGRES_AVAILABLE = True
    POSTGRES_SKIP_REASON = ""
except Exception as exc:  # noqa: BLE001 — tests skip instead of hitting prod DB
    os.environ["DATABASE_URL"] = "postgresql://nuclei:nuclei@127.0.0.1:1/nuclei_phase0_unused"
    POSTGRES_AVAILABLE = False
    POSTGRES_SKIP_REASON = f"PostgreSQL is not available for Phase 0 tests: {exc}"

os.environ.setdefault("SECRET_KEY", "phase0-test-secret-not-for-production")
os.environ.setdefault("ADMIN_USERNAME", "admin")
os.environ.setdefault("ADMIN_PASSWORD", "test-admin-pass")
os.environ.setdefault("ADMIN_EMAIL", "admin@localhost")
os.environ.setdefault("AGENT_TLS_VERIFY", "1")

requires_postgres = pytest.mark.skipif(not POSTGRES_AVAILABLE, reason=POSTGRES_SKIP_REASON)


def pytest_sessionfinish(session, exitstatus) -> None:  # noqa: ARG001
    if _STARTED_CONTAINER:
        subprocess.run(["docker", "rm", "-f", _CONTAINER_NAME], check=False, capture_output=True)


@pytest.fixture
def reset_db() -> Iterator[None]:
    if not POSTGRES_AVAILABLE:
        pytest.skip(POSTGRES_SKIP_REASON)
    from app.database import engine

    engine.dispose()
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    engine.dispose()
    yield
    engine.dispose()
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    engine.dispose()
