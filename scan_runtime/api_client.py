from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

import httpx

ARTIFACT_UPLOAD_TIMEOUT = 300.0
ARTIFACT_UPLOAD_RETRIES = 3


class ApiError(RuntimeError):
    pass


def _tls_verify() -> bool | str:
    """TLS verification is on by default.

    TLS_VERIFY=0 disables verification (development opt-out only).
    TLS_VERIFY=1 (default) uses the system trust store.
    Any other non-empty value is treated as a CA bundle path for an
    internal/private CA. TLS_CA_FILE is an equivalent explicit alias.
    """
    ca_file = os.environ.get("TLS_CA_FILE", "").strip()
    if ca_file:
        return ca_file
    value = os.environ.get("TLS_VERIFY", "1").strip()
    if value in {"0", "false", "False", "no", "off"}:
        return False
    if value in {"", "1", "true", "True", "yes", "on"}:
        return True
    return value


class CentralClient:
    def __init__(self, base_url: str, timeout: float = 30.0):
        self.base = base_url.rstrip("/")
        self.timeout = timeout

    def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        url = f"{self.base}{path}"
        kwargs.setdefault("verify", _tls_verify())
        try:
            response = httpx.request(method, url, timeout=self.timeout, **kwargs)
        except httpx.HTTPError as exc:
            raise ApiError(str(exc)) from exc
        if response.status_code >= 400:
            raise ApiError(f"{method} {path} -> {response.status_code} {response.text}")
        return response

    def enroll(self, uuid: str, secret: str, public_key: str, hostname: str, container_id: str) -> dict:
        return self._request(
            "POST",
            "/api/agent/enroll",
            json={
                "uuid": uuid,
                "enrollment_secret": secret,
                "public_key": public_key,
                "hostname": hostname,
                "container_id": container_id,
            },
        ).json()

    def challenge(self, uuid: str) -> str:
        return self._request("GET", "/api/agent/challenge", params={"uuid": uuid}).json()["nonce"]

    def token(self, uuid: str, nonce: str, signature: str) -> dict:
        return self._request(
            "POST",
            "/api/agent/token",
            json={"uuid": uuid, "nonce": nonce, "signature": signature},
        ).json()

    def heartbeat(self, token: str) -> dict:
        return self._request("POST", "/api/agent/heartbeat", headers=_auth(token)).json()

    def jobs(self, token: str) -> list[dict[str, Any]]:
        return self._request("GET", "/api/agent/jobs", headers=_auth(token)).json()

    def start(self, token: str, job_id: int) -> dict:
        return self._request("POST", f"/api/agent/jobs/{job_id}/start", headers=_auth(token)).json()

    def devices(self, token: str, job_id: int, devices: list[dict]) -> dict:
        return self._request(
            "POST", f"/api/agent/jobs/{job_id}/devices", headers=_auth(token), json=devices
        ).json()

    def findings(self, token: str, job_id: int, findings: list[dict]) -> dict:
        return self._request(
            "POST", f"/api/agent/jobs/{job_id}/findings", headers=_auth(token), json=findings
        ).json()

    def detector_coverage(self, token: str, job_id: int, payload: dict[str, Any]) -> dict:
        return self._request(
            "POST",
            f"/api/agent/jobs/{job_id}/detector-coverage",
            headers=_auth(token),
            json=payload,
        ).json()

    def provenance(self, token: str, job_id: int, payload: dict[str, Any]) -> dict:
        return self._request(
            "POST", f"/api/agent/jobs/{job_id}/provenance", headers=_auth(token), json=payload
        ).json()

    def complete(self, token: str, job_id: int, ok: bool = True, error: str | None = None) -> dict:
        params = {"ok": str(ok).lower()}
        if error:
            params["error"] = error
        return self._request(
            "POST", f"/api/agent/jobs/{job_id}/complete", headers=_auth(token), params=params
        ).json()

    def upload_artifact(self, token: str, job_id: int, artifact: dict[str, Any]) -> dict:
        return _upload_artifact(
            self._request,
            f"/api/agent/jobs/{job_id}/artifacts",
            artifact,
            headers=_auth(token),
        )


class ScannerClient:
    def __init__(self, base_url: str, token: str, timeout: float = 30.0):
        self.base = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        return {"X-Scanner-Token": self.token}

    def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        url = f"{self.base}{path}"
        headers = {**self._headers(), **(kwargs.pop("headers", {}) or {})}
        try:
            response = httpx.request(method, url, timeout=self.timeout, headers=headers, **kwargs)
        except httpx.HTTPError as exc:
            raise ApiError(str(exc)) from exc
        if response.status_code >= 400:
            raise ApiError(f"{method} {path} -> {response.status_code} {response.text}")
        return response

    def jobs(self) -> list[dict[str, Any]]:
        return self._request("GET", "/api/internal/scanner/jobs").json()

    def start(self, job_id: int) -> dict:
        return self._request("POST", f"/api/internal/scanner/jobs/{job_id}/start").json()

    def devices(self, job_id: int, devices: list[dict]) -> dict:
        return self._request("POST", f"/api/internal/scanner/jobs/{job_id}/devices", json=devices).json()

    def findings(self, job_id: int, findings: list[dict]) -> dict:
        return self._request("POST", f"/api/internal/scanner/jobs/{job_id}/findings", json=findings).json()

    def detector_coverage(self, job_id: int, payload: dict[str, Any]) -> dict:
        return self._request("POST", f"/api/internal/scanner/jobs/{job_id}/detector-coverage", json=payload).json()

    def provenance(self, job_id: int, payload: dict[str, Any]) -> dict:
        return self._request("POST", f"/api/internal/scanner/jobs/{job_id}/provenance", json=payload).json()

    def complete(self, job_id: int, ok: bool = True, error: str | None = None) -> dict:
        params = {"ok": str(ok).lower()}
        if error:
            params["error"] = error
        return self._request("POST", f"/api/internal/scanner/jobs/{job_id}/complete", params=params).json()

    def upload_artifact(self, job_id: int, artifact: dict[str, Any]) -> dict:
        return _upload_artifact(self._request, f"/api/internal/scanner/jobs/{job_id}/artifacts", artifact)


def wait(seconds: float) -> None:
    time.sleep(seconds)


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _transient_upload_error(exc: ApiError) -> bool:
    text = str(exc)
    return any(token in text for token in (" 500 ", " 502 ", " 503 ", " 504 ", "timeout", "Timeout", "connect"))


def _upload_artifact(request_fn, path: str, artifact: dict[str, Any], *, headers: dict[str, str] | None = None) -> dict:
    file_path = Path(artifact["path"])
    last_error: ApiError | None = None
    for attempt in range(ARTIFACT_UPLOAD_RETRIES):
        try:
            with file_path.open("rb") as handle:
                files = {"file": (file_path.name, handle, "application/gzip")}
                data = {
                    "artifact_key": artifact["artifact_key"],
                    "stage": artifact["stage"],
                    "tool": artifact["tool"],
                    "media_type": artifact.get("media_type") or "application/x-ndjson",
                    "content_encoding": artifact.get("content_encoding") or "gzip",
                    "provenance": json.dumps(artifact.get("provenance") or {}, default=str),
                }
                kwargs: dict[str, Any] = {
                    "files": files,
                    "data": data,
                    "timeout": ARTIFACT_UPLOAD_TIMEOUT,
                }
                if headers:
                    kwargs["headers"] = headers
                return request_fn("POST", path, **kwargs).json()
        except ApiError as exc:
            last_error = exc
            if attempt >= ARTIFACT_UPLOAD_RETRIES - 1 or not _transient_upload_error(exc):
                raise
            time.sleep(1.0 * (attempt + 1))
    raise last_error or ApiError("artifact upload failed")
