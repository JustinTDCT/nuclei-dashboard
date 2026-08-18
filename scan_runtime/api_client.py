from __future__ import annotations

import os
import time
from typing import Any

import httpx


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


def wait(seconds: float) -> None:
    time.sleep(seconds)


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}
