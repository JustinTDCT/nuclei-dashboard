from __future__ import annotations

import os
import time
from typing import Any

import httpx


class ApiError(RuntimeError):
    pass


def _tls_verify() -> bool:
    return os.environ.get("TLS_VERIFY", "1") != "0"


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

    def complete(self, job_id: int, ok: bool = True, error: str | None = None) -> dict:
        params = {"ok": str(ok).lower()}
        if error:
            params["error"] = error
        return self._request("POST", f"/api/internal/scanner/jobs/{job_id}/complete", params=params).json()


def wait(seconds: float) -> None:
    time.sleep(seconds)


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}
