import os
import random
import socket
import threading
import time
import traceback
from typing import Any, Callable

from api_client import ApiError, CentralClient
from job_finish import finish_pipeline_run
from keys import load_or_create_keypair, sign
from runner import PipelineError, run_pipeline
from artifact_io import JobControl, cleanup_staging, use_job_control
from tool_versions import collect_runtime_inventory

INVENTORY_REFRESH_SECONDS = 3600
CONTROL_INTERVAL_SECONDS = 15.0
CONTROL_JITTER_SECONDS = 5.0
_inventory_cache: dict | None = None
_inventory_cached_at = 0.0
_last_sent_inventory: dict | None = None
_last_inventory_sent_at = 0.0


def cached_runtime_inventory() -> dict:
    global _inventory_cache, _inventory_cached_at
    now = time.time()
    if _inventory_cache is None or now - _inventory_cached_at >= INVENTORY_REFRESH_SECONDS:
        _inventory_cache = collect_runtime_inventory()
        _inventory_cached_at = now
    return _inventory_cache


def inventory_for_heartbeat(*, now: float | None = None, force: bool = False) -> dict | None:
    """Send inventory on startup, on change, and on the periodic refresh — not every beat."""
    global _last_sent_inventory, _last_inventory_sent_at
    current = cached_runtime_inventory()
    current_ts = time.time() if now is None else now
    if (
        force
        or _last_sent_inventory is None
        or current != _last_sent_inventory
        or current_ts - _last_inventory_sent_at >= INVENTORY_REFRESH_SECONDS
    ):
        _last_sent_inventory = current
        _last_inventory_sent_at = current_ts
        return current
    return None


def env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if not value:
        raise SystemExit(f"Missing required environment variable {name}")
    return value


def authenticate(client: CentralClient, uuid: str, secret: str, public_hex: str, private) -> str | None:
    hostname = socket.gethostname()
    container_id = os.environ.get("HOSTNAME", hostname)
    client.enroll(uuid, secret, public_hex, hostname, container_id)
    nonce = client.challenge(uuid)
    result = client.token(uuid, nonce, sign(private, nonce))
    if not result.get("approved"):
        print(f"Waiting for approval (status={result.get('status')})", flush=True)
        return None
    return result["access_token"]


def jittered_interval(base: float = CONTROL_INTERVAL_SECONDS, jitter: float = CONTROL_JITTER_SECONDS) -> float:
    span = max(0.0, jitter)
    return base + random.uniform(0.0, span)


def run_job(client: CentralClient, token: str, job: dict, refresh_token, cancel_event=None) -> None:
    job_id = job["job_id"]
    print(f"Starting job {job_id}", flush=True)
    started = client.start(token, job_id)
    result: dict = {"artifacts": [], "staging_dir": None}
    control = JobControl.from_job(started, cancel_event=cancel_event)
    try:
        with use_job_control(control):
            result = run_pipeline(started, log=lambda message: print(message, flush=True), control=control)
        token = refresh_token() or token
        finish_pipeline_run(
            result=result,
            upload=lambda artifact: client.upload_artifact(token, job_id, artifact),
            complete=lambda ok, error, raw_evidence=None: client.complete(
                token, job_id, ok=ok, error=error, raw_evidence=raw_evidence
            ),
            provenance_fn=lambda payload: client.provenance(token, job_id, payload),
            devices_fn=lambda devices: client.devices(token, job_id, devices),
            coverage_fn=lambda payload: client.detector_coverage(token, job_id, payload),
            findings_fn=lambda findings: client.findings(token, job_id, findings),
        )
        print(f"Finished job {job_id}", flush=True)
    except PipelineError as exc:
        token = refresh_token() or token
        result = exc.as_result()
        try:
            finish_pipeline_run(
                result=result,
                upload=lambda artifact: client.upload_artifact(token, job_id, artifact),
                complete=lambda ok, error, raw_evidence=None: client.complete(
                    token, job_id, ok=ok, error=error, raw_evidence=raw_evidence
                ),
                provenance_fn=lambda payload: client.provenance(token, job_id, payload),
                devices_fn=lambda devices: client.devices(token, job_id, devices),
                coverage_fn=lambda payload: client.detector_coverage(token, job_id, payload),
                findings_fn=lambda findings: client.findings(token, job_id, findings),
                pipeline_error=str(exc),
            )
        except Exception as persist_exc:
            traceback.print_exc()
            cleanup_staging(result.get("staging_dir"))
            try:
                client.complete(token, job_id, ok=False, error=str(persist_exc))
            except ApiError:
                pass
    except Exception as exc:
        traceback.print_exc()
        cleanup_staging(result.get("staging_dir"))
        try:
            token = refresh_token() or token
            client.complete(token, job_id, ok=False, error=str(exc))
        except ApiError:
            pass


class AgentRuntime:
    """Independent control/heartbeat loop plus a single scan worker."""

    def __init__(
        self,
        client: CentralClient,
        uuid: str,
        secret: str,
        public_hex: str,
        private,
        *,
        interval: float = CONTROL_INTERVAL_SECONDS,
        jitter: float = CONTROL_JITTER_SECONDS,
        run_job_fn: Callable = run_job,
        authenticate_fn: Callable = authenticate,
        inventory_fn: Callable[..., dict | None] = inventory_for_heartbeat,
    ):
        self.client = client
        self.uuid = uuid
        self.secret = secret
        self.public_hex = public_hex
        self.private = private
        self.interval = interval
        self.jitter = jitter
        self._run_job = run_job_fn
        self._authenticate = authenticate_fn
        self._inventory = inventory_fn
        self._lock = threading.Lock()
        self._token: str | None = None
        self._job_id: int | None = None
        self._activity = "idle"
        self._stop = threading.Event()
        self._work: dict[str, Any] | None = None
        self._work_ready = threading.Event()
        self._idle = threading.Event()
        self._idle.set()
        self._cancel = threading.Event()

    def stop(self) -> None:
        self._stop.set()
        self._work_ready.set()

    def current_job(self) -> tuple[int | None, str]:
        with self._lock:
            return self._job_id, self._activity

    def _set_token(self, token: str | None) -> None:
        with self._lock:
            self._token = token

    def _get_token(self) -> str | None:
        with self._lock:
            return self._token

    def _set_work(self, job: dict[str, Any] | None, activity: str) -> None:
        with self._lock:
            self._work = job
            self._job_id = None if job is None else job.get("job_id")
            self._activity = activity
        if job is None:
            self._idle.set()
            self._work_ready.clear()
        else:
            self._idle.clear()
            self._work_ready.set()

    def refresh_token(self) -> str | None:
        token = self._authenticate(self.client, self.uuid, self.secret, self.public_hex, self.private)
        if token:
            self._set_token(token)
        return token

    def send_heartbeat(self, *, force_inventory: bool = False) -> None:
        token = self._get_token()
        if not token:
            return
        job_id, activity = self.current_job()
        inventory = self._inventory(force=force_inventory)
        result = self.client.heartbeat(token, runtime_inventory=inventory, job_id=job_id, activity=activity)
        if result.get("cancel_requested"):
            self._cancel.set()

    def _heartbeat_loop(self) -> None:
        first = True
        while not self._stop.is_set():
            try:
                if self._get_token():
                    self.send_heartbeat(force_inventory=first)
                    first = False
            except ApiError as exc:
                print(f"Heartbeat API error: {exc}", flush=True)
                self._set_token(None)
            except Exception:
                traceback.print_exc()
            self._stop.wait(jittered_interval(self.interval, self.jitter))

    def _worker_loop(self) -> None:
        while not self._stop.is_set():
            self._work_ready.wait(timeout=1.0)
            if self._stop.is_set():
                return
            with self._lock:
                job = self._work
            if job is None:
                continue
            try:
                token = self._get_token()
                if not token:
                    token = self.refresh_token()
                if not token:
                    print("Scan worker has no token; returning job to idle", flush=True)
                    continue
                self._cancel.clear()
                self._run_job(
                    self.client,
                    token,
                    job,
                    refresh_token=self.refresh_token,
                    cancel_event=self._cancel,
                )
            except Exception:
                traceback.print_exc()
            finally:
                self._set_work(None, "idle")

    def _ensure_token(self) -> str | None:
        token = self._get_token()
        if token:
            return token
        token = self.refresh_token()
        return token

    def _poll_once(self) -> None:
        if not self._idle.is_set():
            return
        token = self._get_token()
        if not token:
            return
        jobs = self.client.jobs(token)
        if not jobs or not self._idle.is_set():
            return
        self._set_work(jobs[0], "scanning")

    def run(self, *, max_cycles: int | None = None) -> None:
        heartbeat = threading.Thread(target=self._heartbeat_loop, name="agent-heartbeat", daemon=True)
        worker = threading.Thread(target=self._worker_loop, name="agent-scan-worker", daemon=True)
        heartbeat.start()
        worker.start()
        cycles = 0
        try:
            while not self._stop.is_set():
                try:
                    if not self._ensure_token():
                        self._stop.wait(jittered_interval(self.interval, self.jitter))
                        cycles += 1
                        if max_cycles is not None and cycles >= max_cycles:
                            self.stop()
                            break
                        continue
                    self._poll_once()
                except ApiError as exc:
                    print(f"API error: {exc}", flush=True)
                    self._set_token(None)
                except Exception:
                    traceback.print_exc()
                    self._set_token(None)
                self._stop.wait(jittered_interval(self.interval, self.jitter))
                cycles += 1
                if max_cycles is not None and cycles >= max_cycles:
                    self.stop()
                    break
        finally:
            self.stop()
            heartbeat.join(timeout=2.0)
            worker.join(timeout=2.0)


def main() -> None:
    central = env("CENTRAL_URL")
    uuid = env("AGENT_UUID")
    secret = os.environ.get("ENROLLMENT_SECRET", "")
    private, public_hex = load_or_create_keypair()
    client = CentralClient(central)
    print(f"Agent {uuid} starting; central={central}", flush=True)
    try:
        AgentRuntime(client, uuid, secret, public_hex, private).run()
    finally:
        client.close()


if __name__ == "__main__":
    main()
