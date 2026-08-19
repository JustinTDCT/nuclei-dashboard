import os
import socket
import time
import traceback

from api_client import ApiError, CentralClient, wait
from job_finish import finish_pipeline_run
from keys import load_or_create_keypair, sign
from runner import PipelineError, run_pipeline
from artifact_io import cleanup_staging
from tool_versions import collect_runtime_inventory

INVENTORY_REFRESH_SECONDS = 3600
_inventory_cache: dict | None = None
_inventory_cached_at = 0.0


def cached_runtime_inventory() -> dict:
    global _inventory_cache, _inventory_cached_at
    now = time.time()
    if _inventory_cache is None or now - _inventory_cached_at >= INVENTORY_REFRESH_SECONDS:
        _inventory_cache = collect_runtime_inventory()
        _inventory_cached_at = now
    return _inventory_cache


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


def run_job(client: CentralClient, token: str, job: dict, refresh_token) -> None:
    job_id = job["job_id"]
    print(f"Starting job {job_id}", flush=True)
    started = client.start(token, job_id)
    result: dict = {"artifacts": [], "staging_dir": None}
    try:
        result = run_pipeline(started, log=lambda message: print(message, flush=True))
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


def main() -> None:
    central = env("CENTRAL_URL")
    uuid = env("AGENT_UUID")
    secret = os.environ.get("ENROLLMENT_SECRET", "")
    private, public_hex = load_or_create_keypair()
    client = CentralClient(central)
    token = None
    print(f"Agent {uuid} starting; central={central}", flush=True)
    while True:
        try:
            if not token:
                token = authenticate(client, uuid, secret, public_hex, private)
                if not token:
                    wait(15)
                    continue
            client.heartbeat(token, runtime_inventory=cached_runtime_inventory())
            for job in client.jobs(token):
                run_job(
                    client,
                    token,
                    job,
                    refresh_token=lambda: authenticate(client, uuid, secret, public_hex, private),
                )
        except ApiError as exc:
            print(f"API error: {exc}", flush=True)
            token = None
            wait(10)
            continue
        except Exception:
            traceback.print_exc()
            token = None
            wait(10)
            continue
        time.sleep(15)


if __name__ == "__main__":
    main()
