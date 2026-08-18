import os
import socket
import time
import traceback

from api_client import ApiError, CentralClient, wait
from keys import load_or_create_keypair, sign
from runner import run_pipeline


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
    client.start(token, job_id)
    try:
        result = run_pipeline(job, log=lambda message: print(message, flush=True))
        token = refresh_token() or token
        if result.get("provenance"):
            try:
                client.provenance(token, job_id, result["provenance"])
            except ApiError:
                pass
        if result["devices"]:
            client.devices(token, job_id, result["devices"])
        if result["findings"]:
            client.findings(token, job_id, result["findings"])
        client.complete(token, job_id, ok=True)
        print(f"Finished job {job_id}", flush=True)
    except Exception as exc:
        traceback.print_exc()
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
            client.heartbeat(token)
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
