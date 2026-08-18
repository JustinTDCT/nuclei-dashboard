import os
import time
import traceback

from api_client import ApiError, ScannerClient
from runner import run_pipeline


def main() -> None:
    central = os.environ.get("CENTRAL_URL", "http://api:8000")
    token = os.environ.get("SCANNER_TOKEN")
    if not token:
        raise SystemExit("SCANNER_TOKEN is required")
    client = ScannerClient(central, token)
    print(f"WAN scanner starting; central={central}", flush=True)
    while True:
        try:
            jobs = client.jobs()
            for job in jobs:
                job_id = job["job_id"]
                print(f"Starting WAN job {job_id}", flush=True)
                client.start(job_id)
                try:
                    result = run_pipeline(job)
                    if result.get("provenance"):
                        try:
                            client.provenance(job_id, result["provenance"])
                        except ApiError:
                            pass
                    if result["devices"]:
                        client.devices(job_id, result["devices"])
                    if result["findings"]:
                        client.findings(job_id, result["findings"])
                    client.complete(job_id, ok=True)
                    print(f"Finished WAN job {job_id}", flush=True)
                except Exception as exc:
                    traceback.print_exc()
                    client.complete(job_id, ok=False, error=str(exc))
        except ApiError as exc:
            print(f"API error: {exc}", flush=True)
        except Exception:
            traceback.print_exc()
        time.sleep(10)


if __name__ == "__main__":
    main()
