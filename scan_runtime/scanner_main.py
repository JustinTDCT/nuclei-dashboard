import os
import time
import traceback

from api_client import ApiError, ScannerClient
from artifact_io import cleanup_staging
from job_finish import finish_pipeline_run
from runner import PipelineError, run_pipeline


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
                started = client.start(job_id)
                result: dict = {"artifacts": [], "staging_dir": None}
                try:
                    result = run_pipeline(started)
                    finish_pipeline_run(
                        result=result,
                        upload=lambda artifact, current_id=job_id: client.upload_artifact(current_id, artifact),
                        complete=lambda ok, error, current_id=job_id: client.complete(current_id, ok=ok, error=error),
                        provenance_fn=lambda payload, current_id=job_id: client.provenance(current_id, payload),
                        devices_fn=lambda devices, current_id=job_id: client.devices(current_id, devices),
                        coverage_fn=lambda payload, current_id=job_id: client.detector_coverage(current_id, payload),
                        findings_fn=lambda findings, current_id=job_id: client.findings(current_id, findings),
                    )
                    print(f"Finished WAN job {job_id}", flush=True)
                except PipelineError as exc:
                    result = exc.as_result()
                    try:
                        finish_pipeline_run(
                            result=result,
                            upload=lambda artifact, current_id=job_id: client.upload_artifact(current_id, artifact),
                            complete=lambda ok, error, current_id=job_id: client.complete(current_id, ok=ok, error=error),
                            provenance_fn=lambda payload, current_id=job_id: client.provenance(current_id, payload),
                            devices_fn=lambda devices, current_id=job_id: client.devices(current_id, devices),
                            coverage_fn=lambda payload, current_id=job_id: client.detector_coverage(current_id, payload),
                            findings_fn=lambda findings, current_id=job_id: client.findings(current_id, findings),
                            pipeline_error=str(exc),
                        )
                    except Exception as persist_exc:
                        traceback.print_exc()
                        cleanup_staging(result.get("staging_dir"))
                        client.complete(job_id, ok=False, error=str(persist_exc))
                except Exception as exc:
                    traceback.print_exc()
                    cleanup_staging(result.get("staging_dir"))
                    client.complete(job_id, ok=False, error=str(exc))
        except ApiError as exc:
            print(f"API error: {exc}", flush=True)
        except Exception:
            traceback.print_exc()
        time.sleep(10)


if __name__ == "__main__":
    main()
