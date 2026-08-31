import os
import time
import traceback

import threading

from api_client import ApiError, ScannerClient
from artifact_io import JobControl, cleanup_staging, use_job_control
from job_finish import finish_pipeline_run
from runner import PipelineError, run_pipeline
from scan_progress import bind_job, clear_job, snapshot as progress_snapshot
from spool import abandon_job_spool, discover_completed_job_ids, recover_owned_spool, resume_pipeline_result


def try_resume_completed_jobs(client: ScannerClient) -> bool:
    """Resume a local pipeline.done job still owned by the central scanner.

    Must run before queued poll: GET /jobs only returns JOB_QUEUED rows,
    and POST /start rejects an already-running claimed job.
    """
    for job_id in discover_completed_job_ids():
        try:
            status = client.job_status(job_id)
        except ApiError:
            abandon_job_spool(job_id)
            continue
        if status.get("status") != "running":
            abandon_job_spool(job_id)
            continue
        print(f"Resuming WAN job {job_id}", flush=True)
        execute_wan_job(client, {"job_id": job_id, **status}, resume=True)
        return True
    return False


def execute_wan_job(client: ScannerClient, job: dict, *, resume: bool = False) -> None:
    job_id = job["job_id"]
    result: dict = {"artifacts": [], "staging_dir": None}
    cancel = threading.Event()
    bind_job(job_id)
    started = job
    if not resume:
        print(f"Starting WAN job {job_id}", flush=True)
        started = client.start(job_id)
    control = JobControl.from_job(started, cancel_event=cancel)

    def _watch_cancel() -> None:
        while not cancel.is_set():
            try:
                status = client.job_status(job_id)
            except ApiError:
                time.sleep(5)
                continue
            if status.get("cancel_requested"):
                cancel.set()
                return
            progress = progress_snapshot()
            if progress:
                try:
                    client.progress(job_id, progress)
                except ApiError:
                    pass
            time.sleep(5)

    watcher = threading.Thread(target=_watch_cancel, name=f"wan-cancel-{job_id}", daemon=True)
    watcher.start()
    try:
        if resume:
            resumed = recover_owned_spool(job_id)
            if resumed is None:
                client.complete(job_id, ok=False, error="owned running job has no recoverable spool")
                return
            result = resume_pipeline_result(resumed)
        else:
            resumed = recover_owned_spool(job_id)
            if resumed is not None:
                print(f"Resuming spool upload for WAN job {job_id}", flush=True)
                result = resume_pipeline_result(resumed)
            else:
                with use_job_control(control):
                    result = run_pipeline(started, control=control)
        finish_pipeline_run(
            result=result,
            upload=lambda artifact, current_id=job_id: client.upload_artifact(current_id, artifact),
            complete=lambda ok, error, raw_evidence=None, current_id=job_id: client.complete(
                current_id, ok=ok, error=error, raw_evidence=raw_evidence
            ),
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
                complete=lambda ok, error, raw_evidence=None, current_id=job_id: client.complete(
                    current_id, ok=ok, error=error, raw_evidence=raw_evidence
                ),
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
    finally:
        cancel.set()
        clear_job()


def main() -> None:
    central = os.environ.get("CENTRAL_URL", "http://api:8000")
    token = os.environ.get("SCANNER_TOKEN")
    if not token:
        raise SystemExit("SCANNER_TOKEN is required")
    client = ScannerClient(central, token)
    print(f"WAN scanner starting; central={central}", flush=True)
    while True:
        try:
            try_resume_completed_jobs(client)
            jobs = client.jobs()
            for job in jobs:
                execute_wan_job(client, job, resume=False)
        except ApiError as exc:
            print(f"API error: {exc}", flush=True)
        except Exception:
            traceback.print_exc()
        time.sleep(10)


if __name__ == "__main__":
    main()
