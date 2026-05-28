"""FastAPI surface for mcpnuke-runner.

Endpoints:
    GET  /health          liveness + active job count
    POST /scans           submit a scan, returns {id, status}
    GET  /scans           list recent jobs (newest first)
    GET  /scans/{id}      poll a job; includes report/by_lane/coverage when done

Run directly with ``mcpnuke-runner`` (see pyproject scripts) or
``uvicorn mcpnuke.server.app:app``.
"""

from __future__ import annotations

import os

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from mcpnuke.server.models import (
    HealthResponse,
    ScanAccepted,
    ScanJob,
    ScanRequest,
)
from mcpnuke.server.runner import JobManager

try:
    from importlib.metadata import version as _pkg_version

    _VERSION = _pkg_version("mcpnuke")
except Exception:  # noqa: BLE001
    _VERSION = "0.0.0"

app = FastAPI(
    title="mcpnuke-runner",
    version=_VERSION,
    description="HTTP job API wrapping the mcpnuke MCP security scanner.",
)

# The portal proxies server-side, but allow CORS so the API can also be hit
# directly from a browser during local development.
_origins = os.getenv("MCPNUKE_RUNNER_CORS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _origins if o.strip()],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

_manager = JobManager(max_workers=int(os.getenv("MCPNUKE_RUNNER_WORKERS", "2")))


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(version=_VERSION, active_jobs=_manager.active_jobs)


@app.post("/scans", response_model=ScanAccepted, status_code=202)
def create_scan(req: ScanRequest) -> ScanAccepted:
    job = _manager.submit(req)
    return ScanAccepted(id=job.id, status=job.status)


@app.get("/scans", response_model=list[ScanJob])
def list_scans() -> list[ScanJob]:
    return _manager.list()


@app.get("/scans/{job_id}", response_model=ScanJob)
def get_scan(job_id: str) -> ScanJob:
    job = _manager.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"no scan job {job_id!r}")
    return job


def run() -> None:
    """Console-script entrypoint (``mcpnuke-runner``)."""
    import uvicorn

    uvicorn.run(
        "mcpnuke.server.app:app",
        host=os.getenv("MCPNUKE_RUNNER_HOST", "0.0.0.0"),
        port=int(os.getenv("MCPNUKE_RUNNER_PORT", "8090")),
        log_level=os.getenv("MCPNUKE_RUNNER_LOG_LEVEL", "info"),
    )


if __name__ == "__main__":
    run()
