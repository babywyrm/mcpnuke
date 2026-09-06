"""Typed request/response models for the mcpnuke-runner service."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ScanDepth(str, Enum):
    """Scan intensity presets, mapped to mcpnuke probe options in runner.py.

    - ``fast``: sample the top security-relevant tools, skip heavy probes.
    - ``standard``: full enumeration + behavioral probes in safe mode
      (no destructive tool invocations).
    - ``deep``: standard plus active probe calls. Still safe-mode by default.
    """

    fast = "fast"
    standard = "standard"
    deep = "deep"


class ScanRequest(BaseModel):
    target: str = Field(
        ...,
        description="MCP endpoint URL or host:port to scan, e.g. http://brain-gateway:8080/mcp",
        min_length=1,
    )
    depth: ScanDepth = ScanDepth.standard
    safe_mode: bool = Field(
        True,
        description=(
            "When true, skip invocations flagged as destructive. "
            "Strongly recommended for portal-launched scans."
        ),
    )
    timeout: float = Field(25.0, ge=1.0, le=120.0, description="Per-target connect/probe timeout (seconds).")
    max_seconds: float | None = Field(
        None,
        ge=5.0,
        le=1800.0,
        description=(
            "Hard wall-clock cap for the whole job. The scan subprocess is "
            "killed if it exceeds this. None uses the server default "
            "(MCPNUKE_RUNNER_JOB_TIMEOUT)."
        ),
    )
    coverage_url: str | None = Field(
        None,
        description=(
            "Optional camazotz base URL; when set, the result includes a "
            "cross-project coverage report vs that instance's lane taxonomy."
        ),
    )
    auth_token: str | None = Field(
        None,
        exclude=True,  # never serialize — GET /scans must not leak callers' tokens
        description="Optional bearer token forwarded to the target.",
    )


class ScanStatus(str, Enum):
    queued = "queued"
    running = "running"
    done = "done"
    error = "error"


class ScanJob(BaseModel):
    id: str
    status: ScanStatus
    request: ScanRequest
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None
    error: str | None = None
    # Populated when status == done.
    report: dict[str, Any] | None = None
    by_lane: dict[str, Any] | None = None
    coverage: dict[str, Any] | None = None


class ScanAccepted(BaseModel):
    """Returned by POST /scans — the caller polls GET /scans/{id}."""

    id: str
    status: ScanStatus


class HealthResponse(BaseModel):
    status: str = "ok"
    service: str = "mcpnuke-runner"
    version: str
    active_jobs: int
