"""
Continuous monitoring endpoints.

List/create/delete scheduled re-scan jobs; trigger a re-scan on demand.
"""

from datetime import datetime, timezone, timedelta
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, Query, status
from pydantic import BaseModel, Field

from api.dependencies import ProjectAccess, get_current_user
from core.constants import ScanType
from core.monitoring import (
    add_job,
    get_job,
    get_jobs,
    remove_job,
    update_job_last_run,
    MonitoringJob,
)
from core.exceptions import ResourceNotFoundError
from graph.client import get_neo4j_client

from api.routes.scans import _create_scan_record, _execute_scan_async


router = APIRouter()


# =============================================================================
# Request/Response Models
# =============================================================================

class MonitoringJobCreate(BaseModel):
    """Create a monitoring job."""
    target: str = Field(..., min_length=1, description="Scan target (domain or IP)")
    interval_hours: float = Field(24.0, ge=1.0, le=168.0, description="Re-scan interval in hours (1–168)")


class MonitoringJobResponse(BaseModel):
    """Monitoring job response."""
    job_id: str
    project_id: str
    target: str
    interval_hours: float
    last_triggered_at: str | None
    last_scan_id: str | None
    enabled: bool


class TriggerRequest(BaseModel):
    """Trigger a re-scan for a project."""
    target: str = Field(..., min_length=1, description="Scan target (domain or IP)")


# =============================================================================
# Endpoints
# =============================================================================

@router.get(
    "/jobs",
    summary="List monitoring jobs",
    description="List scheduled re-scan jobs, optionally filtered by project.",
)
async def list_monitoring_jobs(
    project_id: str | None = Query(None, description="Filter by project ID"),
    _: dict = Depends(get_current_user),
) -> list[MonitoringJobResponse]:
    """List all monitoring jobs (or for a project)."""
    jobs = get_jobs(project_id=project_id)
    return [MonitoringJobResponse(**j.to_dict()) for j in jobs]


@router.post(
    "/jobs",
    status_code=status.HTTP_201_CREATED,
    summary="Create monitoring job",
    description="Schedule periodic re-scans for a project target.",
)
async def create_monitoring_job(
    data: MonitoringJobCreate,
    project_id: str = Query(..., description="Project ID"),
    project: Annotated[dict, Depends(ProjectAccess(require_write=True))] = None,
    _: dict = Depends(get_current_user),
) -> MonitoringJobResponse:
    """Create a new monitoring job."""
    job = add_job(
        project_id=project_id,
        target=data.target,
        interval_hours=data.interval_hours,
    )
    return MonitoringJobResponse(**job.to_dict())


@router.delete(
    "/jobs/{job_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete monitoring job",
)
async def delete_monitoring_job(
    job_id: str,
    _: dict = Depends(get_current_user),
) -> None:
    """Remove a monitoring job."""
    if not remove_job(job_id):
        raise ResourceNotFoundError("Monitoring job", job_id)


@router.post(
    "/trigger",
    status_code=status.HTTP_201_CREATED,
    summary="Trigger re-scan",
    description="Run a re-scan now for the given project and target (without waiting for schedule).",
)
async def trigger_rescan(
    data: TriggerRequest,
    background_tasks: BackgroundTasks,
    project_id: str = Query(..., description="Project ID"),
    project: Annotated[dict, Depends(ProjectAccess(require_write=True))] = None,
    _: dict = Depends(get_current_user),
) -> dict:
    """Trigger a re-scan now. Returns scan_id."""
    from api.routes.scans import ScanAlreadyRunningError

    client = get_neo4j_client()
    existing = await client.execute_read(
        """
        MATCH (s:Scan { target: $target, project_id: $project_id, status: 'running' })
        RETURN s LIMIT 1
        """,
        {"target": data.target, "project_id": project_id},
    )
    if existing:
        raise ScanAlreadyRunningError(existing[0]["s"]["scan_id"])

    scan_id, now = await _create_scan_record(
        client, project_id, data.target, ScanType.FULL_RECON, {}
    )
    background_tasks.add_task(
        _execute_scan_async,
        scan_id=scan_id,
        project_id=project_id,
        target=data.target,
        scan_type=ScanType.FULL_RECON,
        options={},
    )
    return {"scan_id": scan_id, "target": data.target, "status": "queued"}


async def monitoring_tick() -> None:
    """
    Scheduler tick: run due monitoring jobs (create scan + queue execution).
    Called by APScheduler every few minutes.
    """
    jobs = get_jobs()
    now = datetime.now(timezone.utc)
    client = get_neo4j_client()
    for job in jobs:
        if not job.enabled:
            continue
        due = False
        if job.last_triggered_at is None:
            due = True
        else:
            try:
                last = datetime.fromisoformat(job.last_triggered_at.replace("Z", "+00:00"))
                if (now - last) >= timedelta(hours=job.interval_hours):
                    due = True
            except (ValueError, TypeError):
                due = True
        if not due:
            continue
        try:
            scan_id, created_at = await _create_scan_record(
                client, job.project_id, job.target, ScanType.FULL_RECON, {}
            )
            update_job_last_run(job.job_id, scan_id, created_at)
            import asyncio
            asyncio.create_task(_execute_scan_async(
                scan_id, job.project_id, job.target, ScanType.FULL_RECON, {}
            ))
        except Exception as e:
            from core.logging import get_logger
            get_logger(__name__).warning(
                "Monitoring job trigger failed",
                job_id=job.job_id,
                target=job.target,
                error=str(e),
            )
