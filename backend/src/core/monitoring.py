"""
Continuous monitoring scheduler.

Runs periodic re-scans for projects. Jobs are stored in memory; restart clears them.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from core.logging import get_logger

logger = get_logger(__name__)

# In-memory job store: job_id -> MonitoringJob
_jobs: dict[str, MonitoringJob] = {}
_scheduler: Any = None


@dataclass
class MonitoringJob:
    """A scheduled re-scan job."""

    job_id: str
    project_id: str
    target: str
    interval_hours: float
    last_triggered_at: str | None = None
    last_scan_id: str | None = None
    enabled: bool = True

    def to_dict(self) -> dict:
        return {
            "job_id": self.job_id,
            "project_id": self.project_id,
            "target": self.target,
            "interval_hours": self.interval_hours,
            "last_triggered_at": self.last_triggered_at,
            "last_scan_id": self.last_scan_id,
            "enabled": self.enabled,
        }


def get_jobs(project_id: str | None = None) -> list[MonitoringJob]:
    """Return all jobs, optionally filtered by project_id."""
    jobs = list(_jobs.values())
    if project_id is not None:
        jobs = [j for j in jobs if j.project_id == project_id]
    return jobs


def add_job(project_id: str, target: str, interval_hours: float) -> MonitoringJob:
    """Add a monitoring job. Returns the created job."""
    job_id = str(uuid.uuid4())
    job = MonitoringJob(
        job_id=job_id,
        project_id=project_id,
        target=target,
        interval_hours=interval_hours,
    )
    _jobs[job_id] = job
    logger.info("Monitoring job added", job_id=job_id, project_id=project_id, target=target)
    return job


def get_job(job_id: str) -> MonitoringJob | None:
    return _jobs.get(job_id)


def remove_job(job_id: str) -> bool:
    """Remove a job. Returns True if it existed."""
    if job_id in _jobs:
        del _jobs[job_id]
        logger.info("Monitoring job removed", job_id=job_id)
        return True
    return False


def update_job_last_run(job_id: str, scan_id: str, triggered_at: str) -> None:
    """Update last run info for a job."""
    job = _jobs.get(job_id)
    if job:
        job.last_triggered_at = triggered_at
        job.last_scan_id = scan_id


def get_scheduler():
    """Return the APScheduler instance. Created on first use."""
    global _scheduler
    if _scheduler is None:
        from apscheduler.schedulers.asyncio import AsyncIOScheduler
        _scheduler = AsyncIOScheduler()
    return _scheduler


def start_scheduler(trigger_fn) -> None:
    """Start the scheduler and add a tick job that invokes trigger_fn for due jobs."""
    from core.config import get_settings
    if not get_settings().MONITORING_ENABLED:
        logger.info("Monitoring scheduler disabled by config")
        return
    sched = get_scheduler()
    if not sched.running:
        # Run trigger check every 5 minutes
        sched.add_job(
            trigger_fn,
            "interval",
            minutes=5,
            id="monitoring_tick",
            replace_existing=True,
        )
        sched.start()
        logger.info("Monitoring scheduler started")


def stop_scheduler() -> None:
    """Stop the scheduler."""
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        logger.info("Monitoring scheduler stopped")
    _scheduler = None
