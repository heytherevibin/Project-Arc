"""
WebSocket event payload builders.

Pure functions that build JSON-serializable message dicts.
No I/O; used by handler and callers that broadcast.
"""

from datetime import datetime, timezone
from typing import Any

from core.constants import WSEventType


def _with_timestamp(payload: dict[str, Any]) -> dict[str, Any]:
    """Add UTC timestamp to payload."""
    payload["timestamp"] = datetime.now(timezone.utc).isoformat()
    return payload


def build_connected_event(user_id: str) -> dict[str, Any]:
    """Build connected event payload."""
    return _with_timestamp({
        "event": WSEventType.CONNECTED.value,
        "data": {"user_id": user_id},
    })


def build_scan_progress_event(
    scan_id: str,
    progress: float,
    phase: str | None,
    items_discovered: int,
    vulnerabilities_found: int,
) -> dict[str, Any]:
    """Build scan progress event payload."""
    return _with_timestamp({
        "event": WSEventType.SCAN_PROGRESS.value,
        "data": {
            "scan_id": scan_id,
            "progress": progress,
            "phase": phase,
            "items_discovered": items_discovered,
            "vulnerabilities_found": vulnerabilities_found,
        },
    })


def build_scan_completed_event(
    scan_id: str,
    project_id: str,
    summary: dict[str, Any],
) -> dict[str, Any]:
    """Build scan completed event payload."""
    return _with_timestamp({
        "event": WSEventType.SCAN_COMPLETED.value,
        "data": {
            "scan_id": scan_id,
            "project_id": project_id,
            "summary": summary,
        },
    })


def build_vulnerability_found_event(
    scan_id: str,
    project_id: str,
    vulnerability: dict[str, Any],
) -> dict[str, Any]:
    """Build vulnerability found event payload."""
    return _with_timestamp({
        "event": WSEventType.VULNERABILITY_FOUND.value,
        "data": {
            "scan_id": scan_id,
            "project_id": project_id,
            "vulnerability": vulnerability,
        },
    })


def build_mission_update_event(
    mission_id: str,
    project_id: str,
    event_type: str,
    data: dict[str, Any],
) -> dict[str, Any]:
    """Build mission update event payload (e.g. mission_phase_change)."""
    return _with_timestamp({
        "event": f"mission_{event_type}",
        "data": {
            "mission_id": mission_id,
            "project_id": project_id,
            **data,
        },
    })


def build_agent_message_event(
    project_id: str,
    agent_id: str,
    content: str,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build agent message event payload."""
    return _with_timestamp({
        "event": "agent_message",
        "data": {
            "agent_id": agent_id,
            "content": content,
            "project_id": project_id,
            **(data or {}),
        },
    })


def build_pong_event() -> dict[str, Any]:
    """Build pong response for ping."""
    return _with_timestamp({"event": "pong", "data": None})
