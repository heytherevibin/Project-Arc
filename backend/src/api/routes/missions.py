"""
Mission Management Endpoints

CRUD operations for penetration testing missions, mission execution,
approval handling, and timeline queries.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from agents.shared.agent_protocol import MissionStatus, get_mission_manager
from core.logging import get_logger
from intelligence.planner.mission_planner import get_mission_planner

router = APIRouter()
logger = get_logger(__name__)


# =============================================================================
# Request/Response Models
# =============================================================================

class MissionCreate(BaseModel):
    """Request model for creating a mission."""
    project_id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1, max_length=200)
    objective: str = Field(..., min_length=1)
    target: str = Field(..., min_length=1)
    target_type: str = Field(default="web_application_pentest")
    constraints: dict[str, Any] = Field(default_factory=dict)


class MissionResponse(BaseModel):
    """Response model for a mission."""
    mission_id: str
    project_id: str
    name: str
    objective: str
    target: str
    status: str
    current_phase: str
    created_at: str
    updated_at: str
    started_at: str | None = None
    completed_at: str | None = None
    discovered_hosts_count: int = 0
    discovered_vulns_count: int = 0
    active_sessions_count: int = 0
    compromised_hosts_count: int = 0


class MissionListResponse(BaseModel):
    """Response model for listing missions."""
    items: list[MissionResponse]
    total: int


class MissionPlanResponse(BaseModel):
    """Response with the mission and its generated plan."""
    mission: dict[str, Any]
    plan: dict[str, Any]


class MissionStepResponse(BaseModel):
    """Response after executing a mission step."""
    mission_id: str
    phase: str | None = None
    next_agent: str | None = None
    discovered_hosts: int = 0
    discovered_vulns: int = 0
    active_sessions: int = 0
    pending_approvals: list[dict[str, Any]] = []
    status: str = ""
    error: str | None = None


class ApprovalRequest(BaseModel):
    """Request to approve a pending mission action."""
    approved_by: str = Field(..., min_length=1)


class TimelineResponse(BaseModel):
    """Response for mission timeline events."""
    events: list[dict[str, Any]]


# =============================================================================
# Endpoints
# =============================================================================

@router.post("", status_code=status.HTTP_201_CREATED, response_model=MissionPlanResponse)
async def create_mission(body: MissionCreate) -> dict[str, Any]:
    """Create a new mission with an auto-generated attack plan."""
    planner = get_mission_planner()
    result = await planner.plan_mission(
        project_id=body.project_id,
        name=body.name,
        objective=body.objective,
        target=body.target,
        target_type=body.target_type,
        constraints=body.constraints,
    )
    return result


@router.get("", response_model=MissionListResponse)
async def list_missions(
    project_id: str | None = Query(None),
    status_filter: str | None = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=100),
) -> dict[str, Any]:
    """List missions with optional filters."""
    mgr = get_mission_manager()
    ms = None
    if status_filter:
        try:
            ms = MissionStatus(status_filter)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status: {status_filter}",
            )

    missions = mgr.list_missions(project_id=project_id, status=ms, limit=limit)
    items = [_to_response(m) for m in missions]
    return {"items": items, "total": len(items)}


@router.get("/{mission_id}", response_model=MissionResponse)
async def get_mission(mission_id: str) -> dict[str, Any]:
    """Get a specific mission."""
    mgr = get_mission_manager()
    mission = mgr.get_mission(mission_id)
    if not mission:
        raise HTTPException(status_code=404, detail="Mission not found")
    return _to_response(mission)


@router.post("/{mission_id}/start", response_model=MissionStepResponse)
async def start_mission(mission_id: str) -> dict[str, Any]:
    """Start executing a planned mission."""
    planner = get_mission_planner()
    success = await planner.start_mission(mission_id)
    if not success:
        raise HTTPException(status_code=400, detail="Mission cannot be started")

    # Execute the first step
    result = await planner.step_mission(mission_id)
    return result


@router.post("/{mission_id}/step", response_model=MissionStepResponse)
async def step_mission(mission_id: str) -> dict[str, Any]:
    """Execute the next step of a running mission."""
    planner = get_mission_planner()
    result = await planner.step_mission(mission_id)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@router.post("/{mission_id}/approve", response_model=MissionStepResponse)
async def approve_mission(mission_id: str, body: ApprovalRequest) -> dict[str, Any]:
    """Approve pending phase transition and continue the mission."""
    planner = get_mission_planner()
    result = await planner.approve_and_continue(mission_id, approved_by=body.approved_by)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@router.post("/{mission_id}/cancel", status_code=status.HTTP_200_OK)
async def cancel_mission(mission_id: str) -> dict[str, str]:
    """Cancel a running mission."""
    planner = get_mission_planner()
    success = await planner.cancel_mission(mission_id)
    if not success:
        raise HTTPException(status_code=400, detail="Mission cannot be cancelled")
    return {"status": "cancelled", "mission_id": mission_id}


@router.get("/{mission_id}/timeline", response_model=TimelineResponse)
async def get_timeline(
    mission_id: str,
    limit: int = Query(100, ge=1, le=500),
) -> dict[str, Any]:
    """Get the event timeline for a mission."""
    mgr = get_mission_manager()
    events = mgr.get_timeline(mission_id, limit=limit)
    return {"events": [e.to_dict() for e in events]}


@router.get("/{mission_id}/state")
async def get_mission_state(mission_id: str) -> dict[str, Any]:
    """Get the current LangGraph state for a mission (debug)."""
    planner = get_mission_planner()
    state = planner.get_mission_state(mission_id)
    if state is None:
        raise HTTPException(status_code=404, detail="No active state for this mission")
    # Return a safe subset (not the full LangGraph internal state)
    return {
        "mission_id": state.get("mission_id"),
        "current_phase": state.get("current_phase"),
        "discovered_hosts": len(state.get("discovered_hosts", [])),
        "discovered_vulns": len(state.get("discovered_vulns", [])),
        "active_sessions": len(state.get("active_sessions", [])),
        "compromised_hosts": len(state.get("compromised_hosts", [])),
        "pending_approvals": [
            a for a in state.get("pending_approvals", []) if a.get("status") == "pending"
        ],
        "phase_history": state.get("phase_history", []),
    }


@router.delete("/{mission_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_mission(mission_id: str) -> None:
    """Delete a mission."""
    mgr = get_mission_manager()
    if not mgr.delete_mission(mission_id):
        raise HTTPException(status_code=404, detail="Mission not found")


# =============================================================================
# Helpers
# =============================================================================

def _to_response(m: Any) -> dict[str, Any]:
    """Convert a Mission to a MissionResponse dict."""
    return {
        "mission_id": m.mission_id,
        "project_id": m.project_id,
        "name": m.name,
        "objective": m.objective,
        "target": m.target,
        "status": m.status.value if hasattr(m.status, "value") else str(m.status),
        "current_phase": m.current_phase,
        "created_at": m.created_at,
        "updated_at": m.updated_at,
        "started_at": m.started_at,
        "completed_at": m.completed_at,
        "discovered_hosts_count": len(m.discovered_hosts),
        "discovered_vulns_count": len(m.discovered_vulns),
        "active_sessions_count": len(m.active_sessions),
        "compromised_hosts_count": len(m.compromised_hosts),
    }
