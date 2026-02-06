"""
Mission Planner

Orchestrates the high-level mission lifecycle:
  1. Accept mission parameters (objective, target, constraints)
  2. Generate an attack plan via the AGE planner
  3. Configure the LangGraph workflow
  4. Execute and monitor the workflow
  5. Handle approvals and phase transitions

This module is the main entry point for running a pentest mission.
"""

from __future__ import annotations

import asyncio
from typing import Any

from agents.shared.agent_protocol import (
    Mission,
    MissionManager,
    MissionStatus,
    get_mission_manager,
)
from agents.supervisor.supervisor_agent import AgentState, SupervisorAgent
from core.logging import get_logger
from intelligence.planner.age_planner import AGEPlanner, AttackPlan

logger = get_logger(__name__)


class MissionPlanner:
    """
    High-level mission planner that bridges:
    - AGE planner (strategy generation)
    - Mission manager (state tracking)
    - LangGraph workflow (execution)
    """

    def __init__(
        self,
        mission_manager: MissionManager | None = None,
        age_planner: AGEPlanner | None = None,
    ) -> None:
        self._missions = mission_manager or get_mission_manager()
        self._age = age_planner or AGEPlanner()
        self._active_workflows: dict[str, Any] = {}  # mission_id → compiled graph
        self._active_states: dict[str, AgentState] = {}

    async def plan_mission(
        self,
        project_id: str,
        name: str,
        objective: str,
        target: str,
        target_type: str = "web_application_pentest",
        constraints: dict[str, Any] | None = None,
        created_by: str = "",
    ) -> dict[str, Any]:
        """
        Create a mission and generate its attack plan.

        Returns a dict with the mission and its attack plan.
        """
        # Create the mission
        mission = self._missions.create_mission(
            project_id=project_id,
            name=name,
            objective=objective,
            target=target,
            created_by=created_by,
            config={"target_type": target_type, "constraints": constraints or {}},
        )

        # Generate the plan
        plan = self._age.generate_plan(
            objective=objective,
            target=target,
            target_type=target_type,
            constraints=constraints,
        )

        # Update mission status
        self._missions.update_status(mission.mission_id, MissionStatus.PLANNING)

        logger.info(
            "Mission planned",
            mission_id=mission.mission_id,
            plan_id=plan.plan_id,
            steps=len(plan.steps),
        )

        return {
            "mission": mission.to_dict(),
            "plan": {
                "plan_id": plan.plan_id,
                "strategy": plan.strategy,
                "steps": [
                    {
                        "step_id": s.step_id,
                        "description": s.description,
                        "tool_name": s.tool_name,
                        "phase": s.phase,
                        "risk_level": s.risk_level,
                        "requires_approval": s.requires_approval,
                    }
                    for s in plan.steps
                ],
                "estimated_time_minutes": plan.estimated_total_time // 60,
                "risk_assessment": plan.risk_assessment,
            },
        }

    async def start_mission(self, mission_id: str) -> bool:
        """
        Start executing a planned mission.

        Compiles the LangGraph workflow and begins the first iteration.
        """
        mission = self._missions.get_mission(mission_id)
        if not mission:
            logger.error("Mission not found", mission_id=mission_id)
            return False

        if mission.status not in (MissionStatus.PLANNING, MissionStatus.PAUSED):
            logger.warning("Mission not in startable state", status=mission.status.value)
            return False

        # Build the initial LangGraph state
        supervisor = SupervisorAgent(memory=None)
        initial_state = supervisor.create_initial_state(
            mission_id=mission.mission_id,
            project_id=mission.project_id,
            target=mission.target,
            objective=mission.objective,
        )

        # Compile the workflow
        try:
            from agents.graphs.workflow import compile_workflow
            workflow = compile_workflow()
            self._active_workflows[mission_id] = workflow
            self._active_states[mission_id] = initial_state
        except Exception as e:
            logger.error("Failed to compile workflow", error=str(e))
            self._missions.update_status(mission_id, MissionStatus.FAILED)
            return False

        self._missions.update_status(mission_id, MissionStatus.RUNNING)
        logger.info("Mission started", mission_id=mission_id)
        return True

    async def step_mission(self, mission_id: str) -> dict[str, Any]:
        """
        Execute one step of the mission workflow.

        Returns the current state after the step, including any
        pending approvals that need resolution.
        """
        workflow = self._active_workflows.get(mission_id)
        state = self._active_states.get(mission_id)

        if not workflow or state is None:
            return {"error": "Mission not running", "mission_id": mission_id}

        try:
            # Run one iteration of the graph
            result = await workflow.ainvoke(state)
            self._active_states[mission_id] = result

            # Sync state back to mission manager
            self._missions.sync_state(mission_id, result)

            # Check for completion
            if result.get("next_agent") == "__end__":
                self._missions.update_status(mission_id, MissionStatus.COMPLETED)

            # Check for pending approvals
            pending = [
                a for a in result.get("pending_approvals", [])
                if a.get("status") == "pending"
            ]
            if pending:
                self._missions.update_status(mission_id, MissionStatus.PAUSED)

            return {
                "mission_id": mission_id,
                "phase": result.get("current_phase"),
                "next_agent": result.get("next_agent"),
                "discovered_hosts": len(result.get("discovered_hosts", [])),
                "discovered_vulns": len(result.get("discovered_vulns", [])),
                "active_sessions": len(result.get("active_sessions", [])),
                "pending_approvals": pending,
                "status": self._missions.get_mission(mission_id).status.value
                if self._missions.get_mission(mission_id)
                else "unknown",
            }

        except Exception as e:
            logger.error("Mission step failed", mission_id=mission_id, error=str(e))
            self._missions.update_status(mission_id, MissionStatus.FAILED)
            return {"error": str(e), "mission_id": mission_id}

    async def approve_and_continue(
        self,
        mission_id: str,
        approved_by: str,
    ) -> dict[str, Any]:
        """Approve pending phase transition and continue the mission."""
        state = self._active_states.get(mission_id)
        if not state:
            return {"error": "Mission not running"}

        # Approve pending transitions
        pending = state.get("pending_approvals", [])
        for approval in pending:
            if approval.get("status") == "pending":
                from datetime import datetime, timezone
                approval["status"] = "approved"
                approval["approved_by"] = approved_by
                approval["approved_at"] = datetime.now(timezone.utc).isoformat()

                new_phase = approval["to_phase"]
                state["current_phase"] = new_phase
                state["phase_history"] = state.get("phase_history", []) + [{
                    "from": approval["from_phase"],
                    "to": new_phase,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "approved_by": approved_by,
                }]

        self._missions.update_status(mission_id, MissionStatus.RUNNING)
        return await self.step_mission(mission_id)

    async def cancel_mission(self, mission_id: str) -> bool:
        """Cancel a running mission."""
        self._active_workflows.pop(mission_id, None)
        self._active_states.pop(mission_id, None)
        return self._missions.update_status(mission_id, MissionStatus.CANCELLED)

    def get_mission_state(self, mission_id: str) -> dict[str, Any] | None:
        """Get the current LangGraph state for a mission."""
        state = self._active_states.get(mission_id)
        if state is None:
            return None
        return dict(state)


# Singleton
_planner: MissionPlanner | None = None


def get_mission_planner() -> MissionPlanner:
    global _planner
    if _planner is None:
        _planner = MissionPlanner()
    return _planner
