"""
WebSocket subsystem: handler, events, and streams.
"""

from api.websocket.handler import get_manager, handle_connection
from api.websocket.events import (
    build_connected_event,
    build_scan_progress_event,
    build_scan_completed_event,
    build_vulnerability_found_event,
    build_mission_update_event,
    build_agent_message_event,
    build_pong_event,
)

__all__ = [
    "get_manager",
    "handle_connection",
    "build_connected_event",
    "build_scan_progress_event",
    "build_scan_completed_event",
    "build_vulnerability_found_event",
    "build_mission_update_event",
    "build_agent_message_event",
    "build_pong_event",
]
