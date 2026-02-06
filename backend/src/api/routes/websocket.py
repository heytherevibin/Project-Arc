"""
WebSocket route: exposes /ws and re-exports manager for broadcast callers.
"""

from fastapi import APIRouter, Query, WebSocket

from api.websocket.handler import get_manager, handle_connection


router = APIRouter()


@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str = Query(..., description="JWT access token"),
) -> None:
    """
    WebSocket endpoint for real-time updates.
    Connect with: ws://host/ws?token=<jwt_token>

    Client messages:
    - {"type": "subscribe_project", "project_id": "..."}
    - {"type": "subscribe_scan", "scan_id": "..."}
    - {"type": "unsubscribe_scan", "scan_id": "..."}
    - {"type": "ping"}

    Server messages:
    - {"event": "connected", "data": {...}}
    - {"event": "scan_progress", "data": {...}}
    - {"event": "scan_completed", "data": {...}}
    - {"event": "vulnerability_found", "data": {...}}
    - {"event": "pong", "data": null}
    """
    await handle_connection(websocket, token)


# Re-export for callers: from api.routes.websocket import get_manager
