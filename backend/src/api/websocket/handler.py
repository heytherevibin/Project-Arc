"""
WebSocket connection handler and connection manager.

Handles accept, authenticate, subscribe/unsubscribe, and message loop.
"""

import json
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect

from core.config import get_settings
from core.logging import get_logger
from jose import jwt, JWTError

from api.websocket.events import (
    build_agent_message_event,
    build_connected_event,
    build_mission_update_event,
    build_pong_event,
    build_scan_completed_event,
    build_scan_progress_event,
    build_vulnerability_found_event,
)


logger = get_logger(__name__)


class ConnectionManager:
    """
    WebSocket connection manager.
    Manages active connections and project/scan subscriptions.
    """

    def __init__(self) -> None:
        self.active_connections: dict[str, list[WebSocket]] = {}
        self.project_subscriptions: dict[str, set[str]] = {}
        self.scan_subscriptions: dict[str, set[str]] = {}

    async def connect(self, websocket: WebSocket, user_id: str) -> None:
        """Accept a new WebSocket connection."""
        await websocket.accept()
        if user_id not in self.active_connections:
            self.active_connections[user_id] = []
        self.active_connections[user_id].append(websocket)
        logger.info("WebSocket connected", user_id=user_id)

    def disconnect(self, websocket: WebSocket, user_id: str) -> None:
        """Handle WebSocket disconnection."""
        if user_id in self.active_connections:
            if websocket in self.active_connections[user_id]:
                self.active_connections[user_id].remove(websocket)
            if not self.active_connections[user_id]:
                del self.active_connections[user_id]
        for project_id in list(self.project_subscriptions.keys()):
            self.project_subscriptions[project_id].discard(user_id)
            if not self.project_subscriptions[project_id]:
                del self.project_subscriptions[project_id]
        for scan_id in list(self.scan_subscriptions.keys()):
            self.scan_subscriptions[scan_id].discard(user_id)
            if not self.scan_subscriptions[scan_id]:
                del self.scan_subscriptions[scan_id]
        logger.info("WebSocket disconnected", user_id=user_id)

    def subscribe_to_project(self, user_id: str, project_id: str) -> None:
        if project_id not in self.project_subscriptions:
            self.project_subscriptions[project_id] = set()
        self.project_subscriptions[project_id].add(user_id)

    def subscribe_to_scan(self, user_id: str, scan_id: str) -> None:
        if scan_id not in self.scan_subscriptions:
            self.scan_subscriptions[scan_id] = set()
        self.scan_subscriptions[scan_id].add(user_id)

    def unsubscribe_from_scan(self, user_id: str, scan_id: str) -> None:
        if scan_id in self.scan_subscriptions:
            self.scan_subscriptions[scan_id].discard(user_id)

    async def send_to_user(self, user_id: str, message: dict[str, Any]) -> None:
        if user_id not in self.active_connections:
            return
        data = json.dumps(message)
        disconnected = []
        for ws in self.active_connections[user_id]:
            try:
                await ws.send_text(data)
            except Exception:
                disconnected.append(ws)
        for ws in disconnected:
            self.active_connections[user_id].remove(ws)

    async def broadcast_to_project(self, project_id: str, message: dict[str, Any]) -> None:
        if project_id not in self.project_subscriptions:
            return
        for user_id in self.project_subscriptions[project_id]:
            await self.send_to_user(user_id, message)

    async def broadcast_to_scan(self, scan_id: str, message: dict[str, Any]) -> None:
        if scan_id not in self.scan_subscriptions:
            return
        for user_id in self.scan_subscriptions[scan_id]:
            await self.send_to_user(user_id, message)

    async def broadcast_scan_progress(
        self,
        scan_id: str,
        progress: float,
        phase: str | None,
        items_discovered: int,
        vulnerabilities_found: int,
    ) -> None:
        msg = build_scan_progress_event(
            scan_id, progress, phase, items_discovered, vulnerabilities_found
        )
        await self.broadcast_to_scan(scan_id, msg)

    async def broadcast_scan_completed(
        self,
        scan_id: str,
        project_id: str,
        summary: dict[str, Any],
    ) -> None:
        msg = build_scan_completed_event(scan_id, project_id, summary)
        await self.broadcast_to_scan(scan_id, msg)
        await self.broadcast_to_project(project_id, msg)

    async def broadcast_vulnerability_found(
        self,
        scan_id: str,
        project_id: str,
        vulnerability: dict[str, Any],
    ) -> None:
        msg = build_vulnerability_found_event(scan_id, project_id, vulnerability)
        await self.broadcast_to_scan(scan_id, msg)
        await self.broadcast_to_project(project_id, msg)

    async def broadcast_mission_update(
        self,
        mission_id: str,
        project_id: str,
        event_type: str,
        data: dict[str, Any],
    ) -> None:
        msg = build_mission_update_event(mission_id, project_id, event_type, data)
        await self.broadcast_to_project(project_id, msg)

    async def broadcast_agent_message(
        self,
        project_id: str,
        agent_id: str,
        content: str,
        data: dict[str, Any] | None = None,
    ) -> None:
        msg = build_agent_message_event(project_id, agent_id, content, data)
        await self.broadcast_to_project(project_id, msg)


_manager: ConnectionManager | None = None


def get_manager() -> ConnectionManager:
    global _manager
    if _manager is None:
        _manager = ConnectionManager()
    return _manager


async def authenticate_websocket(token: str) -> str | None:
    """Authenticate WebSocket via JWT. Returns user_id if valid, None otherwise."""
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        return payload.get("sub")
    except JWTError:
        return None


async def handle_connection(websocket: WebSocket, token: str) -> None:
    """
    Handle a single WebSocket connection: authenticate, send connected event,
    then run message loop for subscribe/ping.
    """
    if not token or not token.strip():
        logger.warning("WebSocket rejected: missing token")
        await websocket.close(code=4001, reason="Missing token")
        return
    user_id = await authenticate_websocket(token)
    if not user_id:
        logger.warning("WebSocket rejected: invalid or expired token")
        await websocket.close(code=4001, reason="Invalid token")
        return

    manager = get_manager()
    await manager.connect(websocket, user_id)
    await manager.send_to_user(user_id, build_connected_event(user_id))

    try:
        while True:
            data = await websocket.receive_text()
            try:
                message = json.loads(data)
                msg_type = message.get("type")

                if msg_type == "ping":
                    await manager.send_to_user(user_id, build_pong_event())
                elif msg_type == "subscribe_project":
                    project_id = message.get("project_id")
                    if project_id:
                        manager.subscribe_to_project(user_id, project_id)
                        logger.debug("User subscribed to project", user_id=user_id, project_id=project_id)
                elif msg_type == "subscribe_scan":
                    scan_id = message.get("scan_id")
                    if scan_id:
                        manager.subscribe_to_scan(user_id, scan_id)
                        logger.debug("User subscribed to scan", user_id=user_id, scan_id=scan_id)
                elif msg_type == "unsubscribe_scan":
                    scan_id = message.get("scan_id")
                    if scan_id:
                        manager.unsubscribe_from_scan(user_id, scan_id)
                elif msg_type == "subscribe_mission":
                    project_id = message.get("project_id")
                    if project_id:
                        manager.subscribe_to_project(user_id, project_id)
                        logger.debug("User subscribed to mission updates", user_id=user_id, project_id=project_id)
            except json.JSONDecodeError:
                logger.warning("Invalid WebSocket message", user_id=user_id)
    except WebSocketDisconnect:
        manager.disconnect(websocket, user_id)
    except Exception as e:
        logger.exception("WebSocket error", user_id=user_id, error=str(e))
        manager.disconnect(websocket, user_id)
