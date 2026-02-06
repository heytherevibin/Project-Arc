"""
Native Sliver C2 gRPC client.

Uses sliver-py when installed; connects via operator config path from environment.
Falls back to a no-op stub when sliver-py is not available.
"""

import os
from dataclasses import dataclass, field
from typing import Any

from core.logging import get_logger


logger = get_logger(__name__)

_SLIVER_PY_AVAILABLE = False
try:
    from sliver import SliverClientConfig, AsyncSliverClient  # type: ignore[import-untyped]
    _SLIVER_PY_AVAILABLE = True
except ImportError:
    pass


@dataclass
class SliverSession:
    """Minimal session info from Sliver."""

    id: str
    name: str
    hostname: str
    username: str
    os: str
    remote_address: str


@dataclass
class SliverCommandResult:
    """Result of executing a command in a session."""

    success: bool
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    error: str | None = None


class SliverClient:
    """
    Native Sliver gRPC client wrapper.
    Config from env: SLIVER_CONFIG_PATH (path to operator .cfg file).
    """

    def __init__(self, config_path: str | None = None) -> None:
        self._config_path = config_path or os.environ.get("SLIVER_CONFIG_PATH", "")
        self._client: Any = None
        self._connected = False

    @property
    def available(self) -> bool:
        """True if sliver-py is installed and config path is set."""
        return bool(_SLIVER_PY_AVAILABLE and self._config_path and os.path.isfile(self._config_path))

    async def connect(self) -> bool:
        """Connect to Sliver server using operator config. Returns True on success."""
        if not _SLIVER_PY_AVAILABLE:
            logger.warning("sliver-py not installed; Sliver gRPC client unavailable")
            return False
        if not self._config_path or not os.path.isfile(self._config_path):
            logger.warning("SLIVER_CONFIG_PATH not set or file missing", path=self._config_path)
            return False
        try:
            config = SliverClientConfig.parse_config_file(self._config_path)
            self._client = AsyncSliverClient(config)
            await self._client.connect()
            self._connected = True
            logger.info("Sliver gRPC client connected")
            return True
        except Exception as e:
            logger.exception("Sliver gRPC connect failed", error=str(e))
            return False

    async def disconnect(self) -> None:
        """Disconnect from Sliver server."""
        self._connected = False
        self._client = None

    async def list_sessions(self) -> list[SliverSession]:
        """List active Sliver sessions."""
        if not self._connected or not self._client:
            if self.available and not self._connected:
                await self.connect()
            if not self._connected:
                return []
        try:
            raw = await self._client.sessions()
            out: list[SliverSession] = []
            for s in raw:
                out.append(SliverSession(
                    id=getattr(s, "ID", str(getattr(s, "id", ""))),
                    name=getattr(s, "Name", getattr(s, "name", "")),
                    hostname=getattr(s, "Hostname", getattr(s, "hostname", "")),
                    username=getattr(s, "Username", getattr(s, "username", "")),
                    os=getattr(s, "OS", getattr(s, "os", "")),
                    remote_address=getattr(s, "RemoteAddress", getattr(s, "remote_address", "")),
                ))
            return out
        except Exception as e:
            logger.exception("Sliver list_sessions failed", error=str(e))
            return []

    async def execute_command(
        self,
        session_id: str,
        command: str,
        args: list[str] | None = None,
        timeout: int = 60,
    ) -> SliverCommandResult:
        """Execute a command in a Sliver session via gRPC."""
        if not self._connected or not self._client:
            if self.available and not self._connected:
                await self.connect()
            if not self._connected:
                return SliverCommandResult(success=False, error="Sliver client not connected")
        try:
            sessions = await self.list_sessions()
            session = next((s for s in sessions if s.id == session_id), None)
            if not session:
                return SliverCommandResult(success=False, error=f"Session not found: {session_id}")
            interact = await self._client.interact_session(session_id)
            result = await interact.execute(command, args or [], timeout=timeout)
            return SliverCommandResult(
                success=getattr(result, "Status", 0) == 0,
                stdout=getattr(result, "StdOut", "") or "",
                stderr=getattr(result, "StdErr", "") or "",
                exit_code=getattr(result, "Status", -1),
            )
        except Exception as e:
            logger.exception("Sliver execute_command failed", error=str(e))
            return SliverCommandResult(success=False, error=str(e))


_singleton: SliverClient | None = None


def get_sliver_client(config_path: str | None = None) -> SliverClient:
    """Return a shared Sliver client instance (config from env if not passed)."""
    global _singleton
    if _singleton is None:
        _singleton = SliverClient(config_path=config_path)
    return _singleton
