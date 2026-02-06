"""
Tor Wrapper

Routes tool traffic through Tor SOCKS proxy using proxychains
or torsocks.  Provides command wrapping and Tor status checks.
"""

from __future__ import annotations

import shutil
from typing import Any

from core.logging import get_logger

logger = get_logger(__name__)


class TorWrapper:
    """
    Wraps tool commands to route traffic through the Tor network.

    Supports proxychains4 and torsocks as routing mechanisms.
    """

    SOCKS_PORT = 9050
    CONTROL_PORT = 9051

    def __init__(
        self,
        socks_host: str = "127.0.0.1",
        socks_port: int = SOCKS_PORT,
        method: str = "proxychains",
    ) -> None:
        """
        Parameters
        ----------
        socks_host : Tor SOCKS proxy host
        socks_port : Tor SOCKS proxy port
        method     : "proxychains" or "torsocks"
        """
        self._socks_host = socks_host
        self._socks_port = socks_port
        self._method = method

    def wrap_command(self, command: str | list[str]) -> list[str]:
        """
        Wrap a command to route through Tor.

        Parameters
        ----------
        command : the command string or list to wrap

        Returns
        -------
        The wrapped command as a list of strings.
        """
        if isinstance(command, str):
            cmd_parts = command.split()
        else:
            cmd_parts = list(command)

        if self._method == "torsocks":
            return ["torsocks"] + cmd_parts
        else:
            # Default: proxychains4
            return ["proxychains4", "-q"] + cmd_parts

    def get_socks_url(self) -> str:
        """Return the SOCKS5 proxy URL for tools that support direct proxy config."""
        return f"socks5://{self._socks_host}:{self._socks_port}"

    def check_tor_status(self) -> dict[str, Any]:
        """
        Check if Tor is available and functioning.
        Returns status information (synchronous check).
        """
        status: dict[str, Any] = {
            "tor_available": False,
            "socks_host": self._socks_host,
            "socks_port": self._socks_port,
            "method": self._method,
        }

        # Check if the wrapper binary exists
        if self._method == "torsocks":
            status["wrapper_binary"] = shutil.which("torsocks") is not None
        else:
            status["wrapper_binary"] = shutil.which("proxychains4") is not None

        # Assume Tor is available if the binary is found
        status["tor_available"] = status["wrapper_binary"]

        return status

    def get_env_vars(self) -> dict[str, str]:
        """
        Return environment variables for tools that respect
        proxy environment settings.
        """
        proxy_url = self.get_socks_url()
        return {
            "ALL_PROXY": proxy_url,
            "HTTPS_PROXY": proxy_url,
            "HTTP_PROXY": proxy_url,
            "SOCKS_PROXY": proxy_url,
        }
