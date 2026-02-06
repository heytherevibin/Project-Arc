"""
WebSocket streaming utilities.

Reserved for future chunked or binary streaming (e.g. long log streams,
large payloads). Currently a stub; broadcast uses send_text in handler.
"""

from typing import Any

# Future: send_chunked(websocket, stream_id, chunks) or send_binary(websocket, payload)
# when the frontend needs streaming responses. No I/O in this module until then.


def prepare_stream_metadata(stream_id: str, content_type: str = "application/json") -> dict[str, Any]:
    """Build metadata dict for a stream message (for future use)."""
    return {
        "stream_id": stream_id,
        "content_type": content_type,
    }
