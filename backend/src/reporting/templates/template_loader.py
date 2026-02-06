"""
Load standalone Markdown templates and substitute placeholders.

Templates (executive_summary.md, technical_report.md, remediation.md) use
{{ placeholder }} syntax. Call render_template with a dict of key -> value.
"""

import re
from pathlib import Path
from typing import Any

from core.logging import get_logger


logger = get_logger(__name__)

_TEMPLATES_DIR = Path(__file__).parent

PLACEHOLDER_PATTERN = re.compile(r"\{\{\s*(\w+)\s*\}\}")


def get_template_path(name: str) -> Path:
    """Resolve template name to file path under reporting/templates."""
    if not name.endswith(".md"):
        name = f"{name}.md"
    return _TEMPLATES_DIR / name


def load_template(name: str) -> str:
    """Load template content by name (e.g. executive_summary, technical_report, remediation)."""
    path = get_template_path(name)
    if not path.exists():
        logger.warning("Template file not found", path=str(path))
        return ""
    return path.read_text(encoding="utf-8")


def render_template(name: str, data: dict[str, Any]) -> str:
    """
    Load template by name and substitute {{ key }} with data[key].
    Missing keys are replaced with empty string.
    """
    content = load_template(name)
    if not content:
        return ""

    def repl(match: re.Match[str]) -> str:
        key = match.group(1)
        value = data.get(key, "")
        return str(value) if value is not None else ""

    return PLACEHOLDER_PATTERN.sub(repl, content)
