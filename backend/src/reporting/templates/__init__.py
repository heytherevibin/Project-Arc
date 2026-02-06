"""
Report templates for Markdown and HTML output.
"""

from reporting.templates.markdown_templates import MarkdownTemplates
from reporting.templates.template_loader import load_template, render_template, get_template_path

__all__ = ["MarkdownTemplates", "load_template", "render_template", "get_template_path"]
