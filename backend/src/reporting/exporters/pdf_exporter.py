"""
PDF Exporter

Converts Markdown reports (from MarkdownTemplates) to PDF using
weasyprint.  Supports custom CSS styling for professional-looking
penetration test reports.
"""

from __future__ import annotations

from typing import Any

from core.logging import get_logger

logger = get_logger(__name__)

# Default CSS for PDF reports
DEFAULT_CSS = """
@page {
    size: A4;
    margin: 2cm;
    @bottom-center {
        content: "CONFIDENTIAL - Arc Penetration Test Report";
        font-size: 8pt;
        color: #666;
    }
    @bottom-right {
        content: "Page " counter(page) " of " counter(pages);
        font-size: 8pt;
        color: #666;
    }
}

body {
    font-family: 'Helvetica Neue', Arial, sans-serif;
    font-size: 11pt;
    line-height: 1.6;
    color: #1a1a1a;
}

h1 {
    color: #1a1a2e;
    border-bottom: 3px solid #e94560;
    padding-bottom: 8px;
    page-break-after: avoid;
}

h2 {
    color: #16213e;
    border-bottom: 1px solid #ccc;
    padding-bottom: 5px;
    page-break-after: avoid;
}

h3, h4 { color: #0f3460; page-break-after: avoid; }

table {
    width: 100%;
    border-collapse: collapse;
    margin: 12px 0;
    page-break-inside: auto;
}

th {
    background-color: #1a1a2e;
    color: white;
    padding: 8px 12px;
    text-align: left;
}

td {
    padding: 6px 12px;
    border-bottom: 1px solid #ddd;
}

tr:nth-child(even) { background-color: #f5f5f5; }
tr { page-break-inside: avoid; }

code {
    background: #f0f0f0;
    padding: 2px 6px;
    border-radius: 3px;
    font-size: 10pt;
}

pre {
    background: #1a1a2e;
    color: #e0e0e0;
    padding: 12px;
    border-radius: 5px;
    font-size: 9pt;
    overflow-x: auto;
    page-break-inside: avoid;
}

.severity-critical { color: #ff1744; font-weight: bold; }
.severity-high { color: #ff6d00; font-weight: bold; }
.severity-medium { color: #ffd600; }
.severity-low { color: #00c853; }
.severity-info { color: #2979ff; }

blockquote {
    border-left: 4px solid #e94560;
    margin-left: 0;
    padding-left: 16px;
    color: #555;
}
"""


class PDFExporter:
    """
    Exports Markdown reports to PDF using WeasyPrint.

    Usage::

        exporter = PDFExporter()
        pdf_bytes = exporter.export(markdown_content)
        # or
        pdf_bytes = exporter.export_from_report(technical_report)
    """

    def __init__(self, custom_css: str | None = None) -> None:
        self._css = custom_css or DEFAULT_CSS

    def export(self, markdown: str, title: str = "Arc Report") -> bytes:
        """
        Convert a Markdown string to PDF bytes.

        Parameters
        ----------
        markdown : Markdown-formatted report content
        title    : PDF document title

        Returns
        -------
        PDF file as bytes
        """
        html = self._markdown_to_html(markdown, title)
        return self._html_to_pdf(html)

    def export_to_file(
        self,
        markdown: str,
        output_path: str,
        title: str = "Arc Report",
    ) -> str:
        """Export Markdown to a PDF file. Returns the output path."""
        pdf_bytes = self.export(markdown, title)
        with open(output_path, "wb") as f:
            f.write(pdf_bytes)

        logger.info("PDF exported", path=output_path, size_kb=len(pdf_bytes) // 1024)
        return output_path

    def export_from_report(self, report: Any) -> bytes:
        """
        Export a report dataclass (TechnicalReport, ExecutiveSummary, etc.)
        to PDF using MarkdownTemplates for rendering.
        """
        from reporting.templates.markdown_templates import MarkdownTemplates

        # Detect report type and render
        class_name = type(report).__name__

        if class_name == "TechnicalReport":
            md = MarkdownTemplates.render_technical_report(report)
        elif class_name == "ExecutiveSummary":
            md = MarkdownTemplates.render_executive_summary(report)
        elif class_name == "RemediationReport":
            md = MarkdownTemplates.render_remediation_report(report)
        elif class_name == "ComplianceReport":
            md = MarkdownTemplates.render_compliance_report(report)
        else:
            md = str(report)

        return self.export(md, title=f"Arc - {class_name}")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _markdown_to_html(self, markdown: str, title: str) -> str:
        """Convert Markdown to styled HTML."""
        try:
            import markdown as md_lib
            body = md_lib.markdown(
                markdown,
                extensions=["tables", "fenced_code", "codehilite", "toc"],
            )
        except ImportError:
            # Fallback: wrap raw markdown in <pre>
            body = f"<pre>{markdown}</pre>"
            logger.warning("python-markdown not installed, using raw output")

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{title}</title>
    <style>{self._css}</style>
</head>
<body>
{body}
</body>
</html>"""
        return html

    @staticmethod
    def _html_to_pdf(html: str) -> bytes:
        """Convert HTML to PDF bytes using WeasyPrint."""
        try:
            from weasyprint import HTML
            pdf = HTML(string=html).write_pdf()
            return pdf
        except ImportError:
            logger.error(
                "weasyprint is not installed. "
                "Install with: pip install weasyprint"
            )
            raise RuntimeError(
                "weasyprint is required for PDF export. "
                "Install with: pip install weasyprint"
            )
