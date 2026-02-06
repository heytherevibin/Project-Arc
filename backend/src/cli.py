"""
Arc CLI

Command-line interface for the Arc penetration testing framework.
Provides commands for scanning, mission management, status checks,
and report generation by calling the REST API.
"""

from __future__ import annotations

import json
import sys
from typing import Any

import click
import httpx


DEFAULT_API_URL = "http://localhost:8080/api/v1"


class ArcClient:
    """HTTP client wrapper for the Arc API."""

    def __init__(self, base_url: str, token: str | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.Client(base_url=self.base_url, headers=headers, timeout=30)

    def get(self, path: str, **kwargs: Any) -> Any:
        resp = self._client.get(path, **kwargs)
        resp.raise_for_status()
        return resp.json()

    def post(self, path: str, data: Any = None, **kwargs: Any) -> Any:
        resp = self._client.post(path, json=data, **kwargs)
        resp.raise_for_status()
        return resp.json()


pass_client = click.make_pass_decorator(ArcClient, ensure=True)


@click.group()
@click.option("--api-url", envvar="ARC_API_URL", default=DEFAULT_API_URL, help="Arc API base URL")
@click.option("--token", envvar="ARC_TOKEN", default=None, help="API authentication token")
@click.pass_context
def main(ctx: click.Context, api_url: str, token: str | None) -> None:
    """Arc - Autonomous Red Team Framework CLI"""
    ctx.ensure_object(dict)
    ctx.obj = ArcClient(api_url, token)


# =========================================================================
# Scan commands
# =========================================================================

@main.command()
@click.argument("target")
@click.option("--project", "-p", required=True, help="Project ID")
@click.option("--type", "-t", "scan_type", default="full", help="Scan type: full, subdomain, port, vuln")
@click.pass_obj
def scan(client: ArcClient, target: str, project: str, scan_type: str) -> None:
    """Start a scan against a target."""
    click.echo(f"Starting {scan_type} scan on {target}...")

    type_map: dict[str, list[str]] = {
        "full": ["subdomain_discovery", "port_scan", "http_probe", "vulnerability_scan"],
        "subdomain": ["subdomain_discovery"],
        "port": ["port_scan"],
        "vuln": ["vulnerability_scan"],
    }
    tools = type_map.get(scan_type, type_map["full"])

    try:
        result = client.post("/scans", data={
            "project_id": project,
            "target": target,
            "scan_type": tools[0],
            "tools": tools,
        })
        click.echo(f"Scan started: {result.get('scan_id', 'unknown')}")
        click.echo(json.dumps(result, indent=2))
    except httpx.HTTPStatusError as e:
        click.echo(f"Error: {e.response.status_code} - {e.response.text}", err=True)
        sys.exit(1)


# =========================================================================
# Mission commands
# =========================================================================

@main.group()
def mission() -> None:
    """Manage penetration test missions."""
    pass


@mission.command("create")
@click.option("--project", "-p", required=True, help="Project ID")
@click.option("--target", "-t", required=True, help="Target domain or IP")
@click.option("--objective", "-o", default="Full penetration test", help="Mission objective")
@click.pass_obj
def mission_create(client: ArcClient, project: str, target: str, objective: str) -> None:
    """Create a new mission."""
    try:
        result = client.post("/missions", data={
            "project_id": project,
            "target": target,
            "objective": objective,
        })
        click.echo(f"Mission created: {result.get('mission_id', 'unknown')}")
        click.echo(json.dumps(result, indent=2))
    except httpx.HTTPStatusError as e:
        click.echo(f"Error: {e.response.status_code} - {e.response.text}", err=True)
        sys.exit(1)


@mission.command("list")
@click.option("--project", "-p", default=None, help="Filter by project ID")
@click.pass_obj
def mission_list(client: ArcClient, project: str | None) -> None:
    """List all missions."""
    try:
        params = {}
        if project:
            params["project_id"] = project
        result = client.get("/missions", params=params)
        missions = result if isinstance(result, list) else result.get("missions", [])

        if not missions:
            click.echo("No missions found.")
            return

        for m in missions:
            status = m.get("status", "unknown")
            phase = m.get("current_phase", "")
            click.echo(
                f"  [{status:>10}] {m.get('mission_id', '?')[:12]}  "
                f"phase={phase:>16}  target={m.get('target', '?')}"
            )
    except httpx.HTTPStatusError as e:
        click.echo(f"Error: {e.response.status_code} - {e.response.text}", err=True)
        sys.exit(1)


# =========================================================================
# Status command
# =========================================================================

@main.command()
@click.pass_obj
def status(client: ArcClient) -> None:
    """Show Arc system status."""
    try:
        result = client.get("/health")
        click.echo("Arc System Status")
        click.echo("=" * 40)
        for key, value in result.items():
            click.echo(f"  {key}: {value}")
    except httpx.HTTPStatusError as e:
        click.echo(f"Error: {e.response.status_code} - {e.response.text}", err=True)
        sys.exit(1)
    except httpx.ConnectError:
        click.echo("Error: Cannot connect to Arc API. Is the server running?", err=True)
        sys.exit(1)


# =========================================================================
# Report commands
# =========================================================================

@main.group()
def report() -> None:
    """Generate and manage reports."""
    pass


@report.command("generate")
@click.option("--project", "-p", required=True, help="Project ID")
@click.option("--type", "-t", "report_type", default="technical", help="Report type: technical, executive, remediation, compliance")
@click.option("--output", "-o", default=None, help="Output file path")
@click.pass_obj
def report_generate(client: ArcClient, project: str, report_type: str, output: str | None) -> None:
    """Generate a report for a project."""
    click.echo(f"Generating {report_type} report for project {project}...")

    try:
        result = client.post("/reports/generate", data={
            "project_id": project,
            "report_type": report_type,
        })

        report_content = result.get("content", result.get("report", ""))

        if output:
            with open(output, "w") as f:
                f.write(report_content if isinstance(report_content, str) else json.dumps(report_content, indent=2))
            click.echo(f"Report saved to {output}")
        else:
            click.echo(report_content if isinstance(report_content, str) else json.dumps(report_content, indent=2))

    except httpx.HTTPStatusError as e:
        click.echo(f"Error: {e.response.status_code} - {e.response.text}", err=True)
        sys.exit(1)


# =========================================================================
# Projects command
# =========================================================================

@main.command("projects")
@click.pass_obj
def projects(client: ArcClient) -> None:
    """List all projects."""
    try:
        result = client.get("/projects")
        items = result if isinstance(result, list) else result.get("projects", [])

        if not items:
            click.echo("No projects found.")
            return

        for p in items:
            status_str = p.get("status", "unknown")
            click.echo(
                f"  [{status_str:>10}] {p.get('project_id', '?')[:12]}  "
                f"{p.get('name', 'Unnamed')}"
            )
    except httpx.HTTPStatusError as e:
        click.echo(f"Error: {e.response.status_code} - {e.response.text}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
