"""Reporters: rich tables for humans, JSON for machines."""

from __future__ import annotations

import json
from dataclasses import asdict

from rich.console import Console
from rich.table import Table

from .audit import AuditResult

_SEVERITY_STYLE = {"high": "bold red", "medium": "yellow", "low": "dim"}


def finding_to_dict(f) -> dict:
    d = asdict(f)
    d.pop("cost_basis", None)
    return d


def report_json(result: AuditResult) -> str:
    return json.dumps(
        {
            "regions": result.regions,
            "inventory_counts": result.inventory_counts,
            "total_estimated_monthly_waste_usd": result.total_monthly_waste_usd,
            "findings": [finding_to_dict(f) for f in result.findings],
        },
        indent=2,
        default=str,
    )


def report_table(result: AuditResult, console: Console | None = None) -> None:
    console = console or Console()
    if not result.findings:
        console.print("[green]No findings — account looks clean.[/green]")
    for severity in ("high", "medium", "low"):
        group = [f for f in result.findings if f.severity == severity]
        if not group:
            continue
        table = Table(title=f"{severity.upper()} severity ({len(group)})")
        table.add_column("Rule", style="cyan")
        table.add_column("Resource")
        table.add_column("Region")
        table.add_column("Detail", max_width=60)
        table.add_column("Est. $/mo", justify="right")
        for f in group:
            cost = f"${f.est_monthly_cost_usd:.2f}" if f.est_monthly_cost_usd else "—"
            table.add_row(f.rule, f.resource_id, f.region, f.detail, cost)
        console.print(table)

    counts = ", ".join(f"{k}: {v}" for k, v in result.inventory_counts.items() if v)
    console.print(f"\n[dim]Inventoried — {counts or 'nothing found'}[/dim]")
    console.print(
        f"[bold]Estimated monthly waste: ${result.total_monthly_waste_usd:.2f}[/bold] "
        "[dim](rough estimate, not a bill)[/dim]"
    )
