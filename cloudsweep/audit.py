"""Audit orchestration: inventory -> rules -> costs."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

import boto3

from . import costs
from .findings import Finding, run_all_rules
from .inventory import inventory_all

SEVERITIES = ("high", "medium", "low")


@dataclass
class AuditResult:
    findings: list[Finding]
    inventory_counts: dict[str, int]
    total_monthly_waste_usd: float
    regions: list[str] = field(default_factory=list)

    def filter_severity(self, min_severity: str) -> list[Finding]:
        order = {s: i for i, s in enumerate(SEVERITIES)}
        cutoff = order[min_severity]
        return [f for f in self.findings if order[f.severity] <= cutoff]


def run_audit(
    regions: list[str],
    session: boto3.Session | None = None,
    now: datetime | None = None,
) -> AuditResult:
    inventory = inventory_all(regions, session)
    findings = run_all_rules(inventory, now)
    costs.attach_costs(findings)
    counts = {k: len(v) for k, v in inventory.items()}
    return AuditResult(
        findings=findings,
        inventory_counts=counts,
        total_monthly_waste_usd=costs.total_monthly_waste_usd(findings),
        regions=regions,
    )
