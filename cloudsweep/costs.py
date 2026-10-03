"""Rough monthly cost estimates for waste findings.

These are back-of-the-envelope ESTIMATES from public unit prices
(us-east-1, on-demand), not bills. They exist to rank findings by
approximate savings, nothing more.
"""

from __future__ import annotations

from .findings import Finding

# Public on-demand unit prices, us-east-1 (documented as constants so the
# assumptions are visible, not buried).
EBS_GB_MONTH = {
    "gp2": 0.10,
    "gp3": 0.08,
    "io1": 0.125,
    "io2": 0.125,
    "st1": 0.045,
    "sc1": 0.025,
    "standard": 0.05,
}
EBS_SNAPSHOT_GB_MONTH = 0.05
DEFAULT_EBS_GB_MONTH = EBS_GB_MONTH["gp3"]  # sensible default for unknown types


def estimate_cost_usd(cost_basis: dict | None) -> float | None:
    """Return an estimated monthly USD cost, or None when not cost-bearing."""
    if not cost_basis:
        return None
    kind = cost_basis.get("kind")
    gb = float(cost_basis.get("gb", 0))
    if kind == "ebs":
        rate = EBS_GB_MONTH.get(cost_basis.get("volume_type", ""), DEFAULT_EBS_GB_MONTH)
        return round(gb * rate, 2)
    if kind == "ebs_snapshot":
        return round(gb * EBS_SNAPSHOT_GB_MONTH, 2)
    return None


def attach_costs(findings: list[Finding]) -> list[Finding]:
    """Fill in ``est_monthly_cost_usd`` on each finding from its cost basis."""
    for f in findings:
        f.est_monthly_cost_usd = estimate_cost_usd(f.cost_basis)
    return findings


def total_monthly_waste_usd(findings: list[Finding]) -> float:
    return round(sum(f.est_monthly_cost_usd or 0.0 for f in findings), 2)
