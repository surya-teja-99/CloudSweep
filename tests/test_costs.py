"""Cost math unit tests."""

from cloudsweep.costs import (
    attach_costs,
    estimate_cost_usd,
    total_monthly_waste_usd,
)
from cloudsweep.findings import Finding


def mkfinding(cost_basis):
    return Finding(
        resource_type="ebs_volume", resource_id="vol-1", region="us-east-1",
        rule="unattached_ebs_volume", severity="medium",
        detail="x", cost_basis=cost_basis,
    )


def test_gp3_volume_cost():
    assert estimate_cost_usd({"kind": "ebs", "gb": 20, "volume_type": "gp3"}) == 1.60


def test_gp2_volume_cost():
    assert estimate_cost_usd({"kind": "ebs", "gb": 10, "volume_type": "gp2"}) == 1.00


def test_snapshot_cost():
    assert estimate_cost_usd({"kind": "ebs_snapshot", "gb": 8}) == 0.40


def test_unknown_volume_type_uses_gp3_default():
    assert estimate_cost_usd({"kind": "ebs", "gb": 10, "volume_type": "weird"}) == 0.80


def test_no_basis_no_cost():
    assert estimate_cost_usd(None) is None


def test_attach_costs_fills_findings():
    findings = [mkfinding({"kind": "ebs", "gb": 20, "volume_type": "gp3"}),
                mkfinding(None)]
    attach_costs(findings)
    assert findings[0].est_monthly_cost_usd == 1.60
    assert findings[1].est_monthly_cost_usd is None


def test_total_waste_sums_only_costed():
    findings = [mkfinding({"kind": "ebs", "gb": 20, "volume_type": "gp3"}),
                mkfinding({"kind": "ebs_snapshot", "gb": 8}),
                mkfinding(None)]
    attach_costs(findings)
    assert total_monthly_waste_usd(findings) == 2.00
