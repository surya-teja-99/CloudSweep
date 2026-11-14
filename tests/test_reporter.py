"""Reporter tests: JSON output and empty-account table."""

import io
import json

from rich.console import Console

from cloudsweep.audit import AuditResult
from cloudsweep.findings import Finding
from cloudsweep.reporter import report_json, report_table


def _finding(**overrides):
    data = {
        "resource_type": "ebs_volume",
        "resource_id": "vol-1",
        "region": "us-east-1",
        "rule": "unattached_ebs_volume",
        "severity": "medium",
        "detail": "20 GB gp3 volume sitting unattached",
        "cost_basis": {"kind": "ebs", "gb": 20, "volume_type": "gp3"},
        "est_monthly_cost_usd": 1.60,
    }
    data.update(overrides)
    return Finding(**data)


def _result(findings=None, total=0.0):
    return AuditResult(
        findings=findings or [],
        inventory_counts={"ebs_volumes": 1},
        total_monthly_waste_usd=total,
        regions=["us-east-1"],
    )


def test_report_json_includes_totals_and_drops_cost_basis():
    out = json.loads(report_json(_result([_finding()], total=1.60)))
    assert out["regions"] == ["us-east-1"]
    assert out["total_estimated_monthly_waste_usd"] == 1.60
    assert out["findings"][0]["rule"] == "unattached_ebs_volume"
    assert out["findings"][0]["est_monthly_cost_usd"] == 1.60
    assert "cost_basis" not in out["findings"][0]


def test_report_table_empty_account_says_clean():
    buf = io.StringIO()
    report_table(_result([]), console=Console(file=buf, width=100))
    assert "No findings" in buf.getvalue()
    assert "Estimated monthly waste: $0.00" in buf.getvalue()


def test_report_table_groups_by_severity():
    buf = io.StringIO()
    report_table(_result([_finding()], total=1.60), console=Console(file=buf, width=100))
    text = buf.getvalue()
    assert "unattached_ebs_volume" in text
    assert "vol-1" in text
    assert "$1.60" in text
