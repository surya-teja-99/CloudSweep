"""Pure rule tests with synthetic inventory and explicit timestamps."""

from datetime import datetime, timedelta, timezone

import pytest

from cloudsweep.findings import (
    rule_old_snapshots,
    rule_rds_no_deletion_protection,
    rule_s3_no_encryption,
    rule_s3_no_versioning,
    rule_stopped_ec2_old,
    rule_unattached_ebs_volumes,
)

NOW = datetime(2026, 10, 3, tzinfo=timezone.utc)


def vol(state="available", size=20, vtype="gp3", attachments=()):
    return {
        "id": "vol-1", "region": "us-east-1", "state": state,
        "size_gb": size, "volume_type": vtype,
        "create_time": NOW, "attachments": list(attachments),
    }


def test_unattached_volume_fires():
    findings = rule_unattached_ebs_volumes([vol()])
    assert len(findings) == 1
    f = findings[0]
    assert f.rule == "unattached_ebs_volume" and f.severity == "medium"
    assert f.cost_basis == {"kind": "ebs", "gb": 20, "volume_type": "gp3"}


def test_attached_volume_no_finding():
    assert rule_unattached_ebs_volumes([vol(state="in-use", attachments=("i-1",))]) == []


def inst(state="stopped", days_ago=31):
    return {
        "id": "i-1", "region": "us-east-1", "state": state,
        "instance_type": "t3.micro",
        "launch_time": NOW - timedelta(days=days_ago), "tags": {},
    }


def test_stopped_old_instance_fires():
    assert len(rule_stopped_ec2_old([inst(days_ago=31)], NOW)) == 1


def test_stopped_recent_instance_no_finding():
    assert rule_stopped_ec2_old([inst(days_ago=29)], NOW) == []


def test_running_old_instance_no_finding():
    assert rule_stopped_ec2_old([inst(state="running", days_ago=365)], NOW) == []


def test_boundary_exactly_30_days_does_not_fire():
    # strictly older than 30 days
    assert rule_stopped_ec2_old([inst(days_ago=30)], NOW) == []


def snap(days_ago=91, size=10):
    return {
        "id": "snap-1", "region": "us-east-1", "volume_size_gb": size,
        "start_time": NOW - timedelta(days=days_ago), "volume_id": "vol-1",
    }


def test_old_snapshot_fires_with_cost_basis():
    findings = rule_old_snapshots([snap(days_ago=91)], NOW)
    assert len(findings) == 1
    assert findings[0].cost_basis == {"kind": "ebs_snapshot", "gb": 10}


def test_fresh_snapshot_no_finding():
    assert rule_old_snapshots([snap(days_ago=89)], NOW) == []


def bucket(enc=True, ver=True):
    return {
        "id": "bkt", "region": "global", "creation_date": NOW,
        "default_encryption": enc, "versioning_enabled": ver,
    }


def test_unencrypted_bucket_fires_high():
    findings = rule_s3_no_encryption([bucket(enc=False)])
    assert len(findings) == 1 and findings[0].severity == "high"


def test_encrypted_bucket_no_finding():
    assert rule_s3_no_encryption([bucket(enc=True)]) == []


def test_unversioned_bucket_fires():
    assert len(rule_s3_no_versioning([bucket(ver=False)])) == 1
    assert rule_s3_no_versioning([bucket(ver=True)]) == []


def rds(protected=False):
    return {
        "id": "db-1", "region": "us-east-1", "engine": "postgres",
        "instance_class": "db.t3.micro", "deletion_protection": protected,
        "backup_retention_days": 0, "status": "available",
    }


def test_rds_without_deletion_protection_fires_high():
    findings = rule_rds_no_deletion_protection([rds(protected=False)])
    assert len(findings) == 1 and findings[0].severity == "high"


def test_rds_with_deletion_protection_no_finding():
    assert rule_rds_no_deletion_protection([rds(protected=True)]) == []
