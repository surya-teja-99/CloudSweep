"""End-to-end audit tests on moto-mocked accounts (fully offline)."""

import io
import os
import zipfile
from datetime import datetime, timedelta, timezone

import boto3
import pytest
from moto import mock_aws

os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

import cloudsweep.inventory as inv_mod  # noqa: E402
from cloudsweep import run_audit  # noqa: E402

REGION = "us-east-1"
NOW = datetime(2026, 10, 3, tzinfo=timezone.utc)


def _seed_bad_account():
    """Account with known waste/misconfigurations (nothing age-based: moto
    timestamps everything at creation time)."""
    ec2 = boto3.client("ec2", region_name=REGION)
    iid = ec2.run_instances(ImageId="ami-12345", MinCount=1, MaxCount=1)["Instances"][0]["InstanceId"]
    ec2.create_volume(AvailabilityZone="us-east-1a", Size=20, VolumeType="gp3")

    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="bad-bucket")

    rds = boto3.client("rds", region_name=REGION)
    rds.create_db_instance(
        DBInstanceIdentifier="exposed-db", DBInstanceClass="db.t3.micro",
        Engine="postgres", MasterUsername="u", MasterUserPassword="pw123456",
        AllocatedStorage=20, DeletionProtection=False,
    )
    return iid


def _seed_clean_account():
    ec2 = boto3.client("ec2", region_name=REGION)
    iid = ec2.run_instances(ImageId="ami-12345", MinCount=1, MaxCount=1)["Instances"][0]["InstanceId"]
    v = ec2.create_volume(AvailabilityZone="us-east-1a", Size=8, VolumeType="gp3")["VolumeId"]
    ec2.attach_volume(VolumeId=v, InstanceId=iid, Device="/dev/sdf")

    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="good-bucket")
    s3.put_bucket_encryption(
        Bucket="good-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    s3.put_bucket_versioning(
        Bucket="good-bucket", VersioningConfiguration={"Status": "Enabled"}
    )

    rds = boto3.client("rds", region_name=REGION)
    rds.create_db_instance(
        DBInstanceIdentifier="safe-db", DBInstanceClass="db.t3.micro",
        Engine="postgres", MasterUsername="u", MasterUserPassword="pw123456",
        AllocatedStorage=20, DeletionProtection=True, BackupRetentionPeriod=7,
    )


def test_bad_account_fires_expected_rules():
    with mock_aws():
        _seed_bad_account()
        result = run_audit([REGION])
    rules = {f.rule for f in result.findings}
    assert rules == {
        "unattached_ebs_volume",
        "s3_no_default_encryption",
        "s3_no_versioning",
        "rds_no_deletion_protection",
    }
    waste = {f.rule: f.est_monthly_cost_usd for f in result.findings}
    assert waste["unattached_ebs_volume"] == 20 * 0.08
    assert result.total_monthly_waste_usd == 1.60


def test_clean_account_zero_findings():
    with mock_aws():
        _seed_clean_account()
        result = run_audit([REGION])
    assert result.findings == []
    assert result.total_monthly_waste_usd == 0.0


def test_age_rules_wired_end_to_end(monkeypatch):
    """Backdated items through the real engine: proves rule wiring, since
    moto stamps everything with the current time."""
    old_snap = {
        "id": "snap-old", "region": REGION, "volume_size_gb": 10,
        "start_time": NOW - timedelta(days=100), "volume_id": "vol-x",
    }
    old_inst = {
        "id": "i-old", "region": REGION, "state": "stopped",
        "instance_type": "t3.micro",
        "launch_time": NOW - timedelta(days=40), "tags": {},
    }
    monkeypatch.setattr(inv_mod, "discover_snapshots", lambda region, session=None: [old_snap])
    monkeypatch.setattr(inv_mod, "discover_ec2_instances", lambda region, session=None: [old_inst])
    monkeypatch.setattr(inv_mod, "discover_ebs_volumes", lambda region, session=None: [])
    monkeypatch.setattr(inv_mod, "discover_amis", lambda region, session=None: [])
    monkeypatch.setattr(inv_mod, "discover_rds_instances", lambda region, session=None: [])
    monkeypatch.setattr(inv_mod, "discover_lambda_functions", lambda region, session=None: [])
    monkeypatch.setattr(inv_mod, "discover_s3_buckets", lambda session=None: [])

    with mock_aws():
        result = run_audit([REGION], now=NOW)
    rules = {f.rule: f for f in result.findings}
    assert set(rules) == {"old_ebs_snapshot", "stopped_ec2_instance_old"}
    assert rules["old_ebs_snapshot"].est_monthly_cost_usd == 10 * 0.05


def test_min_severity_filter():
    with mock_aws():
        _seed_bad_account()
        result = run_audit([REGION])
    highs = result.filter_severity("high")
    assert {f.rule for f in highs} == {"s3_no_default_encryption", "rds_no_deletion_protection"}
    assert all(f.severity == "high" for f in highs)
