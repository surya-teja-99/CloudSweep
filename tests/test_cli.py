"""CLI tests: --json, --min-severity and --version (moto-mocked, offline)."""

import json
import os

import boto3
import pytest
from moto import mock_aws

os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from cloudsweep.cli import main  # noqa: E402

REGION = "us-east-1"


def _seed_bad_account():
    ec2 = boto3.client("ec2", region_name=REGION)
    ec2.run_instances(ImageId="ami-12345", MinCount=1, MaxCount=1)
    ec2.create_volume(AvailabilityZone="us-east-1a", Size=20, VolumeType="gp3")

    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="bad-bucket")

    rds = boto3.client("rds", region_name=REGION)
    rds.create_db_instance(
        DBInstanceIdentifier="exposed-db", DBInstanceClass="db.t3.micro",
        Engine="postgres", MasterUsername="u", MasterUserPassword="pw123456",
        AllocatedStorage=20, DeletionProtection=False,
    )


def test_cli_json_output(capsys):
    with mock_aws():
        _seed_bad_account()
        assert main(["audit", "--regions", REGION, "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert {f["rule"] for f in out["findings"]} == {
        "unattached_ebs_volume",
        "s3_no_default_encryption",
        "s3_no_versioning",
        "rds_no_deletion_protection",
    }
    assert out["total_estimated_monthly_waste_usd"] == 1.60


def test_cli_min_severity_high_json(capsys):
    with mock_aws():
        _seed_bad_account()
        assert main(["audit", "--regions", REGION, "--json", "--min-severity", "high"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert {f["rule"] for f in out["findings"]} == {
        "s3_no_default_encryption",
        "rds_no_deletion_protection",
    }
    assert all(f["severity"] == "high" for f in out["findings"])
    assert out["total_estimated_monthly_waste_usd"] == 0.0


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "0.1.0" in capsys.readouterr().out
