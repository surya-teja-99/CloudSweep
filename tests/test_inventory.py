"""Inventory discovery tests against a moto-mocked account (fully offline)."""

import io
import os
import zipfile

import boto3
import pytest
from moto import mock_aws

os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from cloudsweep import inventory  # noqa: E402

REGION = "us-east-1"


@pytest.fixture()
def seeded():
    with mock_aws():
        ec2 = boto3.client("ec2", region_name=REGION)
        instances = ec2.run_instances(ImageId="ami-12345", MinCount=1, MaxCount=1)["Instances"]
        iid = instances[0]["InstanceId"]
        loose = ec2.create_volume(AvailabilityZone="us-east-1a", Size=20, VolumeType="gp3")["VolumeId"]
        attached = ec2.create_volume(AvailabilityZone="us-east-1a", Size=8, VolumeType="gp3")["VolumeId"]
        ec2.attach_volume(VolumeId=attached, InstanceId=iid, Device="/dev/sdf")
        snap = ec2.create_snapshot(VolumeId=attached)["SnapshotId"]

        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket="plain-bucket")
        s3.create_bucket(Bucket="locked-bucket")
        s3.put_bucket_encryption(
            Bucket="locked-bucket",
            ServerSideEncryptionConfiguration={
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            },
        )
        s3.put_bucket_versioning(
            Bucket="locked-bucket", VersioningConfiguration={"Status": "Enabled"}
        )

        rds = boto3.client("rds", region_name=REGION)
        rds.create_db_instance(
            DBInstanceIdentifier="exposed-db", DBInstanceClass="db.t3.micro",
            Engine="postgres", MasterUsername="u", MasterUserPassword="pw123456",
            AllocatedStorage=20, DeletionProtection=False,
        )

        lam = boto3.client("lambda", region_name=REGION)
        iam = boto3.client("iam", region_name=REGION)
        role_arn = iam.create_role(
            RoleName="lambda-x",
            AssumeRolePolicyDocument=(
                '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
                '"Principal":{"Service":"lambda.amazonaws.com"},'
                '"Action":"sts:AssumeRole"}]}'
            ),
        )["Role"]["Arn"]
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("index.py", "def handler(e, c): return e")
        lam.create_function(
            FunctionName="my-func", Runtime="python3.12",
            Role=role_arn, Handler="index.handler",
            Code={"ZipFile": buf.getvalue()},
        )
        yield {"loose_volume": loose, "attached_volume": attached,
               "instance": iid, "snapshot": snap}


def test_discovers_ec2_instances(seeded):
    found = inventory.discover_ec2_instances(REGION)
    assert [i["id"] for i in found] == [seeded["instance"]]
    assert found[0]["state"] == "running"


def test_discovers_volumes_with_attachment_state(seeded):
    vols = {v["id"]: v for v in inventory.discover_ebs_volumes(REGION)}
    assert vols[seeded["loose_volume"]]["state"] == "available"
    assert vols[seeded["loose_volume"]]["attachments"] == []
    assert vols[seeded["attached_volume"]]["attachments"] == [seeded["instance"]]


def test_discovers_snapshots(seeded):
    snaps = inventory.discover_snapshots(REGION)
    assert [s["id"] for s in snaps] == [seeded["snapshot"]]
    assert snaps[0]["volume_size_gb"] == 8


def test_discovers_s3_encryption_and_versioning(seeded):
    buckets = {b["id"]: b for b in inventory.discover_s3_buckets()}
    assert buckets["plain-bucket"]["default_encryption"] is False
    assert buckets["plain-bucket"]["versioning_enabled"] is False
    assert buckets["locked-bucket"]["default_encryption"] is True
    assert buckets["locked-bucket"]["versioning_enabled"] is True


def test_discovers_rds_deletion_protection(seeded):
    dbs = {d["id"]: d for d in inventory.discover_rds_instances(REGION)}
    assert dbs["exposed-db"]["deletion_protection"] is False


def test_discovers_lambda_functions(seeded):
    funcs = inventory.discover_lambda_functions(REGION)
    assert [f["id"] for f in funcs] == ["my-func"]
    assert funcs[0]["runtime"] == "python3.12"


def test_inventory_all_counts(seeded):
    inv = inventory.inventory_all([REGION])
    assert len(inv["ec2_instances"]) == 1
    # run_instances also provisions a root volume (as on real AWS), so assert
    # the volumes we created are discovered rather than an exact count.
    vol_ids = {v["id"] for v in inv["ebs_volumes"]}
    assert seeded["loose_volume"] in vol_ids
    assert seeded["attached_volume"] in vol_ids
    assert len(inv["s3_buckets"]) == 2
    assert len(inv["rds_instances"]) == 1
    assert len(inv["lambda_functions"]) == 1
