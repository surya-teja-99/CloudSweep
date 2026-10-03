"""CloudSweep demo: audits a fully mocked AWS account (moto, offline).

Seeds a mix of wasteful and clean resources, runs the audit, and prints
the findings table with estimated monthly waste. No real AWS credentials
needed; nothing touches the network.
"""

from __future__ import annotations

import io
import os
import sys
import zipfile
from pathlib import Path

os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from moto import mock_aws  # noqa: E402

import boto3  # noqa: E402
from cloudsweep import run_audit  # noqa: E402
from cloudsweep.reporter import report_table  # noqa: E402

REGION = "us-east-1"


def seed_demo_account() -> None:
    ec2 = boto3.client("ec2", region_name=REGION)
    iid = ec2.run_instances(ImageId="ami-12345", MinCount=1, MaxCount=1)["Instances"][0]["InstanceId"]

    # WASTE: 100 GB gp3 volume nobody attached
    ec2.create_volume(AvailabilityZone="us-east-1a", Size=100, VolumeType="gp3")
    # CLEAN: attached volume on the running instance
    v = ec2.create_volume(AvailabilityZone="us-east-1a", Size=8, VolumeType="gp3")["VolumeId"]
    ec2.attach_volume(VolumeId=v, InstanceId=iid, Device="/dev/sdf")

    s3 = boto3.client("s3", region_name=REGION)
    # WASTE: no encryption, no versioning
    s3.create_bucket(Bucket="demo-unprotected-bucket")
    # CLEAN: encrypted + versioned
    s3.create_bucket(Bucket="demo-locked-bucket")
    s3.put_bucket_encryption(
        Bucket="demo-locked-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    s3.put_bucket_versioning(
        Bucket="demo-locked-bucket", VersioningConfiguration={"Status": "Enabled"}
    )

    rds = boto3.client("rds", region_name=REGION)
    # WASTE: deletion protection off
    rds.create_db_instance(
        DBInstanceIdentifier="demo-exposed-db", DBInstanceClass="db.t3.micro",
        Engine="postgres", MasterUsername="u", MasterUserPassword="pw123456",
        AllocatedStorage=20, DeletionProtection=False,
    )
    # CLEAN: protected with backups
    rds.create_db_instance(
        DBInstanceIdentifier="demo-safe-db", DBInstanceClass="db.t3.micro",
        Engine="postgres", MasterUsername="u", MasterUserPassword="pw123456",
        AllocatedStorage=20, DeletionProtection=True, BackupRetentionPeriod=7,
    )

    lam = boto3.client("lambda", region_name=REGION)
    iam = boto3.client("iam", region_name=REGION)
    role_arn = iam.create_role(
        RoleName="lambda-demo",
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
        FunctionName="demo-func", Runtime="python3.12",
        Role=role_arn, Handler="index.handler",
        Code={"ZipFile": buf.getvalue()},
    )


def main() -> None:
    print("=== CloudSweep demo (mocked AWS account, fully offline) ===\n")
    with mock_aws():
        seed_demo_account()
        result = run_audit([REGION])
    report_table(result)


if __name__ == "__main__":
    main()
