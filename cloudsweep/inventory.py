"""Read-only resource inventory via boto3.

Every function only calls describe/list/get APIs — nothing here creates,
modifies, or deletes anything.
"""

from __future__ import annotations

import boto3
from botocore.exceptions import ClientError


def _client(service: str, region: str | None, session: boto3.Session | None):
    session = session or boto3.Session()
    kwargs = {"region_name": region} if region else {}
    return session.client(service, **kwargs)


# ---------------------------------------------------------------- EC2
def discover_ec2_instances(region: str, session: boto3.Session | None = None) -> list[dict]:
    ec2 = _client("ec2", region, session)
    out: list[dict] = []
    for page in ec2.get_paginator("describe_instances").paginate():
        for r in page["Reservations"]:
            for i in r["Instances"]:
                out.append(
                    {
                        "id": i["InstanceId"],
                        "region": region,
                        "state": i["State"]["Name"],
                        "instance_type": i.get("InstanceType", ""),
                        "launch_time": i.get("LaunchTime"),
                        "tags": {t["Key"]: t["Value"] for t in i.get("Tags", [])},
                    }
                )
    return out


def discover_ebs_volumes(region: str, session: boto3.Session | None = None) -> list[dict]:
    ec2 = _client("ec2", region, session)
    out: list[dict] = []
    for page in ec2.get_paginator("describe_volumes").paginate():
        for v in page["Volumes"]:
            out.append(
                {
                    "id": v["VolumeId"],
                    "region": region,
                    "state": v["State"],
                    "size_gb": v["Size"],
                    "volume_type": v.get("VolumeType", "gp3"),
                    "create_time": v.get("CreateTime"),
                    "attachments": [a.get("InstanceId") for a in v.get("Attachments", [])],
                }
            )
    return out


def discover_snapshots(region: str, session: boto3.Session | None = None) -> list[dict]:
    ec2 = _client("ec2", region, session)
    # Resolve our account id and filter client-side too: some backends
    # (including moto) ignore the OwnerIds filter, and the pre-seeded
    # public snapshots must never be attributed to this account.
    account_id = _client("sts", region, session).get_caller_identity()["Account"]
    out: list[dict] = []
    for page in ec2.get_paginator("describe_snapshots").paginate(OwnerIds=["self"]):
        for s in page["Snapshots"]:
            if s.get("OwnerId") != account_id:
                continue
            out.append(
                {
                    "id": s["SnapshotId"],
                    "region": region,
                    "volume_size_gb": s.get("VolumeSize", 0),
                    "start_time": s.get("StartTime"),
                    "volume_id": s.get("VolumeId"),
                }
            )
    return out


def discover_amis(region: str, session: boto3.Session | None = None) -> list[dict]:
    ec2 = _client("ec2", region, session)
    out: list[dict] = []
    for img in ec2.describe_images(Owners=["self"])["Images"]:
        out.append(
            {
                "id": img["ImageId"],
                "region": region,
                "name": img.get("Name", ""),
                "creation_date": img.get("CreationDate"),
            }
        )
    return out


# ---------------------------------------------------------------- S3 (global)
def discover_s3_buckets(session: boto3.Session | None = None) -> list[dict]:
    s3 = _client("s3", None, session)
    out: list[dict] = []
    for b in s3.list_buckets()["Buckets"]:
        name = b["Name"]
        try:
            s3.get_bucket_encryption(Bucket=name)
            encrypted = True
        except ClientError as e:
            if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                encrypted = False
            else:
                raise
        versioning = s3.get_bucket_versioning(Bucket=name).get("Status", "")
        out.append(
            {
                "id": name,
                "region": "global",
                "creation_date": b.get("CreationDate"),
                "default_encryption": encrypted,
                "versioning_enabled": versioning == "Enabled",
            }
        )
    return out


# ---------------------------------------------------------------- RDS
def discover_rds_instances(region: str, session: boto3.Session | None = None) -> list[dict]:
    rds = _client("rds", region, session)
    out: list[dict] = []
    for page in rds.get_paginator("describe_db_instances").paginate():
        for d in page["DBInstances"]:
            out.append(
                {
                    "id": d["DBInstanceIdentifier"],
                    "region": region,
                    "engine": d.get("Engine", ""),
                    "instance_class": d.get("DBInstanceClass", ""),
                    "deletion_protection": bool(d.get("DeletionProtection", False)),
                    "backup_retention_days": int(d.get("BackupRetentionPeriod", 0)),
                    "status": d.get("DBInstanceStatus", ""),
                }
            )
    return out


# ---------------------------------------------------------------- Lambda
def discover_lambda_functions(region: str, session: boto3.Session | None = None) -> list[dict]:
    lam = _client("lambda", region, session)
    out: list[dict] = []
    for page in lam.get_paginator("list_functions").paginate():
        for f in page["Functions"]:
            out.append(
                {
                    "id": f["FunctionName"],
                    "region": region,
                    "runtime": f.get("Runtime", ""),
                    "last_modified": f.get("LastModified", ""),
                }
            )
    return out


# ---------------------------------------------------------------- all
def inventory_all(regions: list[str], session: boto3.Session | None = None) -> dict[str, list[dict]]:
    """Discover resources in each region. S3 is global and fetched once."""
    inv: dict[str, list[dict]] = {
        "ec2_instances": [],
        "ebs_volumes": [],
        "snapshots": [],
        "amis": [],
        "s3_buckets": [],
        "rds_instances": [],
        "lambda_functions": [],
    }
    for region in regions:
        inv["ec2_instances"].extend(discover_ec2_instances(region, session))
        inv["ebs_volumes"].extend(discover_ebs_volumes(region, session))
        inv["snapshots"].extend(discover_snapshots(region, session))
        inv["amis"].extend(discover_amis(region, session))
        inv["rds_instances"].extend(discover_rds_instances(region, session))
        inv["lambda_functions"].extend(discover_lambda_functions(region, session))
    inv["s3_buckets"] = discover_s3_buckets(session)
    return inv
