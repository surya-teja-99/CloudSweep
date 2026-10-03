"""Hygiene rules. Each rule is a pure function over inventory items.

Rules never touch AWS — they only inspect the dicts produced by
``cloudsweep.inventory``. ``now`` is injectable so age thresholds are
exactly testable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone


@dataclass
class Finding:
    resource_type: str
    resource_id: str
    region: str
    rule: str
    severity: str  # high | medium | low
    detail: str
    cost_basis: dict | None = None  # e.g. {"kind": "ebs", "gb": 20, "volume_type": "gp3"}
    est_monthly_cost_usd: float | None = field(default=None, repr=False)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _older_than(ts: datetime | None, now: datetime, days: int) -> bool:
    if ts is None:
        return False
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return (now - ts) > timedelta(days=days)


def rule_unattached_ebs_volumes(volumes: list[dict], now: datetime | None = None) -> list[Finding]:
    """EBS volumes in 'available' state are paying for storage nobody uses."""
    return [
        Finding(
            resource_type="ebs_volume",
            resource_id=v["id"],
            region=v["region"],
            rule="unattached_ebs_volume",
            severity="medium",
            detail=f"{v['size_gb']} GB {v['volume_type']} volume sitting unattached (state: available)",
            cost_basis={"kind": "ebs", "gb": v["size_gb"], "volume_type": v["volume_type"]},
        )
        for v in volumes
        if v["state"] == "available" and not v["attachments"]
    ]


def rule_stopped_ec2_old(
    instances: list[dict], now: datetime | None = None, days: int = 30
) -> list[Finding]:
    """Stopped instances burn no compute but are usually forgotten; flag old ones."""
    now = now or _utcnow()
    return [
        Finding(
            resource_type="ec2_instance",
            resource_id=i["id"],
            region=i["region"],
            rule="stopped_ec2_instance_old",
            severity="medium",
            detail=(
                f"{i['instance_type']} stopped; launched "
                f"{i['launch_time'].date() if i.get('launch_time') else 'unknown'} "
                f"(>{days}d ago). Consider snapshotting + terminating."
            ),
        )
        for i in instances
        if i["state"] == "stopped" and _older_than(i.get("launch_time"), now, days)
    ]


def rule_old_snapshots(
    snapshots: list[dict], now: datetime | None = None, days: int = 90
) -> list[Finding]:
    """Snapshots older than 90 days are usually stale backups nobody will restore."""
    now = now or _utcnow()
    return [
        Finding(
            resource_type="ebs_snapshot",
            resource_id=s["id"],
            region=s["region"],
            rule="old_ebs_snapshot",
            severity="low",
            detail=(
                f"{s['volume_size_gb']} GB snapshot from "
                f"{s['start_time'].date() if s.get('start_time') else 'unknown'} "
                f"(>{days}d old)"
            ),
            cost_basis={"kind": "ebs_snapshot", "gb": s["volume_size_gb"]},
        )
        for s in snapshots
        if _older_than(s.get("start_time"), now, days)
    ]


def rule_s3_no_encryption(buckets: list[dict], now: datetime | None = None) -> list[Finding]:
    """Buckets without default encryption fail a basic security baseline."""
    return [
        Finding(
            resource_type="s3_bucket",
            resource_id=b["id"],
            region=b["region"],
            rule="s3_no_default_encryption",
            severity="high",
            detail="bucket has no default server-side encryption configured",
        )
        for b in buckets
        if not b["default_encryption"]
    ]


def rule_s3_no_versioning(buckets: list[dict], now: datetime | None = None) -> list[Finding]:
    """Without versioning, an overwrite or delete is unrecoverable."""
    return [
        Finding(
            resource_type="s3_bucket",
            resource_id=b["id"],
            region=b["region"],
            rule="s3_no_versioning",
            severity="medium",
            detail="bucket versioning is not enabled",
        )
        for b in buckets
        if not b["versioning_enabled"]
    ]


def rule_rds_no_deletion_protection(
    instances: list[dict], now: datetime | None = None
) -> list[Finding]:
    """RDS instances without deletion protection can be deleted with one call."""
    return [
        Finding(
            resource_type="rds_instance",
            resource_id=d["id"],
            region=d["region"],
            rule="rds_no_deletion_protection",
            severity="high",
            detail=f"{d['engine']} {d['instance_class']} has deletion protection disabled",
        )
        for d in instances
        if not d["deletion_protection"]
    ]


ALL_RULES = [
    ("ebs_volumes", rule_unattached_ebs_volumes),
    ("ec2_instances", rule_stopped_ec2_old),
    ("snapshots", rule_old_snapshots),
    ("s3_buckets", rule_s3_no_encryption),
    ("s3_buckets", rule_s3_no_versioning),
    ("rds_instances", rule_rds_no_deletion_protection),
]


def run_all_rules(inventory: dict[str, list[dict]], now: datetime | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for key, rule in ALL_RULES:
        findings.extend(rule(inventory.get(key, []), now))
    return findings
