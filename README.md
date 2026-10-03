# CloudSweep

A **read-only AWS account hygiene auditor**: it inventories your resources,
flags waste and misconfigurations, and estimates what the waste costs.
It never deletes, stops, or modifies anything — only `describe` / `list` /
`get` calls are ever made.

## Architecture

```
 ┌──────────────┐
 │  boto3 (or   │
 │  moto mock)  │
 └──────┬───────┘
        ▼  describe_*/list_*/get_*  (read-only)
 ┌──────────────┐
 │  Inventory   │── EC2 instances, EBS volumes, snapshots, AMIs,
 │              │   S3 buckets, RDS instances, Lambda functions
 └──────┬───────┘   (region-scoped, paginated)
        ▼
 ┌──────────────┐
 │  Rules       │── 6 hygiene rules → findings
 │  engine      │   (resource, rule, severity, detail)
 └──────┬───────┘
        ▼
 ┌──────────────┐
 │  Cost        │── rough $/mo per finding from public
 │  estimates   │   unit-price constants (estimates, not bills)
 └──────┬───────┘
        ▼
 ┌──────────────┐
 │  Reporter    │── rich tables grouped by severity,
 └──────────────┘   or --json for machines
```

## Quickstart

```bash
make setup   # install dependencies
make test    # pytest suite (moto-mocked, fully offline)
make demo    # audit a mocked account with planted waste (offline, ~6s)

# against a real account (uses your standard boto3 credentials):
python -m cloudsweep audit --regions us-east-1 us-west-2
python -m cloudsweep audit --regions us-east-1 --min-severity high --json
```

## Rules

| Rule | Severity | What it flags |
|---|---|---|
| `unattached_ebs_volume` | medium | EBS volume in `available` state — paying for storage nobody uses |
| `stopped_ec2_instance_old` | medium | EC2 instance stopped for >30 days — usually forgotten |
| `old_ebs_snapshot` | low | Snapshot older than 90 days — stale backup nobody will restore |
| `s3_no_default_encryption` | high | Bucket without default server-side encryption |
| `s3_no_versioning` | medium | Bucket without versioning — deletes are unrecoverable |
| `rds_no_deletion_protection` | high | RDS instance deletable with a single API call |

Cost estimates use public on-demand unit prices (us-east-1) kept as visible
constants in `cloudsweep/costs.py` (e.g. gp3 $0.08/GB-mo, snapshots
$0.05/GB-mo). They are labeled estimates everywhere they appear.

## Sample output

Actual `make demo` output (mocked account, 2026-10-03):

```
HIGH severity (2):   s3_no_default_encryption  (demo-unprotected-bucket)
                     rds_no_deletion_protection (demo-exposed-db)
MEDIUM severity (2): unattached_ebs_volume      (100 GB gp3 → $8.00/mo)
                     s3_no_versioning          (demo-unprotected-bucket)

Inventoried — ec2_instances: 1, ebs_volumes: 3, s3_buckets: 2,
              rds_instances: 2, lambda_functions: 1
Estimated monthly waste: $8.00 (rough estimate, not a bill)
```

The clean resources planted alongside (attached volume, encrypted + versioned
bucket, protected RDS with backups, running instance) correctly produce zero
findings.

## Limitations (read before trusting the numbers)

- **Cost figures are rough estimates**, not bills — they rank findings, nothing more.
- **Read-only by design.** CloudSweep cannot delete or fix anything; remediation
  is left to you (or your IaC).
- **Age rules need real history.** The demo/test account is moto-mocked, so
  everything is "new" — the >30d / >90d rules are proven by unit tests with
  explicit timestamps instead.
- **Coverage is EC2/EBS/S3/RDS/Lambda.** No ECS, IAM, CloudTrail, or cost-anomaly
  analysis — deliberately scoped.
- **Snapshot discovery filters by owner.** Some AWS-compatible backends ignore
  the `OwnerIds` filter; CloudSweep double-checks `OwnerId` client-side so
  public snapshots are never attributed to your account.

## Project layout

```
CloudSweep/
├── cloudsweep/
│   ├── inventory.py  # read-only boto3 discovery (paginated, region-scoped)
│   ├── findings.py   # 6 hygiene rules, pure functions over inventory
│   ├── costs.py      # unit-price constants + waste estimates
│   ├── audit.py      # orchestration: inventory → rules → costs
│   ├── reporter.py   # rich tables + JSON output
│   └── cli.py        # `cloudsweep audit` argparse CLI
├── scripts/demo.py   # mocked-account demo (moto, offline)
├── tests/            # pytest: rules, costs, inventory (moto), audit (moto)
└── Makefile
```
