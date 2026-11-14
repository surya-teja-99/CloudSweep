"""CLI: ``python -m cloudsweep audit [--regions ...] [--json] [--min-severity ...]``.

Read-only: only describe/list/get calls are ever made. Credentials come
from the standard boto3 chain (env vars, ~/.aws, IAM role).
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .audit import run_audit
from .costs import total_monthly_waste_usd
from .reporter import report_json, report_table


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cloudsweep",
        description="Read-only AWS account hygiene auditor: finds waste and misconfigurations.",
    )
    p.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    sub = p.add_subparsers(dest="command", required=True)
    a = sub.add_parser("audit", help="inventory resources and report findings")
    a.add_argument(
        "--regions",
        nargs="+",
        default=["us-east-1"],
        help="AWS regions to audit (default: us-east-1)",
    )
    a.add_argument("--json", action="store_true", help="machine-readable JSON output")
    a.add_argument(
        "--min-severity",
        choices=["low", "medium", "high"],
        default="low",
        help="only show findings at or above this severity (default: low)",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "audit":
        result = run_audit(args.regions)
        findings = result.filter_severity(args.min_severity)
        result.findings = findings
        result.total_monthly_waste_usd = total_monthly_waste_usd(findings)
        if args.json:
            print(report_json(result))
        else:
            report_table(result)
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
