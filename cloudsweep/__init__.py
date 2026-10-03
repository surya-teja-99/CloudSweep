"""CloudSweep — read-only AWS account hygiene auditor.

Inventories resources, flags waste and misconfigurations, and estimates
costs. Never deletes or modifies anything.
"""

from .audit import AuditResult, run_audit
from .findings import Finding

__version__ = "0.1.0"
__all__ = ["AuditResult", "Finding", "run_audit", "__version__"]
