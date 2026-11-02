"""Delivery module — PR creation and audit records.

Only this module talks to the Git host.
Engine tokens have no merge rights.
"""

from __future__ import annotations

from cryptoshift.delivery.pr import (
    PROutcome,
    create_pr_for_finding,
    format_pr_body,
    run_delivery,
    write_audit_record,
)

__all__ = [
    "PROutcome",
    "create_pr_for_finding",
    "format_pr_body",
    "run_delivery",
    "write_audit_record",
]
