"""Codegen — template-driven patch generation.

Accepts validated {template_id, parameters} only, never raw model text.
"""

from __future__ import annotations

from cryptoshift.codegen.transformer import (
    transform_all_findings,
    transform_finding,
)

__all__ = [
    "transform_all_findings",
    "transform_finding",
]
