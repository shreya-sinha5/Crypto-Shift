"""CycloneDX CBOM & Enriched CBOM exporters for legacy code findings.

Bridges discovered C/C++ cryptographic findings with the CryptoShift
CBOM ingestion and enrichment schemas.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Sequence

from cryptoshift.parsers.c import CryptoFinding


def findings_to_enriched_cbom(
    findings: Sequence[CryptoFinding],
    base_dir: Path | str | None = None,
) -> list[dict[str, Any]]:
    """Convert findings into CryptoShift Enriched CBOM finding objects.

    Matches the format defined in schemas/enriched_cbom.json.
    """
    results: list[dict[str, Any]] = []

    for idx, f in enumerate(findings, start=1):
        file_path = f.file
        if base_dir:
            try:
                file_path = str(Path(f.file).relative_to(Path(base_dir)))
            except ValueError:
                file_path = f.file
        file_path = file_path.replace("\\", "/")

        # Risk scoring heuristic based on quantum vulnerability & role
        if f.severity == "error":
            sensitivity = 8.5
            criticality = 8.0
            lifespan = 8.0
            score = 8.17
        elif f.severity == "warning":
            sensitivity = 6.0
            criticality = 5.5
            lifespan = 5.0
            score = 5.50
        else:
            sensitivity = 3.0
            criticality = 3.0
            lifespan = 3.0
            score = 3.00

        finding_obj = {
            "schema_version": "1.0.0",
            "finding_id": f"f-{idx:04d}",
            "cbom_ref": f"urn:cdx:crypto:{f.library.lower()}:{f.algorithm.lower()}:{idx}",
            "file": file_path,
            "line": f.line,
            "ast_node": f"{f.library}:{f.matched_text}",
            "algorithm": f.algorithm,
            "key_size": f.key_size,
            "role": f.role if f.role in {"key_exchange", "signature", "symmetric", "hash", "unknown"} else "unknown",
            "role_confidence": 0.95,
            "call_context": [f"{f.library}::{f.matched_text}"],
            "indirect_usage": False,
            "risk": {
                "sensitivity": sensitivity,
                "criticality": criticality,
                "lifespan": lifespan,
                "score": score,
            },
            "status": "linked",
            "unlinked_reason": None,
        }
        results.append(finding_obj)

    return results


def findings_to_cyclonedx_cbom(
    findings: Sequence[CryptoFinding],
    repo_name: str = "legacy-code",
    base_dir: Path | str | None = None,
) -> dict[str, Any]:
    """Export findings as CycloneDX 1.6 Cryptographic Bill of Materials (CBOM)."""
    components = []
    for idx, f in enumerate(findings, start=1):
        file_path = f.file
        if base_dir:
            try:
                file_path = str(Path(f.file).relative_to(Path(base_dir)))
            except ValueError:
                file_path = f.file
        file_path = file_path.replace("\\", "/")

        components.append({
            "type": "cryptographic-asset",
            "bom-ref": f"urn:cdx:crypto:{f.library.lower()}:{f.algorithm.lower()}:{idx}",
            "name": f.algorithm,
            "version": f.library,
            "description": f.message,
            "evidence": {
                "occurrences": [
                    {
                        "location": file_path,
                        "line": f.line,
                        "offset": f.col_start,
                    }
                ]
            },
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": f.role,
                    "parameterSetIdentifier": str(f.key_size) if f.key_size else None,
                    "executionEnvironment": "native-c",
                },
            },
        })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:cryptoshift-{repo_name}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": repo_name,
            },
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "CryptoShift Legacy Scanner",
                        "version": "0.1.0",
                    }
                ]
            },
        },
        "components": components,
    }
