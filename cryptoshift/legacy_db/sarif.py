"""SARIF 2.1.0 generator and parser for legacy cryptographic findings.

Complies with the OASIS SARIF 2.1.0 specification and GitHub Code Scanning
ingestion format.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Sequence

from cryptoshift.parsers.c import PATTERNS, CryptoFinding, CryptoPattern

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
TOOL_NAME = "CryptoShift Legacy Scanner"
TOOL_VERSION = "0.1.0"


def _rules_dictionary() -> dict[str, CryptoPattern]:
    """Map rule_id to its pattern definition."""
    return {p.rule_id: p for p in PATTERNS}


def findings_to_sarif_dict(
    findings: Sequence[CryptoFinding],
    base_uri: str | None = None,
) -> dict[str, Any]:
    """Convert a sequence of CryptoFinding instances into a SARIF 2.1.0 dictionary."""
    rule_map = _rules_dictionary()

    # Collect unique rules referenced by findings
    used_rule_ids = {f.rule_id for f in findings}
    rules = []
    for rule_id in sorted(used_rule_ids):
        pattern = rule_map.get(rule_id)
        if pattern:
            rules.append({
                "id": pattern.rule_id,
                "name": f"{pattern.algorithm}_{pattern.role}".replace(" ", "_"),
                "shortDescription": {
                    "text": f"Legacy {pattern.algorithm} ({pattern.library})"
                },
                "fullDescription": {
                    "text": pattern.message
                },
                "defaultConfiguration": {
                    "level": pattern.severity
                },
                "properties": {
                    "precision": "high",
                    "tags": ["cryptography", "legacy-crypto", "post-quantum", pattern.algorithm.lower()],
                    "problem.severity": pattern.severity,
                },
            })

    results = []
    for f in findings:
        file_path = f.file
        if base_uri:
            try:
                file_path = str(Path(f.file).relative_to(Path(base_uri)))
            except ValueError:
                file_path = f.file
        # Normalize path separators for SARIF URI
        file_uri = file_path.replace("\\", "/")

        results.append({
            "ruleId": f.rule_id,
            "level": f.severity,
            "message": {
                "text": f"{f.message} (matched: '{f.matched_text}')"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_uri,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": f.line,
                            "startColumn": f.col_start,
                            "endColumn": f.col_end,
                            "snippet": {
                                "text": f.matched_text,
                            },
                        },
                    }
                }
            ],
            "properties": {
                "algorithm": f.algorithm,
                "library": f.library,
                "role": f.role,
                "key_size": f.key_size,
            },
        })

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": "https://github.com/CryptoShift/CryptoShift",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif_file(
    findings: Sequence[CryptoFinding],
    output_path: Path,
    base_uri: str | None = None,
) -> None:
    """Generate and write a SARIF JSON report to output_path."""
    sarif_data = findings_to_sarif_dict(findings, base_uri=base_uri)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fp:
        json.dump(sarif_data, fp, indent=2)


def read_sarif_file(path: Path) -> list[dict[str, Any]]:
    """Read a SARIF file and return standardized finding dictionaries."""
    with path.open("r", encoding="utf-8") as fp:
        data = json.load(fp)

    findings: list[dict[str, Any]] = []
    runs = data.get("runs", [])
    for run in runs:
        results = run.get("results", [])
        for res in results:
            rule_id = res.get("ruleId", "")
            level = res.get("level", "warning")
            message = res.get("message", {}).get("text", "")
            props = res.get("properties", {})
            locs = res.get("locations", [])
            for loc in locs:
                phys = loc.get("physicalLocation", {})
                art = phys.get("artifactLocation", {})
                region = phys.get("region", {})
                findings.append({
                    "rule_id": rule_id,
                    "severity": level,
                    "message": message,
                    "file": art.get("uri", ""),
                    "line": region.get("startLine", 0),
                    "col_start": region.get("startColumn", 0),
                    "col_end": region.get("endColumn", 0),
                    "matched_text": region.get("snippet", {}).get("text", ""),
                    "algorithm": props.get("algorithm", "unknown"),
                    "library": props.get("library", "unknown"),
                    "role": props.get("role", "unknown"),
                    "key_size": props.get("key_size"),
                })
    return findings
