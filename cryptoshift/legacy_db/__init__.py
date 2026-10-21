"""Legacy code database module for CryptoShift.

Manages legacy code scanning, SARIF 2.1.0 generation, SQLite persistence,
and CycloneDX CBOM integration.
"""

from __future__ import annotations

from cryptoshift.legacy_db.cbom import (
    findings_to_cyclonedx_cbom,
    findings_to_enriched_cbom,
)
from cryptoshift.legacy_db.db import DEFAULT_DB_PATH, CryptoDatabase
from cryptoshift.legacy_db.sarif import (
    findings_to_sarif_dict,
    read_sarif_file,
    write_sarif_file,
)
from cryptoshift.parsers.c import CryptoFinding, scan_directory, scan_file

__all__ = [
    "CryptoDatabase",
    "CryptoFinding",
    "DEFAULT_DB_PATH",
    "findings_to_cyclonedx_cbom",
    "findings_to_enriched_cbom",
    "findings_to_sarif_dict",
    "read_sarif_file",
    "scan_directory",
    "scan_file",
    "write_sarif_file",
]
