"""Unit tests for legacy code database, C parser, and SARIF/CBOM exporters."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cryptoshift.cli.main import app
from cryptoshift.legacy_db import (
    CryptoDatabase,
    findings_to_cyclonedx_cbom,
    findings_to_enriched_cbom,
    findings_to_sarif_dict,
    scan_directory,
)

runner = CliRunner()


@pytest.fixture
def sample_legacy_dir() -> Path:
    return Path("demo/legacy_code")


@pytest.fixture
def in_memory_db() -> CryptoDatabase:
    return CryptoDatabase(":memory:")


def test_scan_legacy_code_directory(sample_legacy_dir: Path) -> None:
    findings = scan_directory(sample_legacy_dir)
    assert len(findings) > 0

    algorithms = {f.algorithm for f in findings}
    assert "RSA" in algorithms
    assert "ECDSA" in algorithms
    assert "DH" in algorithms
    assert "MD5" in algorithms
    assert "SHA-1" in algorithms

    # Check key exchange roles
    roles = {f.role for f in findings}
    assert "key_exchange" in roles
    assert "signature" in roles
    assert "symmetric" in roles
    assert "hash" in roles


def test_database_crud(sample_legacy_dir: Path, in_memory_db: CryptoDatabase) -> None:
    findings = scan_directory(sample_legacy_dir)
    count = in_memory_db.record_scan(
        repo_name="test-repo",
        findings=findings,
        base_dir=sample_legacy_dir,
    )
    assert count == len(findings)

    # Query RSA only
    rsa_findings = in_memory_db.query_findings(repo_name="test-repo", algorithm="RSA")
    assert len(rsa_findings) > 0
    assert all(f["algorithm"] == "RSA" for f in rsa_findings)

    # Query by severity
    error_findings = in_memory_db.query_findings(repo_name="test-repo", severity="error")
    assert len(error_findings) > 0

    # Summary
    summary = in_memory_db.get_summary(repo_name="test-repo")
    assert summary["total_findings"] == len(findings)
    assert summary["by_algorithm"]["RSA"] == len(rsa_findings)

    # Status update
    first_id = rsa_findings[0]["id"]
    updated = in_memory_db.update_status(first_id, "migrating")
    assert updated is True
    migrating = in_memory_db.query_findings(status="migrating")
    assert len(migrating) == 1
    assert migrating[0]["id"] == first_id


def test_sarif_generation(sample_legacy_dir: Path) -> None:
    findings = scan_directory(sample_legacy_dir)
    sarif = findings_to_sarif_dict(findings, base_uri=str(sample_legacy_dir))

    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1

    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "CryptoShift Legacy Scanner"
    assert len(run["results"]) == len(findings)
    assert len(run["tool"]["driver"]["rules"]) > 0

    first_result = run["results"][0]
    assert "ruleId" in first_result
    assert "locations" in first_result
    assert "properties" in first_result


def test_cbom_and_enriched_export(sample_legacy_dir: Path) -> None:
    findings = scan_directory(sample_legacy_dir)

    # CycloneDX CBOM
    cbom = findings_to_cyclonedx_cbom(findings, repo_name="test-repo")
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"
    assert len(cbom["components"]) == len(findings)

    # Enriched CBOM findings
    enriched = findings_to_enriched_cbom(findings)
    assert len(enriched) == len(findings)
    first = enriched[0]
    assert first["schema_version"] == "1.0.0"
    assert first["finding_id"].startswith("f-")
    assert "risk" in first
    assert "score" in first["risk"]


def test_cli_db_scan_and_list(tmp_path: Path) -> None:
    db_file = tmp_path / "test_crypto.db"
    sarif_file = tmp_path / "test.sarif"
    cbom_file = tmp_path / "test_cbom.json"

    # Scan command
    scan_res = runner.invoke(
        app,
        [
            "db",
            "scan",
            "demo/legacy_code",
            "--repo",
            "cli-test",
            "--db",
            str(db_file),
            "--sarif",
            str(sarif_file),
            "--cbom",
            str(cbom_file),
            "--json",
        ],
    )
    assert scan_res.exit_code == 0
    assert db_file.exists()
    assert sarif_file.exists()
    assert cbom_file.exists()

    # List command
    list_res = runner.invoke(
        app,
        ["db", "list", "--db", str(db_file), "--algo", "RSA", "--json"],
    )
    assert list_res.exit_code == 0
    data = json.loads(list_res.output)
    assert len(data) > 0
    assert all(item["algorithm"] == "RSA" for item in data)

    # Summary command
    summary_res = runner.invoke(
        app,
        ["db", "summary", "--db", str(db_file), "--json"],
    )
    assert summary_res.exit_code == 0
    summary_data = json.loads(summary_res.output)
    assert summary_data["total_findings"] > 0
