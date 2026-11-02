"""Unit tests for the CryptoShift Delivery module.

Tests pull request body formatting, schema-valid audit records,
approval gating, and atomic PR creation outcomes.
"""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft7Validator

from cryptoshift import EXIT_APPROVAL_MISSING, EXIT_SUCCESS
from cryptoshift.delivery import (
    create_pr_for_finding,
    format_pr_body,
    run_delivery,
    write_audit_record,
)


def test_format_pr_body() -> None:
    body = format_pr_body(
        finding_id="f-0006",
        file_path="src/tls_session.c",
        line=72,
        algorithm="AES-CBC",
        role="symmetric",
        template_id="c/openssl/aes_256_gcm_aead",
        parameters={"cipher": "AES-256-GCM"},
        rationale="Replace AES-CBC with AES-256-GCM",
        track_a={"status": "pass", "tests_run": 10},
        track_b={"status": "pass", "kat_results": {"passed": 50, "total": 50}},
    )

    assert "f-0006" in body
    assert "src/tls_session.c:72" in body
    assert "AES-256-GCM" in body
    assert "Track A — Functional Equivalence" in body
    assert "Track B — Cryptographic Assurance" in body
    assert "git revert" in body


def test_write_audit_record(tmp_path: Path) -> None:
    schema_path = Path("schemas/audit_record.json")
    with schema_path.open(encoding="utf-8") as fp:
        schema = json.load(fp)

    record_path = write_audit_record(
        artifacts_dir=tmp_path,
        finding_id="f-0006",
        action="pr_opened",
        actor="lead-reviewer",
        details={
            "template_id": "c/openssl/aes_256_gcm_aead",
            "parameters": {"cipher": "AES-256-GCM"},
            "validator_result": "passed",
            "trackA_status": "pass",
            "trackB_status": "pass",
            "overall_status": "pass",
            "pr_branch": "cryptoshift/f-0006",
            "pr_url": "https://github.com/org/repo/pull/42",
            "decision": "approved",
            "notes": "Looks good",
        },
    )

    assert record_path.exists()
    with record_path.open(encoding="utf-8") as fp:
        data = json.load(fp)

    Draft7Validator.check_schema(schema)
    validator = Draft7Validator(schema)
    validator.validate(data)
    assert data["action"] == "pr_opened"
    assert data["actor"] == "lead-reviewer"


def test_create_pr_missing_approval(tmp_path: Path) -> None:
    outcome = create_pr_for_finding("f-9999", artifacts_dir=tmp_path)
    assert outcome.status == "missing_approval"
    assert "Human approval required" in outcome.message


def test_create_pr_rejected_decision(tmp_path: Path) -> None:
    decisions_dir = tmp_path / "decisions"
    decisions_dir.mkdir(parents=True)
    decision_file = decisions_dir / "f-0001.json"
    decision_file.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "finding_id": "f-0001",
                "reviewer": "auditor",
                "decision": "rejected",
                "notes": "Risk too high",
                "timestamp": "2026-11-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )

    outcome = create_pr_for_finding("f-0001", artifacts_dir=tmp_path)
    assert outcome.status == "rejected"
    assert "rejected" in outcome.message


def test_run_delivery_approved_flow() -> None:
    artifacts_dir = Path("artifacts")
    code, outcomes = run_delivery(
        artifacts_dir=artifacts_dir,
        finding_ids=["f-0006"],
        dry_run=True,
    )
    assert code == EXIT_SUCCESS
    assert len(outcomes) == 1
    assert outcomes[0].status == "dry_run"
    assert outcomes[0].branch == "cryptoshift/f-0006"


def test_run_delivery_unapproved_flow(tmp_path: Path) -> None:
    code, outcomes = run_delivery(
        artifacts_dir=tmp_path,
        finding_ids=["f-9999"],
    )
    assert code == EXIT_APPROVAL_MISSING
    assert outcomes[0].status == "missing_approval"
