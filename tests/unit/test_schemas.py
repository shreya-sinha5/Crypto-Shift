"""Tests for JSON schemas in schemas/ directory.

Validates that:
1. All schema files are valid JSON.
2. All schemas are valid JSON Schema Draft 7.
3. Sample artifacts validate against their schemas.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

SCHEMAS_DIR = Path(__file__).resolve().parent.parent.parent / "schemas"


def get_schema_files() -> list[Path]:
    """Get all JSON schema files."""
    return sorted(SCHEMAS_DIR.glob("*.json"))


@pytest.mark.unit
class TestSchemasValid:
    """Verify each schema file is well-formed."""

    @pytest.mark.parametrize("schema_file", get_schema_files(), ids=lambda p: p.name)
    def test_schema_is_valid_json(self, schema_file: Path) -> None:
        with open(schema_file, encoding="utf-8") as f:
            schema = json.load(f)
        assert isinstance(schema, dict)

    @pytest.mark.parametrize("schema_file", get_schema_files(), ids=lambda p: p.name)
    def test_schema_is_valid_draft7(self, schema_file: Path) -> None:
        with open(schema_file, encoding="utf-8") as f:
            schema = json.load(f)
        jsonschema.Draft7Validator.check_schema(schema)

    @pytest.mark.parametrize("schema_file", get_schema_files(), ids=lambda p: p.name)
    def test_schema_has_version(self, schema_file: Path) -> None:
        with open(schema_file, encoding="utf-8") as f:
            schema = json.load(f)
        # schema_version should be in required or properties
        props = schema.get("properties", {})
        assert "schema_version" in props, f"{schema_file.name} missing schema_version property"


@pytest.mark.unit
class TestSampleValidation:
    """Validate sample data against schemas."""

    def test_enriched_cbom_sample(self) -> None:
        schema_path = SCHEMAS_DIR / "enriched_cbom.json"
        with open(schema_path, encoding="utf-8") as f:
            schema = json.load(f)

        sample = {
            "schema_version": "1.0.0",
            "finding_id": "f-0042",
            "cbom_ref": "component-bom-ref-001",
            "file": "src/main/java/com/example/KeyService.java",
            "line": 88,
            "ast_node": "MethodCallExpr:KeyPairGenerator.getInstance",
            "algorithm": "RSA",
            "key_size": 2048,
            "role": "key_exchange",
            "role_confidence": 0.92,
            "call_context": ["KeyService.generateKeyPair", "ConnectionManager.init"],
            "indirect_usage": False,
            "risk": {
                "sensitivity": 8,
                "criticality": 7,
                "lifespan": 9,
                "score": 8.0,
            },
            "status": "linked",
        }
        jsonschema.validate(sample, schema)

    def test_enriched_cbom_rejects_invalid_role(self) -> None:
        schema_path = SCHEMAS_DIR / "enriched_cbom.json"
        with open(schema_path, encoding="utf-8") as f:
            schema = json.load(f)

        sample = {
            "schema_version": "1.0.0",
            "finding_id": "f-0042",
            "cbom_ref": "ref",
            "file": "test.java",
            "line": 1,
            "algorithm": "RSA",
            "role": "invalid_role",  # Not in enum
            "role_confidence": 0.5,
            "risk": {"sensitivity": 5, "criticality": 5, "lifespan": 5, "score": 5},
            "status": "linked",
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(sample, schema)

    def test_decision_sample(self) -> None:
        schema_path = SCHEMAS_DIR / "decision.json"
        with open(schema_path, encoding="utf-8") as f:
            schema = json.load(f)

        sample = {
            "schema_version": "1.0.0",
            "finding_id": "f-0042",
            "reviewer": "alice",
            "decision": "approved",
            "notes": "Looks good after Track A and B pass.",
            "timestamp": "2026-09-29T17:00:00Z",
        }
        jsonschema.validate(sample, schema)

    def test_decision_rejects_invalid_decision(self) -> None:
        schema_path = SCHEMAS_DIR / "decision.json"
        with open(schema_path, encoding="utf-8") as f:
            schema = json.load(f)

        sample = {
            "schema_version": "1.0.0",
            "finding_id": "f-0042",
            "reviewer": "alice",
            "decision": "maybe",  # Not in enum
            "timestamp": "2026-09-29T17:00:00Z",
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(sample, schema)
