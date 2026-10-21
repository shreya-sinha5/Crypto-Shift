#!/usr/bin/env python3
"""Validate that all JSON Schema files in schemas/ are well-formed.

Checks:
  1. Each file is valid JSON.
  2. Each file is a valid JSON Schema (Draft 7).
  3. Each schema has required fields: $schema, $id, title, type.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

import jsonschema


def main() -> int:
    schemas_dir = Path(__file__).resolve().parent.parent / "schemas"

    if not schemas_dir.exists():
        print(f"❌ Schemas directory not found: {schemas_dir}")
        return 1

    schema_files = list(schemas_dir.glob("*.json"))
    if not schema_files:
        print("⚠️ No schema files found in schemas/")
        return 0

    errors: list[str] = []

    for schema_file in sorted(schema_files):
        try:
            with open(schema_file, encoding="utf-8") as f:
                schema = json.load(f)
        except json.JSONDecodeError as e:
            errors.append(f"  {schema_file.name}: Invalid JSON — {e}")
            continue

        # Check required meta-fields
        for field in ["$schema", "title", "type"]:
            if field not in schema:
                errors.append(f"  {schema_file.name}: Missing required field '{field}'")

        # Validate the schema itself is a valid JSON Schema
        try:
            jsonschema.Draft7Validator.check_schema(schema)
        except jsonschema.SchemaError as e:
            errors.append(f"  {schema_file.name}: Invalid JSON Schema — {e.message}")

        print(f"  ✅ {schema_file.name}")

    if errors:
        print(f"\n❌ {len(errors)} schema validation error(s):\n")
        for e in errors:
            print(e)
        return 1
    else:
        print(f"\n✅ All {len(schema_files)} schemas are valid.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
