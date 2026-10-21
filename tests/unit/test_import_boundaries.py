"""Tests for import boundary enforcement.

Verifies that control_centre imports no engine modules.
This test runs the same check as scripts/check_imports.py.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

FORBIDDEN_ENGINE_MODULES = {
    "cryptoshift.ingest",
    "cryptoshift.parsers",
    "cryptoshift.enrich",
    "cryptoshift.registry",
    "cryptoshift.llm_gateway",
    "cryptoshift.validator",
    "cryptoshift.codegen",
    "cryptoshift.verify",
    "cryptoshift.delivery",
    "cryptoshift.cli",
}


def get_control_centre_files() -> list[Path]:
    """Get all Python files in control_centre."""
    cc_dir = PROJECT_ROOT / "cryptoshift" / "control_centre"
    return sorted(cc_dir.rglob("*.py")) if cc_dir.exists() else []


@pytest.mark.unit
class TestImportBoundaries:
    """Verify control_centre respects import boundaries."""

    @pytest.mark.parametrize(
        "py_file",
        get_control_centre_files(),
        ids=lambda p: p.name,
    )
    def test_no_engine_imports(self, py_file: Path) -> None:
        """Each control_centre file must not import engine modules."""
        tree = ast.parse(py_file.read_text(encoding="utf-8"))

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    for forbidden in FORBIDDEN_ENGINE_MODULES:
                        assert not (
                            alias.name == forbidden or alias.name.startswith(f"{forbidden}.")
                        ), (
                            f"{py_file.name}:{node.lineno} imports '{alias.name}' — "
                            f"control_centre must not import engine modules"
                        )
            elif isinstance(node, ast.ImportFrom) and node.module:
                for forbidden in FORBIDDEN_ENGINE_MODULES:
                    assert not (
                        node.module == forbidden or node.module.startswith(f"{forbidden}.")
                    ), (
                        f"{py_file.name}:{node.lineno} imports from '{node.module}' — "
                        f"control_centre must not import engine modules"
                    )
