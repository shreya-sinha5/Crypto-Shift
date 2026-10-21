#!/usr/bin/env python3
"""Import boundary checker for CryptoShift.

Enforces that control_centre must NOT import engine modules.

Import boundaries:
  cli → (ingest, enrich, transform, verify, delivery)
  transform → (registry, llm_gateway, validator, codegen)
  verify → (trackA, trackB)
  control_centre → schemas + artifact files only

Exit code 0 = pass, 1 = violations found.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Modules that control_centre must NOT import
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

# Additional boundary checks
BOUNDARY_RULES: dict[str, set[str]] = {
    "cryptoshift.llm_gateway": {
        "cryptoshift.codegen",
        "cryptoshift.delivery",
        "cryptoshift.verify",
        "cryptoshift.cli",
    },
}


def get_imports(filepath: Path) -> list[tuple[str, int]]:
    """Extract all import module names and line numbers from a Python file."""
    imports = []
    try:
        tree = ast.parse(filepath.read_text(encoding="utf-8"))
    except SyntaxError:
        return imports

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append((alias.name, node.lineno))
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.append((node.module, node.lineno))
    return imports


def check_control_centre(project_root: Path) -> list[str]:
    """Check that control_centre imports no engine modules."""
    violations = []
    cc_dir = project_root / "cryptoshift" / "control_centre"

    if not cc_dir.exists():
        return violations

    for py_file in cc_dir.rglob("*.py"):
        for module_name, lineno in get_imports(py_file):
            for forbidden in FORBIDDEN_ENGINE_MODULES:
                if module_name == forbidden or module_name.startswith(f"{forbidden}."):
                    rel_path = py_file.relative_to(project_root)
                    violations.append(
                        f"  {rel_path}:{lineno} — imports '{module_name}' "
                        f"(control_centre must not import engine modules)"
                    )
    return violations


def check_boundary_rules(project_root: Path) -> list[str]:
    """Check additional import boundary rules."""
    violations = []

    for source_pkg, forbidden_set in BOUNDARY_RULES.items():
        pkg_path = project_root / source_pkg.replace(".", "/")
        if not pkg_path.exists():
            continue

        for py_file in pkg_path.rglob("*.py"):
            for module_name, lineno in get_imports(py_file):
                for forbidden in forbidden_set:
                    if module_name == forbidden or module_name.startswith(f"{forbidden}."):
                        rel_path = py_file.relative_to(project_root)
                        violations.append(
                            f"  {rel_path}:{lineno} — '{source_pkg}' imports "
                            f"'{module_name}' (boundary violation)"
                        )
    return violations


def main() -> int:
    project_root = Path(__file__).resolve().parent.parent
    all_violations: list[str] = []

    print("Checking import boundaries...")

    cc_violations = check_control_centre(project_root)
    all_violations.extend(cc_violations)

    boundary_violations = check_boundary_rules(project_root)
    all_violations.extend(boundary_violations)

    if all_violations:
        print(f"\n❌ {len(all_violations)} import boundary violation(s) found:\n")
        for v in all_violations:
            print(v)
        print("\nSee the import boundary documentation for details.")
        return 1
    else:
        print("✅ All import boundaries respected.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
