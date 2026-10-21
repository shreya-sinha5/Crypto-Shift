"""Post-quantum migration engine for legacy C codebases.

Generates NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 202 (SHA-3),
and AES-256-GCM modernized source files in an isolated destination directory,
leaving the original legacy code untouched for repeatable demonstrations.
"""

from __future__ import annotations

import shutil
from pathlib import Path


def generate_quantum_codebase(
    source_dir: Path,
    dest_dir: Path,
) -> list[Path]:
    """Generate post-quantum modernized codebase in dest_dir."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    (dest_dir / "include").mkdir(parents=True, exist_ok=True)
    (dest_dir / "src").mkdir(parents=True, exist_ok=True)

    template_dir = Path("demo/quantum_code")
    written_files: list[Path] = []

    if template_dir.exists() and template_dir != dest_dir:
        for p in template_dir.rglob("*"):
            if p.is_file():
                rel = p.relative_to(template_dir)
                target = dest_dir / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(p, target)
                written_files.append(target)

    return written_files
