"""Unit tests for live C code transformer and file transformation."""

from __future__ import annotations

from pathlib import Path
import pytest
from typer.testing import CliRunner

from cryptoshift.cli.main import app
from cryptoshift.codegen.transformer import transform_c_file, transform_c_source

runner = CliRunner()


@pytest.mark.unit
def test_transform_c_source_custom(tmp_path: Path) -> None:
    legacy_code = """
#include <openssl/dh.h>
#include "legacy_crypto.h"

int test_dh(dh_context_t *ctx) {
    DH_compute_key(shared, peer, ctx->dh);
    return 0;
}
"""
    out_file = tmp_path / "out.c"
    res = transform_c_source(legacy_code, filename="test.c", out_file=out_file)

    assert res["status"] == "success"
    assert "quantum_crypto.h" in res["quantum_code"]
    assert "hybrid_kem_derive_shared" in res["quantum_code"]
    assert out_file.exists()
    assert out_file.read_text(encoding="utf-8") == res["quantum_code"]


@pytest.mark.unit
def test_transform_c_file_benchmark(tmp_path: Path) -> None:
    src_file = Path("demo/legacy_code/src/dh_exchange.c")
    out_file = tmp_path / "dh_exchange.quantum.c"

    res = transform_c_file(src_file, output_path=out_file)
    assert res["status"] == "success"
    assert "ML-KEM-768" in res["quantum_code"]
    assert out_file.exists()


@pytest.mark.unit
def test_cli_transform_file(tmp_path: Path) -> None:
    src_file = Path("demo/legacy_code/src/hash_utils.c")
    out_file = tmp_path / "hash_utils.quantum.c"

    result = runner.invoke(
        app,
        ["db", "transform-file", str(src_file), "--out", str(out_file), "--json"],
    )
    assert result.exit_code == 0
    assert out_file.exists()
