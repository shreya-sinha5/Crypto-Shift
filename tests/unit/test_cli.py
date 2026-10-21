"""Tests for CryptoShift CLI skeleton.

Verifies that all five subcommands exist, return the correct exit codes,
and support required flags (--json, --artifacts-dir, --dry-run, --config).
"""

from __future__ import annotations

from typer.testing import CliRunner

from cryptoshift import EXIT_TOOL_ERROR
from cryptoshift.cli.main import app

runner = CliRunner()


class TestCLIVersion:
    """Test CLI version and help output."""

    def test_version_flag(self) -> None:
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "cryptoshift" in result.stdout
        assert "0.1.0" in result.stdout

    def test_no_args_shows_help(self) -> None:
        result = runner.invoke(app, [])
        assert result.exit_code == 0
        assert "Usage" in result.stdout or "cryptoshift" in result.stdout.lower()


class TestScanCommand:
    """Test the scan subcommand skeleton."""

    def test_scan_returns_not_implemented(self) -> None:
        result = runner.invoke(app, ["scan", "--json"])
        assert result.exit_code == EXIT_TOOL_ERROR
        assert "not_implemented" in result.stdout

    def test_scan_accepts_cbom_flag(self) -> None:
        result = runner.invoke(app, ["scan", "--cbom", "test.json", "--json"])
        assert result.exit_code == EXIT_TOOL_ERROR

    def test_scan_accepts_artifacts_dir(self) -> None:
        result = runner.invoke(app, ["scan", "--artifacts-dir", "out/", "--json"])
        assert result.exit_code == EXIT_TOOL_ERROR

    def test_scan_accepts_dry_run(self) -> None:
        result = runner.invoke(app, ["scan", "--dry-run", "--json"])
        assert result.exit_code == EXIT_TOOL_ERROR


class TestEnrichCommand:
    """Test the enrich subcommand skeleton."""

    def test_enrich_returns_not_implemented(self) -> None:
        result = runner.invoke(app, ["enrich", "--json"])
        assert result.exit_code == EXIT_TOOL_ERROR
        assert "not_implemented" in result.stdout


class TestTransformCommand:
    """Test the transform subcommand skeleton."""

    def test_transform_returns_not_implemented(self) -> None:
        result = runner.invoke(app, ["transform", "--json"])
        assert result.exit_code == EXIT_TOOL_ERROR
        assert "not_implemented" in result.stdout

    def test_transform_accepts_finding_ids(self) -> None:
        result = runner.invoke(app, ["transform", "--finding-ids", "f-0001,f-0002", "--json"])
        assert result.exit_code == EXIT_TOOL_ERROR


class TestVerifyCommand:
    """Test the verify subcommand skeleton."""

    def test_verify_returns_not_implemented(self) -> None:
        result = runner.invoke(app, ["verify", "--json"])
        assert result.exit_code == EXIT_TOOL_ERROR
        assert "not_implemented" in result.stdout


class TestPRCommand:
    """Test the pr subcommand skeleton."""

    def test_pr_returns_not_implemented(self) -> None:
        result = runner.invoke(app, ["pr", "--json"])
        assert result.exit_code == EXIT_TOOL_ERROR
        assert "not_implemented" in result.stdout


class TestExitCodes:
    """Verify exit code constants match the contract."""

    def test_exit_code_values(self) -> None:
        from cryptoshift import (
            EXIT_APPROVAL_MISSING,
            EXIT_NEEDS_HUMAN,
            EXIT_SUCCESS,
            EXIT_TOOL_ERROR,
            EXIT_VERIFICATION_FAILED,
        )

        assert EXIT_SUCCESS == 0
        assert EXIT_TOOL_ERROR == 1
        assert EXIT_VERIFICATION_FAILED == 2
        assert EXIT_NEEDS_HUMAN == 3
        assert EXIT_APPROVAL_MISSING == 4
