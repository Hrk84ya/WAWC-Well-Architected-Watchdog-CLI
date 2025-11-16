"""Tests for CLI commands."""

from click.testing import CliRunner

from wawc.cli import cli


def test_cli_version():
    """Test version flag."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "1.0.0" in result.output


def test_cli_help():
    """Test help output."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "WAWC" in result.output
    assert "scan" in result.output


def test_scan_invalid_check():
    """Test scan with invalid check name."""
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--checks", "invalid"])
    assert result.exit_code == 1
    assert "Invalid checks" in result.output
