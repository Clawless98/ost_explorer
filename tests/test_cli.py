from __future__ import annotations
from pathlib import Path
import pytest
from click.testing import CliRunner
from ost_explorer.cli import cli

@pytest.fixture
def runner():
    return CliRunner()

def test_cli_help(runner: CliRunner):
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "PST/OST" in result.output

def test_cli_info_file_not_found(runner: CliRunner):
    result = runner.invoke(cli, ["info", "/nonexistent/file.pst"])
    assert result.exit_code == 2

def test_cli_validate_good_rules(runner: CliRunner, tmp_path: Path):
    rule_file = tmp_path / "good.yaml"
    rule_file.write_text("""
- name: test
  find: "password"
  severity: high
""")
    result = runner.invoke(cli, ["validate", str(rule_file)])
    assert result.exit_code == 0
    assert "valid" in result.output.lower() or "1 rule" in result.output.lower()

def test_cli_validate_bad_rules(runner: CliRunner, tmp_path: Path):
    rule_file = tmp_path / "bad.yaml"
    rule_file.write_text("""
- find: "test"
  severity: high
""")
    result = runner.invoke(cli, ["validate", str(rule_file)])
    assert result.exit_code != 0

def test_cli_scan_command_exists(runner: CliRunner):
    result = runner.invoke(cli, ["scan", "--help"])
    assert result.exit_code == 0

def test_cli_export_command_exists(runner: CliRunner):
    result = runner.invoke(cli, ["export", "--help"])
    assert result.exit_code == 0

def test_cli_browse_command_exists(runner: CliRunner):
    result = runner.invoke(cli, ["browse", "--help"])
    assert result.exit_code == 0
