from __future__ import annotations
from pathlib import Path
import pytest
from ost_explorer.rules.loader import Rule, RuleValidationError, load_rules_from_yaml, load_rules_from_string

def test_load_find_rule():
    yaml_str = """
- name: vpn creds
  find: "vpn password"
  severity: high
  note: "VPN access credentials"
"""
    rules = load_rules_from_string(yaml_str)
    assert len(rules) == 1
    assert rules[0].name == "vpn creds"
    assert rules[0].severity == "high"
    assert rules[0].matches("Here is the vpn password for the office")
    assert not rules[0].matches("Nothing here")

def test_load_find_case_insensitive():
    yaml_str = """
- name: test
  find: "Secret Key"
  severity: medium
"""
    rules = load_rules_from_string(yaml_str)
    assert rules[0].matches("the SECRET KEY is here")
    assert rules[0].matches("secret key")

def test_load_find_any_rule():
    yaml_str = """
- name: codenames
  find_any:
    - "Project Nightfall"
    - "Operation Sunrise"
  severity: medium
  note: "M&A codenames"
"""
    rules = load_rules_from_string(yaml_str)
    assert len(rules) == 1
    assert rules[0].matches("Regarding Project Nightfall update")
    assert rules[0].matches("Operation Sunrise is on track")
    assert not rules[0].matches("Nothing matching here")

def test_load_pattern_rule():
    yaml_str = """
- name: employee_id
  pattern: "EMP-\\d{6}"
  severity: low
"""
    rules = load_rules_from_string(yaml_str)
    assert rules[0].matches("Employee EMP-123456 started today")
    assert not rules[0].matches("EMP-12345")

def test_load_multiple_rules():
    yaml_str = """
- name: rule1
  find: "password"
  severity: high
- name: rule2
  find: "secret"
  severity: medium
"""
    rules = load_rules_from_string(yaml_str)
    assert len(rules) == 2

def test_validation_missing_name():
    yaml_str = """
- find: "test"
  severity: high
"""
    with pytest.raises(RuleValidationError, match="missing 'name'"):
        load_rules_from_string(yaml_str)

def test_validation_missing_match_field():
    yaml_str = """
- name: bad rule
  severity: high
"""
    with pytest.raises(RuleValidationError, match="missing 'find', 'find_any', or 'pattern'"):
        load_rules_from_string(yaml_str)

def test_validation_invalid_severity():
    yaml_str = """
- name: test
  find: "test"
  severity: extreme
"""
    with pytest.raises(RuleValidationError, match="invalid severity"):
        load_rules_from_string(yaml_str)

def test_validation_bad_regex():
    yaml_str = """
- name: test
  pattern: "[invalid"
  severity: low
"""
    with pytest.raises(RuleValidationError, match="invalid regex"):
        load_rules_from_string(yaml_str)

def test_load_from_file(tmp_rules_dir: Path):
    rule_file = tmp_rules_dir / "test.yaml"
    rule_file.write_text("""
- name: test
  find: "password"
  severity: high
""")
    rules = load_rules_from_yaml(rule_file)
    assert len(rules) == 1

def test_rule_find_all_matches():
    yaml_str = """
- name: passwords
  find: "password"
  severity: high
"""
    rules = load_rules_from_string(yaml_str)
    text = "password: abc123\nanother password: xyz789"
    matches = rules[0].find_all(text)
    assert len(matches) == 2

def test_default_severity():
    yaml_str = """
- name: test
  find: "hello"
"""
    rules = load_rules_from_string(yaml_str)
    assert rules[0].severity == "medium"

def test_default_rules_load():
    from importlib.resources import files
    rules_path = Path(str(files("ost_explorer.rules").joinpath("default_rules.yaml")))
    rules = load_rules_from_yaml(rules_path)
    assert len(rules) > 50
    for rule in rules:
        assert rule.name
        assert rule.severity in {"low", "medium", "high", "critical"}
