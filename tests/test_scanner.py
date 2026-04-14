from __future__ import annotations
import datetime
from pathlib import Path
import pytest
from ost_explorer.engine.scanner import Scanner
from ost_explorer.models import Attachment, Message, Severity

def _make_message(body: str, subject: str = "Test", sender: str = "a@b.com",
                  attachments: list[Attachment] | None = None) -> Message:
    return Message(
        subject=subject, sender=sender,
        recipients_to=["to@b.com"], recipients_cc=[], recipients_bcc=[],
        date=datetime.datetime(2025, 3, 15),
        body_plain=body, body_html="", headers={},
        attachments=attachments or [],
        is_read=True, is_flagged=False,
    )

def test_scanner_detects_password():
    scanner = Scanner()
    msg = _make_message("Here is the password: Summer2025!")
    findings = scanner.scan_message(msg, folder_path="Inbox")
    matching = [f for f in findings if f.rule_name == "password_colon"]
    assert len(matching) >= 1
    assert matching[0].severity == Severity.CRITICAL

def test_scanner_detects_aws_key():
    scanner = Scanner()
    msg = _make_message("The key is AKIAIOSFODNN7EXAMPLE")
    findings = scanner.scan_message(msg, folder_path="Inbox")
    matching = [f for f in findings if f.rule_name == "aws_access_key"]
    assert len(matching) == 1

def test_scanner_detects_github_token():
    scanner = Scanner()
    msg = _make_message("Use this token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
    findings = scanner.scan_message(msg, folder_path="Inbox")
    matching = [f for f in findings if f.rule_name == "github_token"]
    assert len(matching) == 1

def test_scanner_detects_private_key():
    scanner = Scanner()
    msg = _make_message("-----BEGIN RSA PRIVATE KEY-----\nMIIE...")
    findings = scanner.scan_message(msg, folder_path="Inbox")
    matching = [f for f in findings if f.rule_name == "private_key_pem"]
    assert len(matching) >= 1

def test_scanner_detects_ssn():
    scanner = Scanner()
    msg = _make_message("SSN: 123-45-6789")
    findings = scanner.scan_message(msg, folder_path="Inbox")
    matching = [f for f in findings if f.rule_name == "ssn"]
    assert len(matching) == 1

def test_scanner_detects_credit_card():
    scanner = Scanner()
    msg = _make_message("Card: 4111-1111-1111-1111")
    findings = scanner.scan_message(msg, folder_path="Inbox")
    matching = [f for f in findings if f.rule_name == "credit_card_visa"]
    assert len(matching) == 1

def test_scanner_detects_unc_path():
    scanner = Scanner()
    msg = _make_message("See \\\\fileserver\\share$\\docs")
    findings = scanner.scan_message(msg, folder_path="Inbox")
    matching = [f for f in findings if f.rule_name == "unc_path"]
    assert len(matching) >= 1

def test_scanner_detects_confidential():
    scanner = Scanner()
    msg = _make_message("This is confidential information")
    findings = scanner.scan_message(msg, folder_path="Inbox")
    matching = [f for f in findings if f.rule_name == "confidential_marking"]
    assert len(matching) >= 1

def test_scanner_scans_attachment_names():
    scanner = Scanner()
    att = Attachment(filename="secrets.kdbx", size=1024, mime_type="application/octet-stream", _extract_fn=None)
    msg = _make_message("See attached", attachments=[att])
    findings = scanner.scan_message(msg, folder_path="Inbox")
    matching = [f for f in findings if f.rule_name == "keepass_database"]
    assert len(matching) >= 1

def test_scanner_with_custom_rules(tmp_rules_dir: Path):
    rule_file = tmp_rules_dir / "custom.yaml"
    rule_file.write_text("""
- name: secret_project
  find: "Project Zodiac"
  severity: critical
""")
    scanner = Scanner(custom_rule_paths=[rule_file])
    msg = _make_message("Update on Project Zodiac deliverables")
    findings = scanner.scan_message(msg, folder_path="Inbox")
    matching = [f for f in findings if f.rule_name == "secret_project"]
    assert len(matching) == 1
    assert matching[0].severity == Severity.CRITICAL

def test_scanner_no_false_positive_on_clean_message():
    scanner = Scanner()
    msg = _make_message("Hi, let's meet for lunch tomorrow at noon.")
    findings = scanner.scan_message(msg, folder_path="Inbox")
    high_findings = [f for f in findings if f.severity >= Severity.HIGH]
    assert len(high_findings) == 0

def test_scanner_scan_multiple_messages():
    scanner = Scanner()
    messages = [
        _make_message("password: abc123"),
        _make_message("Nothing interesting here"),
        _make_message("AKIAIOSFODNN7EXAMPLE"),
    ]
    all_findings = scanner.scan_messages(messages, folder_path="Inbox")
    assert len(all_findings) >= 2

def test_scanner_context_extraction():
    scanner = Scanner()
    body = "Line 1\nLine 2\nPassword: Secret123\nLine 4\nLine 5"
    msg = _make_message(body)
    findings = scanner.scan_message(msg, folder_path="Inbox")
    matching = [f for f in findings if f.rule_name == "password_colon"]
    assert len(matching) >= 1
    assert "Password: Secret123" in matching[0].context

def test_scanner_severity_filter():
    scanner = Scanner()
    msg = _make_message("password: test123 and phone 555-123-4567")
    all_findings = scanner.scan_message(msg, folder_path="Inbox")
    high_only = scanner.scan_message(msg, folder_path="Inbox", min_severity=Severity.HIGH)
    assert len(high_only) <= len(all_findings)
