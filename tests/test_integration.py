from __future__ import annotations
import datetime
import json
from pathlib import Path
import pytest
from ost_explorer.models import Attachment, Folder, Mailbox, Message

def _build_mock_mailbox(tmp_path: Path):
    messages = [
        Message(
            subject="RE: VPN credentials", sender="jane@corp.com",
            recipients_to=["user@corp.com"], recipients_cc=[], recipients_bcc=[],
            date=datetime.datetime(2025, 3, 15, 10, 30),
            body_plain="Hey, here are the creds:\nUsername: jdoe\nPassword: Summer2025!\n",
            body_html="", headers={},
            attachments=[Attachment(
                filename="vpn_config.ovpn", size=512,
                mime_type="application/x-openvpn-profile",
                _extract_fn=lambda: b"client\nremote vpn.corp.com 1194\nauth-user-pass",
            )],
            is_read=True, is_flagged=False,
        ),
        Message(
            subject="AWS Keys for staging", sender="devops@corp.com",
            recipients_to=["dev@corp.com"], recipients_cc=[], recipients_bcc=[],
            date=datetime.datetime(2025, 3, 10, 14, 0),
            body_plain="Here are the staging keys:\nAKIAIOSFODNN7EXAMPLE\nwJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            body_html="", headers={}, attachments=[],
            is_read=True, is_flagged=False,
        ),
        Message(
            subject="Lunch plans", sender="bob@corp.com",
            recipients_to=["alice@corp.com"], recipients_cc=[], recipients_bcc=[],
            date=datetime.datetime(2025, 3, 12),
            body_plain="Hey, want to grab sushi at noon?",
            body_html="", headers={}, attachments=[],
            is_read=True, is_flagged=False,
        ),
    ]
    folder = Folder(name="Inbox", message_count=3, children=[], _folder_id="f1")
    mailbox = Mailbox(path=tmp_path / "test.pst", format_type="PST", folders=[folder], total_messages=3)
    return mailbox, folder, messages

def test_full_scan_pipeline(tmp_path: Path):
    mailbox, folder, messages = _build_mock_mailbox(tmp_path)
    from ost_explorer.engine.scanner import Scanner
    scanner = Scanner()
    findings = scanner.scan_messages(messages, folder_path="Inbox")
    rule_names = {f.rule_name for f in findings}
    assert "password_plain" in rule_names
    assert "aws_access_key" in rule_names
    lunch_findings = scanner.scan_message(messages[2], folder_path="Inbox")
    high_lunch = [f for f in lunch_findings if f.severity.value >= 3]
    assert len(high_lunch) == 0

def test_full_export_pipeline(tmp_path: Path):
    _, _, messages = _build_mock_mailbox(tmp_path)
    from ost_explorer.engine.scanner import Scanner
    from ost_explorer.engine.export import export_json
    scanner = Scanner()
    findings = scanner.scan_messages(messages, folder_path="Inbox")
    output = tmp_path / "report.json"
    export_json(messages, findings, output)
    data = json.loads(output.read_text())
    assert len(data["messages"]) == 3
    assert len(data["findings"]) > 0
    assert any(f["rule_name"] == "password_plain" for f in data["findings"])

def test_search_then_scan(tmp_path: Path):
    _, _, messages = _build_mock_mailbox(tmp_path)
    from ost_explorer.engine.search import parse_query, search_messages
    from ost_explorer.engine.scanner import Scanner
    results = search_messages(messages, parse_query("VPN"))
    assert len(results) == 1
    assert results[0].subject == "RE: VPN credentials"
    scanner = Scanner()
    findings = scanner.scan_messages(results, folder_path="Inbox")
    assert any(f.rule_name == "password_plain" for f in findings)

def test_html_export(tmp_path: Path):
    _, _, messages = _build_mock_mailbox(tmp_path)
    from ost_explorer.engine.scanner import Scanner
    from ost_explorer.engine.export import export_html
    scanner = Scanner()
    findings = scanner.scan_messages(messages, folder_path="Inbox")
    output = tmp_path / "report.html"
    export_html(messages, findings, output, mailbox_name="test.pst")
    html = output.read_text()
    assert "test.pst" in html
    assert "password_plain" in html
    assert "CRITICAL" in html

def test_attachment_extraction(tmp_path: Path):
    _, _, messages = _build_mock_mailbox(tmp_path)
    vpn_msg = messages[0]
    assert len(vpn_msg.attachments) == 1
    att = vpn_msg.attachments[0]
    data = att.extract_bytes()
    assert b"vpn.corp.com" in data
