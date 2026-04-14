from __future__ import annotations
import csv
import datetime
import json
from pathlib import Path
import pytest
from ost_explorer.engine.export import export_json, export_csv, export_html
from ost_explorer.models import Attachment, Message, ScanFinding, Severity

def _make_msg(subject: str = "Test", body: str = "Hello") -> Message:
    return Message(
        subject=subject, sender="alice@corp.com",
        recipients_to=["bob@corp.com"], recipients_cc=[], recipients_bcc=[],
        date=datetime.datetime(2025, 3, 15, 10, 30),
        body_plain=body, body_html="", headers={"Message-ID": "<test@corp.com>"},
        attachments=[], is_read=True, is_flagged=False,
    )

def _make_finding() -> ScanFinding:
    return ScanFinding(
        rule_name="password_colon", severity=Severity.CRITICAL,
        matched_text="password: Summer2025!",
        context="Here is the password: Summer2025!",
        message_subject="VPN creds", message_sender="jane@corp.com",
        message_date=datetime.datetime(2025, 3, 15), folder_path="Inbox",
    )

def test_export_json(tmp_path: Path):
    messages = [_make_msg("Email 1", "Body 1"), _make_msg("Email 2", "Body 2")]
    findings = [_make_finding()]
    output = tmp_path / "export.json"
    export_json(messages, findings, output)
    data = json.loads(output.read_text())
    assert len(data["messages"]) == 2
    assert len(data["findings"]) == 1
    assert data["messages"][0]["subject"] == "Email 1"
    assert data["findings"][0]["rule_name"] == "password_colon"

def test_export_csv_messages(tmp_path: Path):
    messages = [_make_msg("Email 1"), _make_msg("Email 2")]
    output = tmp_path / "messages.csv"
    export_csv(messages, [], output)
    with open(output) as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    assert len(rows) == 2
    assert rows[0]["subject"] == "Email 1"
    assert "sender" in rows[0]
    assert "date" in rows[0]

def test_export_csv_findings(tmp_path: Path):
    findings = [_make_finding()]
    output = tmp_path / "findings.csv"
    export_csv([], findings, output)
    with open(output) as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    assert len(rows) == 1
    assert rows[0]["rule_name"] == "password_colon"

def test_export_html(tmp_path: Path):
    messages = [_make_msg("Email 1", "Body text")]
    findings = [_make_finding()]
    output = tmp_path / "report.html"
    export_html(messages, findings, output, mailbox_name="test.pst")
    html = output.read_text()
    assert "<html" in html
    assert "test.pst" in html
    assert "password_colon" in html
    assert "Email 1" in html

def test_export_json_empty(tmp_path: Path):
    output = tmp_path / "empty.json"
    export_json([], [], output)
    data = json.loads(output.read_text())
    assert data["messages"] == []
    assert data["findings"] == []
