from __future__ import annotations

import datetime
from pathlib import Path

from ost_explorer.models import (
    Attachment,
    Contact,
    Folder,
    Mailbox,
    Message,
    ScanFinding,
    Severity,
)


def test_attachment_extract_bytes():
    data = b"file content here"
    att = Attachment(
        filename="test.txt",
        size=len(data),
        mime_type="text/plain",
        _extract_fn=lambda: data,
    )
    assert att.extract_bytes() == data


def test_attachment_extract_bytes_lazy_none():
    att = Attachment(
        filename="test.txt",
        size=100,
        mime_type="text/plain",
        _extract_fn=None,
    )
    assert att.extract_bytes() == b""


def test_message_has_attachments(sample_message):
    assert sample_message.has_attachments is True


def test_message_no_attachments():
    msg = Message(
        subject="Hello",
        sender="a@b.com",
        recipients_to=["c@d.com"],
        recipients_cc=[],
        recipients_bcc=[],
        date=datetime.datetime(2025, 1, 1),
        body_plain="hi",
        body_html="",
        headers={},
        attachments=[],
        is_read=False,
        is_flagged=False,
    )
    assert msg.has_attachments is False


def test_message_all_recipients():
    msg = Message(
        subject="Hello",
        sender="a@b.com",
        recipients_to=["to@b.com"],
        recipients_cc=["cc@b.com"],
        recipients_bcc=["bcc@b.com"],
        date=datetime.datetime(2025, 1, 1),
        body_plain="hi",
        body_html="",
        headers={},
        attachments=[],
        is_read=False,
        is_flagged=False,
    )
    assert msg.all_recipients == ["to@b.com", "cc@b.com", "bcc@b.com"]


def test_folder_creation():
    child = Folder(name="Subfolder", message_count=5, children=[], _folder_id="f2")
    parent = Folder(name="Inbox", message_count=10, children=[child], _folder_id="f1")
    assert len(parent.children) == 1
    assert parent.children[0].name == "Subfolder"


def test_mailbox_creation():
    mb = Mailbox(
        path=Path("/tmp/test.pst"),
        format_type="PST",
        folders=[],
        total_messages=0,
    )
    assert mb.format_type == "PST"
    assert mb.total_messages == 0


def test_contact_creation():
    c = Contact(
        display_name="John Doe",
        email_addresses=["john@corp.com", "jdoe@corp.com"],
        phone_numbers=["+1-555-0100"],
        organization="Corp Inc",
        title="CTO",
    )
    assert c.display_name == "John Doe"
    assert len(c.email_addresses) == 2


def test_severity_ordering():
    assert Severity.LOW.value < Severity.MEDIUM.value
    assert Severity.MEDIUM.value < Severity.HIGH.value
    assert Severity.HIGH.value < Severity.CRITICAL.value


def test_scan_finding_creation():
    finding = ScanFinding(
        rule_name="password_plain",
        severity=Severity.HIGH,
        matched_text="Password: Summer2025!",
        context="Username: jdoe\nPassword: Summer2025!\nLet me know",
        message_subject="RE: VPN credentials",
        message_sender="jane@corp.com",
        message_date=datetime.datetime(2025, 3, 15),
        folder_path="Inbox",
    )
    assert finding.severity == Severity.HIGH
    assert "Summer2025" in finding.matched_text
