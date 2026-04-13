from __future__ import annotations

import datetime
from pathlib import Path

import pytest

from ost_explorer.models import (
    Attachment,
    Contact,
    Folder,
    Mailbox,
    Message,
)


@pytest.fixture
def sample_attachment() -> Attachment:
    return Attachment(
        filename="secret.docx",
        size=2048,
        mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        _extract_fn=lambda: b"fake document content",
    )


@pytest.fixture
def sample_message(sample_attachment: Attachment) -> Message:
    return Message(
        subject="RE: VPN credentials",
        sender="jane@corp.com",
        recipients_to=["user@corp.com"],
        recipients_cc=[],
        recipients_bcc=[],
        date=datetime.datetime(2025, 3, 15, 10, 30, 0),
        body_plain="Hey, here are the creds:\nUsername: jdoe\nPassword: Summer2025!\n",
        body_html="<html><body>Hey, here are the creds:<br>Username: jdoe<br>Password: Summer2025!</body></html>",
        headers={"Message-ID": "<abc123@corp.com>"},
        attachments=[sample_attachment],
        is_read=True,
        is_flagged=False,
    )


@pytest.fixture
def sample_folder(sample_message: Message) -> Folder:
    return Folder(
        name="Inbox",
        message_count=1,
        children=[],
        _folder_id="folder_001",
    )


@pytest.fixture
def sample_mailbox(sample_folder: Folder) -> Mailbox:
    return Mailbox(
        path=Path("/tmp/test.pst"),
        format_type="PST",
        folders=[sample_folder],
        total_messages=1,
    )


@pytest.fixture
def tmp_rules_dir(tmp_path: Path) -> Path:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    return rules_dir
