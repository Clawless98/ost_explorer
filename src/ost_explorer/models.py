from __future__ import annotations

import datetime
import enum
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional


class Severity(enum.IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Attachment:
    filename: str
    size: int
    mime_type: str
    _extract_fn: Optional[Callable[[], bytes]]

    def extract_bytes(self) -> bytes:
        if self._extract_fn is None:
            return b""
        return self._extract_fn()


@dataclass
class Message:
    subject: str
    sender: str
    recipients_to: list[str]
    recipients_cc: list[str]
    recipients_bcc: list[str]
    date: datetime.datetime
    body_plain: str
    body_html: str
    headers: dict[str, str]
    attachments: list[Attachment]
    is_read: bool
    is_flagged: bool

    @property
    def has_attachments(self) -> bool:
        return len(self.attachments) > 0

    @property
    def all_recipients(self) -> list[str]:
        return self.recipients_to + self.recipients_cc + self.recipients_bcc


@dataclass
class Folder:
    name: str
    message_count: int
    children: list[Folder]
    _folder_id: str


@dataclass
class Mailbox:
    path: Path
    format_type: str  # "PST" or "OST"
    folders: list[Folder]
    total_messages: int


@dataclass
class Contact:
    display_name: str
    email_addresses: list[str]
    phone_numbers: list[str]
    organization: str
    title: str


@dataclass
class ScanFinding:
    rule_name: str
    severity: Severity
    matched_text: str
    context: str
    message_subject: str
    message_sender: str
    message_date: datetime.datetime
    folder_path: str
