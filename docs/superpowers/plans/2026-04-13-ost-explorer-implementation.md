# ost_explorer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Python CLI + TUI tool that parses PST/OST email archives and provides interactive browsing, comprehensive secret detection, and multi-format export for penetration test engagements.

**Architecture:** Four-layer design — pypff/olefile parsers wrapped by a mailbox abstraction, a core engine layer (search, scanner, export), and a Textual TUI on top. CLI entry point via Click with `browse`, `scan`, `export`, `info`, and `validate` commands.

**Tech Stack:** Python 3.12, pypff (libpff), olefile, Textual, Click, PyYAML, Jinja2, SQLite (caching)

---

## File Structure

```
ost_explorer/
├── src/
│   └── ost_explorer/
│       ├── __init__.py              # Version string
│       ├── cli.py                   # Click CLI entry point (browse, scan, export, info, validate)
│       ├── models.py                # Dataclasses: Mailbox, Folder, Message, Attachment, Contact, ScanFinding
│       ├── parser/
│       │   ├── __init__.py          # Re-exports open_mailbox()
│       │   ├── base.py             # MailboxParser ABC
│       │   ├── pypff_parser.py     # pypff-based parser implementation
│       │   ├── ole_parser.py       # olefile fallback parser
│       │   ├── detect.py           # Format auto-detection (header sniffing)
│       │   └── cache.py            # SQLite metadata cache
│       ├── engine/
│       │   ├── __init__.py
│       │   ├── search.py           # Search engine with filter syntax parser
│       │   ├── scanner.py          # Sensitive data scanner (loads rules, scans messages)
│       │   └── export.py           # JSON/CSV/HTML/attachment export
│       ├── rules/
│       │   ├── __init__.py
│       │   ├── loader.py           # YAML rule loader + validator
│       │   └── default_rules.yaml  # Comprehensive built-in detection rules
│       ├── tui/
│       │   ├── __init__.py
│       │   ├── app.py              # Main Textual app, layout, keybindings
│       │   ├── folder_tree.py      # Folder pane widget (Tree)
│       │   ├── message_list.py     # Message list pane widget (DataTable)
│       │   ├── message_view.py     # Message viewer pane widget (RichLog/Static)
│       │   ├── search_bar.py       # Search input widget
│       │   └── export_dialog.py    # Export options modal dialog
│       └── templates/
│           └── report.html         # Jinja2 HTML report template
├── rules/
│   └── example_rules.yaml          # Example custom rules for users
├── tests/
│   ├── __init__.py
│   ├── conftest.py                 # Shared fixtures (mock mailbox, temp dirs)
│   ├── test_models.py
│   ├── test_detect.py
│   ├── test_cache.py
│   ├── test_rules_loader.py
│   ├── test_search.py
│   ├── test_scanner.py
│   ├── test_export.py
│   └── test_cli.py
├── pyproject.toml
└── README.md
```

---

## Task 1: Project Scaffolding and Dependencies

**Files:**
- Create: `pyproject.toml`
- Create: `src/ost_explorer/__init__.py`
- Create: `tests/__init__.py`
- Create: `tests/conftest.py`
- Create: `.gitignore`

- [ ] **Step 1: Create pyproject.toml**

```toml
[build-system]
requires = ["setuptools>=68.0", "wheel"]
build-backend = "setuptools.backends._legacy:_Backend"

[project]
name = "ost-explorer"
version = "0.1.0"
description = "PST/OST email archive triage tool for penetration testing"
requires-python = ">=3.10"
dependencies = [
    "textual>=0.70.0",
    "click>=8.0",
    "pyyaml>=6.0",
    "jinja2>=3.0",
    "olefile>=0.46",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0",
    "pytest-asyncio>=0.23.0",
]

[project.scripts]
ost_explorer = "ost_explorer.cli:cli"

[tool.setuptools.packages.find]
where = ["src"]

[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"
```

- [ ] **Step 2: Create src/ost_explorer/__init__.py**

```python
__version__ = "0.1.0"
```

- [ ] **Step 3: Create tests/__init__.py and tests/conftest.py**

`tests/__init__.py` — empty file.

`tests/conftest.py`:

```python
from __future__ import annotations

import datetime
from dataclasses import field
from pathlib import Path
from typing import Generator

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
```

- [ ] **Step 4: Create .gitignore**

```
__pycache__/
*.pyc
*.egg-info/
dist/
build/
.venv/
*.pst.cache.db
*.ost.cache.db
.pytest_cache/
```

- [ ] **Step 5: Create virtual environment and install dependencies**

Run:
```bash
cd /home/ai-dev/projects/ost_explorer
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Expected: Successful install with all dependencies resolved.

- [ ] **Step 6: Verify pytest runs (no tests yet)**

Run: `cd /home/ai-dev/projects/ost_explorer && source .venv/bin/activate && python -m pytest --co -q`

Expected: "no tests ran" or similar — confirms pytest is configured.

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml src/ost_explorer/__init__.py tests/__init__.py tests/conftest.py .gitignore
git commit -m "feat: scaffold project structure and dependencies"
```

---

## Task 2: Data Models

**Files:**
- Create: `src/ost_explorer/models.py`
- Create: `tests/test_models.py`

- [ ] **Step 1: Write failing tests for data models**

`tests/test_models.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/ai-dev/projects/ost_explorer && source .venv/bin/activate && python -m pytest tests/test_models.py -v`

Expected: FAIL — `ModuleNotFoundError: No module named 'ost_explorer.models'`

- [ ] **Step 3: Implement models**

`src/ost_explorer/models.py`:

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/ai-dev/projects/ost_explorer && source .venv/bin/activate && python -m pytest tests/test_models.py -v`

Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ost_explorer/models.py tests/test_models.py
git commit -m "feat: add data models (Mailbox, Folder, Message, Attachment, Contact, ScanFinding)"
```

---

## Task 3: Format Auto-Detection

**Files:**
- Create: `src/ost_explorer/parser/__init__.py`
- Create: `src/ost_explorer/parser/detect.py`
- Create: `tests/test_detect.py`

- [ ] **Step 1: Write failing tests for format detection**

`tests/test_detect.py`:

```python
from __future__ import annotations

from pathlib import Path

import pytest

from ost_explorer.parser.detect import detect_format, FormatError


def test_detect_pst_format(tmp_path: Path):
    pst_file = tmp_path / "test.pst"
    # PST magic bytes: !BDN (hex: 21 42 44 4E) at offset 0
    header = b"!BDN" + b"\x00" * 10 + b"\x17" + b"\x00" * 497
    pst_file.write_bytes(header)
    assert detect_format(pst_file) == "PST"


def test_detect_ost_format(tmp_path: Path):
    ost_file = tmp_path / "test.ost"
    # OST shares the same magic but has different version byte at offset 10
    header = b"!BDN" + b"\x00" * 10 + b"\x15" + b"\x00" * 497
    ost_file.write_bytes(header)
    assert detect_format(ost_file) == "OST"


def test_detect_unknown_format(tmp_path: Path):
    bad_file = tmp_path / "test.xyz"
    bad_file.write_bytes(b"this is not a pst file at all")
    with pytest.raises(FormatError, match="Unrecognized file format"):
        detect_format(bad_file)


def test_detect_file_not_found():
    with pytest.raises(FileNotFoundError):
        detect_format(Path("/nonexistent/file.pst"))


def test_detect_file_too_small(tmp_path: Path):
    tiny = tmp_path / "tiny.pst"
    tiny.write_bytes(b"!BD")
    with pytest.raises(FormatError, match="too small"):
        detect_format(tiny)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/ai-dev/projects/ost_explorer && source .venv/bin/activate && python -m pytest tests/test_detect.py -v`

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement format detection**

`src/ost_explorer/parser/__init__.py`:

```python
from ost_explorer.parser.detect import detect_format

__all__ = ["detect_format"]
```

`src/ost_explorer/parser/detect.py`:

```python
from __future__ import annotations

from pathlib import Path

# PST/OST magic: "!BDN" at offset 0 (hex 21 42 44 4E)
_PST_MAGIC = b"!BDN"
_MIN_HEADER_SIZE = 512

# Version byte at offset 10:
# 0x17 (23) = PST (ANSI or Unicode)
# 0x15 (21) = OST
# 0x0E (14) = PST (older ANSI)
# 0x24 (36) = PST (Unicode 4k)
_PST_VERSIONS = {0x17, 0x0E, 0x24}
_OST_VERSIONS = {0x15}


class FormatError(Exception):
    pass


def detect_format(path: Path) -> str:
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    size = path.stat().st_size
    if size < _MIN_HEADER_SIZE:
        raise FormatError(f"File too small to be a PST/OST ({size} bytes)")

    with open(path, "rb") as f:
        header = f.read(_MIN_HEADER_SIZE)

    if header[:4] != _PST_MAGIC:
        raise FormatError(f"Unrecognized file format (magic bytes: {header[:4]!r})")

    version_byte = header[10]
    if version_byte in _OST_VERSIONS:
        return "OST"
    return "PST"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/ai-dev/projects/ost_explorer && source .venv/bin/activate && python -m pytest tests/test_detect.py -v`

Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ost_explorer/parser/__init__.py src/ost_explorer/parser/detect.py tests/test_detect.py
git commit -m "feat: add PST/OST format auto-detection via header sniffing"
```

---

## Task 4: Parser Base Class and pypff Implementation

**Files:**
- Create: `src/ost_explorer/parser/base.py`
- Create: `src/ost_explorer/parser/pypff_parser.py`
- Create: `src/ost_explorer/parser/ole_parser.py`

Note: pypff may not be available in the dev environment. The parser will gracefully degrade. Tests for parser internals require mock objects since we cannot depend on PST files being available at test time.

- [ ] **Step 1: Implement parser base class**

`src/ost_explorer/parser/base.py`:

```python
from __future__ import annotations

import abc
from pathlib import Path

from ost_explorer.models import Attachment, Contact, Folder, Mailbox, Message


class MailboxParser(abc.ABC):
    @abc.abstractmethod
    def open(self, path: Path) -> Mailbox:
        """Open a PST/OST file and return a Mailbox with folder tree."""
        ...

    @abc.abstractmethod
    def get_messages(self, folder: Folder, offset: int = 0, limit: int = 50) -> list[Message]:
        """Get paginated messages from a folder."""
        ...

    @abc.abstractmethod
    def get_attachment_bytes(self, attachment: Attachment) -> bytes:
        """Extract raw bytes from an attachment."""
        ...

    @abc.abstractmethod
    def get_recovered_messages(self) -> list[Message]:
        """Get deleted/recovered messages from unallocated space."""
        ...

    @abc.abstractmethod
    def get_contacts(self) -> list[Contact]:
        """Extract contacts from the Contacts folder."""
        ...

    @abc.abstractmethod
    def close(self) -> None:
        """Release resources."""
        ...
```

- [ ] **Step 2: Implement pypff parser**

`src/ost_explorer/parser/pypff_parser.py`:

```python
from __future__ import annotations

import datetime
import logging
from pathlib import Path
from typing import Any, Optional

from ost_explorer.models import Attachment, Contact, Folder, Mailbox, Message
from ost_explorer.parser.base import MailboxParser
from ost_explorer.parser.detect import detect_format

logger = logging.getLogger(__name__)

try:
    import pypff

    HAS_PYPFF = True
except ImportError:
    HAS_PYPFF = False


class PypffParser(MailboxParser):
    def __init__(self) -> None:
        if not HAS_PYPFF:
            raise ImportError(
                "pypff is not installed. Install libpff and its Python bindings:\n"
                "  apt install libpff-dev\n"
                "  pip install pypff"
            )
        self._pff_file: Any = None
        self._path: Optional[Path] = None

    def open(self, path: Path) -> Mailbox:
        self._path = path
        format_type = detect_format(path)

        self._pff_file = pypff.file()
        try:
            self._pff_file.open(str(path))
        except Exception as e:
            raise IOError(f"Failed to open {path}: {e}") from e

        root = self._pff_file.get_root_folder()
        folders = self._build_folder_tree(root)
        total = sum(f.message_count for f in self._flatten_folders(folders))

        return Mailbox(
            path=path,
            format_type=format_type,
            folders=folders,
            total_messages=total,
        )

    def _build_folder_tree(self, pff_folder: Any) -> list[Folder]:
        folders: list[Folder] = []
        for i in range(pff_folder.get_number_of_sub_folders()):
            sub = pff_folder.get_sub_folder(i)
            children = self._build_folder_tree(sub)
            folder = Folder(
                name=sub.get_name() or "(unnamed)",
                message_count=sub.get_number_of_sub_messages(),
                children=children,
                _folder_id=str(id(sub)),
            )
            # Store reference for later message retrieval
            folder._pff_folder = sub  # type: ignore[attr-defined]
            folders.append(folder)
        return folders

    def _flatten_folders(self, folders: list[Folder]) -> list[Folder]:
        result: list[Folder] = []
        for f in folders:
            result.append(f)
            result.extend(self._flatten_folders(f.children))
        return result

    def get_messages(self, folder: Folder, offset: int = 0, limit: int = 50) -> list[Message]:
        pff_folder = getattr(folder, "_pff_folder", None)
        if pff_folder is None:
            return []

        messages: list[Message] = []
        total = pff_folder.get_number_of_sub_messages()
        end = min(offset + limit, total)

        for i in range(offset, end):
            try:
                pff_msg = pff_folder.get_sub_message(i)
                messages.append(self._convert_message(pff_msg))
            except Exception as e:
                logger.warning("Failed to parse message %d in %s: %s", i, folder.name, e)
                continue

        return messages

    def _convert_message(self, pff_msg: Any) -> Message:
        attachments: list[Attachment] = []
        for j in range(pff_msg.get_number_of_attachments()):
            try:
                pff_att = pff_msg.get_attachment(j)
                att_ref = pff_att  # capture for closure
                attachments.append(
                    Attachment(
                        filename=pff_att.get_name() or f"attachment_{j}",
                        size=pff_att.get_size(),
                        mime_type=pff_att.get_content_type() or "application/octet-stream",
                        _extract_fn=lambda a=att_ref: a.read_buffer(a.get_size()),
                    )
                )
            except Exception as e:
                logger.warning("Failed to parse attachment %d: %s", j, e)

        # Parse date
        msg_date = None
        try:
            msg_date = pff_msg.get_delivery_time()
        except Exception:
            msg_date = datetime.datetime(1970, 1, 1)

        return Message(
            subject=pff_msg.get_subject() or "(no subject)",
            sender=pff_msg.get_sender_name() or "",
            recipients_to=self._safe_split(pff_msg.get_display_to()),
            recipients_cc=self._safe_split(pff_msg.get_display_cc()),
            recipients_bcc=self._safe_split(pff_msg.get_display_bcc()),
            date=msg_date or datetime.datetime(1970, 1, 1),
            body_plain=pff_msg.get_plain_text_body() or "",
            body_html=pff_msg.get_html_body() or "",
            headers=self._parse_headers(pff_msg.get_transport_headers()),
            attachments=attachments,
            is_read=True,  # pypff doesn't expose read status easily
            is_flagged=False,
        )

    def _safe_split(self, value: Optional[str]) -> list[str]:
        if not value:
            return []
        return [addr.strip() for addr in value.split(";") if addr.strip()]

    def _parse_headers(self, raw: Optional[str]) -> dict[str, str]:
        if not raw:
            return {}
        headers: dict[str, str] = {}
        for line in raw.split("\n"):
            if ": " in line:
                key, _, val = line.partition(": ")
                headers[key.strip()] = val.strip()
        return headers

    def get_attachment_bytes(self, attachment: Attachment) -> bytes:
        return attachment.extract_bytes()

    def get_recovered_messages(self) -> list[Message]:
        if self._pff_file is None:
            return []
        messages: list[Message] = []
        try:
            recovered = self._pff_file.get_recovered_items()
            if recovered is None:
                return []
            for i in range(recovered.get_number_of_sub_messages()):
                try:
                    pff_msg = recovered.get_sub_message(i)
                    messages.append(self._convert_message(pff_msg))
                except Exception as e:
                    logger.warning("Failed to recover message %d: %s", i, e)
        except Exception as e:
            logger.warning("Deleted item recovery not available: %s", e)
        return messages

    def get_contacts(self) -> list[Contact]:
        # Contacts are stored in a folder named "Contacts" — find it and parse
        if self._pff_file is None:
            return []
        contacts: list[Contact] = []
        root = self._pff_file.get_root_folder()
        contacts_folder = self._find_folder(root, "Contacts")
        if contacts_folder is None:
            return []
        for i in range(contacts_folder.get_number_of_sub_messages()):
            try:
                item = contacts_folder.get_sub_message(i)
                contacts.append(
                    Contact(
                        display_name=item.get_subject() or "",
                        email_addresses=[item.get_sender_name() or ""],
                        phone_numbers=[],
                        organization="",
                        title="",
                    )
                )
            except Exception as e:
                logger.warning("Failed to parse contact %d: %s", i, e)
        return contacts

    def _find_folder(self, pff_folder: Any, name: str) -> Any:
        for i in range(pff_folder.get_number_of_sub_folders()):
            sub = pff_folder.get_sub_folder(i)
            if sub.get_name() and sub.get_name().lower() == name.lower():
                return sub
            found = self._find_folder(sub, name)
            if found:
                return found
        return None

    def close(self) -> None:
        if self._pff_file is not None:
            try:
                self._pff_file.close()
            except Exception:
                pass
            self._pff_file = None
```

- [ ] **Step 3: Implement olefile fallback parser stub**

`src/ost_explorer/parser/ole_parser.py`:

```python
from __future__ import annotations

import logging
from pathlib import Path

from ost_explorer.models import Attachment, Contact, Folder, Mailbox, Message
from ost_explorer.parser.base import MailboxParser
from ost_explorer.parser.detect import detect_format

logger = logging.getLogger(__name__)

try:
    import olefile

    HAS_OLEFILE = True
except ImportError:
    HAS_OLEFILE = False


class OleParser(MailboxParser):
    """Fallback parser using olefile for corrupted/partial PST files.

    This provides best-effort parsing when pypff cannot open a file.
    Coverage is limited compared to pypff — folder structure and basic
    message metadata are available, but full body/attachment support
    depends on the file's internal structure.
    """

    def __init__(self) -> None:
        if not HAS_OLEFILE:
            raise ImportError("olefile is not installed: pip install olefile")
        self._ole = None
        self._path: Path | None = None

    def open(self, path: Path) -> Mailbox:
        self._path = path
        format_type = detect_format(path)

        try:
            self._ole = olefile.OleFileIO(str(path))
        except Exception as e:
            raise IOError(f"olefile could not open {path}: {e}") from e

        # olefile gives us stream listings — map to folders
        folders = self._extract_folders()
        total = sum(f.message_count for f in folders)

        return Mailbox(
            path=path,
            format_type=format_type,
            folders=folders,
            total_messages=total,
        )

    def _extract_folders(self) -> list[Folder]:
        if self._ole is None:
            return []
        # Best-effort: list OLE streams and group into folder-like structures
        folders: list[Folder] = []
        try:
            streams = self._ole.listdir()
            folder_names: set[str] = set()
            for stream in streams:
                if len(stream) > 0:
                    folder_names.add(stream[0])
            for name in sorted(folder_names):
                folders.append(
                    Folder(
                        name=name,
                        message_count=0,
                        children=[],
                        _folder_id=name,
                    )
                )
        except Exception as e:
            logger.warning("Failed to extract folder tree: %s", e)
        return folders

    def get_messages(self, folder: Folder, offset: int = 0, limit: int = 50) -> list[Message]:
        # olefile fallback has limited message extraction
        logger.warning("OLE parser message extraction is limited — use pypff for full support")
        return []

    def get_attachment_bytes(self, attachment: Attachment) -> bytes:
        return attachment.extract_bytes()

    def get_recovered_messages(self) -> list[Message]:
        logger.warning("Deleted item recovery not available with OLE parser")
        return []

    def get_contacts(self) -> list[Contact]:
        return []

    def close(self) -> None:
        if self._ole is not None:
            try:
                self._ole.close()
            except Exception:
                pass
            self._ole = None
```

- [ ] **Step 4: Update parser/__init__.py with open_mailbox factory**

`src/ost_explorer/parser/__init__.py`:

```python
from __future__ import annotations

import logging
from pathlib import Path

from ost_explorer.models import Mailbox
from ost_explorer.parser.base import MailboxParser
from ost_explorer.parser.detect import detect_format

logger = logging.getLogger(__name__)

__all__ = ["detect_format", "open_mailbox"]


def open_mailbox(path: Path) -> tuple[Mailbox, MailboxParser]:
    """Open a PST/OST file with the best available parser.

    Returns (Mailbox, parser_instance) — caller must call parser.close() when done.
    Tries pypff first, falls back to olefile.
    """
    path = Path(path)

    # Try pypff first
    try:
        from ost_explorer.parser.pypff_parser import PypffParser

        parser = PypffParser()
        mailbox = parser.open(path)
        logger.info("Opened %s with pypff parser", path)
        return mailbox, parser
    except ImportError:
        logger.info("pypff not available, trying olefile fallback")
    except IOError as e:
        logger.warning("pypff failed to open %s: %s — trying olefile", path, e)

    # Fall back to olefile
    try:
        from ost_explorer.parser.ole_parser import OleParser

        parser = OleParser()
        mailbox = parser.open(path)
        logger.info("Opened %s with olefile fallback parser", path)
        return mailbox, parser
    except ImportError:
        raise ImportError("No parser available. Install pypff or olefile.")
    except IOError as e:
        raise IOError(f"No parser could open {path}: {e}") from e
```

- [ ] **Step 5: Commit**

```bash
git add src/ost_explorer/parser/
git commit -m "feat: add parser layer (pypff primary, olefile fallback, format detection)"
```

---

## Task 5: SQLite Metadata Cache

**Files:**
- Create: `src/ost_explorer/parser/cache.py`
- Create: `tests/test_cache.py`

- [ ] **Step 1: Write failing tests for cache**

`tests/test_cache.py`:

```python
from __future__ import annotations

import datetime
import json
from pathlib import Path

import pytest

from ost_explorer.parser.cache import MetadataCache
from ost_explorer.models import Folder, Message


@pytest.fixture
def cache_db(tmp_path: Path) -> Path:
    return tmp_path / "test.pst.cache.db"


@pytest.fixture
def pst_file(tmp_path: Path) -> Path:
    f = tmp_path / "test.pst"
    f.write_bytes(b"fake pst content for testing")
    return f


def test_cache_is_valid_when_empty(cache_db: Path, pst_file: Path):
    cache = MetadataCache(cache_db, pst_file)
    assert cache.is_valid() is False


def test_cache_store_and_load_folders(cache_db: Path, pst_file: Path):
    cache = MetadataCache(cache_db, pst_file)
    folders = [
        Folder(name="Inbox", message_count=10, children=[], _folder_id="f1"),
        Folder(name="Sent", message_count=5, children=[], _folder_id="f2"),
    ]
    cache.store_folders(folders)
    assert cache.is_valid() is True

    loaded = cache.load_folders()
    assert len(loaded) == 2
    assert loaded[0].name == "Inbox"
    assert loaded[0].message_count == 10
    assert loaded[1].name == "Sent"


def test_cache_store_and_load_nested_folders(cache_db: Path, pst_file: Path):
    cache = MetadataCache(cache_db, pst_file)
    child = Folder(name="Work", message_count=3, children=[], _folder_id="f3")
    parent = Folder(name="Inbox", message_count=10, children=[child], _folder_id="f1")
    cache.store_folders([parent])

    loaded = cache.load_folders()
    assert len(loaded) == 1
    assert len(loaded[0].children) == 1
    assert loaded[0].children[0].name == "Work"


def test_cache_invalidated_when_file_changes(cache_db: Path, pst_file: Path):
    cache = MetadataCache(cache_db, pst_file)
    folders = [Folder(name="Inbox", message_count=1, children=[], _folder_id="f1")]
    cache.store_folders(folders)
    assert cache.is_valid() is True

    # Modify the source file
    pst_file.write_bytes(b"modified content that changes mtime and size")
    cache2 = MetadataCache(cache_db, pst_file)
    assert cache2.is_valid() is False


def test_cache_store_and_load_message_metadata(cache_db: Path, pst_file: Path):
    cache = MetadataCache(cache_db, pst_file)
    folders = [Folder(name="Inbox", message_count=1, children=[], _folder_id="f1")]
    cache.store_folders(folders)

    msg = {
        "subject": "Test",
        "sender": "a@b.com",
        "date": "2025-03-15T10:30:00",
        "has_attachments": True,
    }
    cache.store_message_metadata("f1", [msg])
    loaded = cache.load_message_metadata("f1")
    assert len(loaded) == 1
    assert loaded[0]["subject"] == "Test"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/ai-dev/projects/ost_explorer && source .venv/bin/activate && python -m pytest tests/test_cache.py -v`

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement cache**

`src/ost_explorer/parser/cache.py`:

```python
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from ost_explorer.models import Folder


class MetadataCache:
    def __init__(self, cache_path: Path, source_path: Path) -> None:
        self._cache_path = cache_path
        self._source_path = source_path
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    def _init_db(self) -> None:
        self._conn = sqlite3.connect(str(self._cache_path))
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS meta ("
            "  key TEXT PRIMARY KEY,"
            "  value TEXT"
            ")"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS folders ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  data TEXT"
            ")"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS messages ("
            "  folder_id TEXT,"
            "  data TEXT"
            ")"
        )
        self._conn.commit()

    def is_valid(self) -> bool:
        if self._conn is None:
            return False
        row = self._conn.execute("SELECT value FROM meta WHERE key='source_mtime'").fetchone()
        if row is None:
            return False
        stored_mtime = float(row[0])
        row2 = self._conn.execute("SELECT value FROM meta WHERE key='source_size'").fetchone()
        if row2 is None:
            return False
        stored_size = int(row2[0])

        current_stat = self._source_path.stat()
        return (
            abs(current_stat.st_mtime - stored_mtime) < 0.001
            and current_stat.st_size == stored_size
        )

    def store_folders(self, folders: list[Folder]) -> None:
        if self._conn is None:
            return
        data = json.dumps(self._serialize_folders(folders))
        self._conn.execute("DELETE FROM folders")
        self._conn.execute("INSERT INTO folders (data) VALUES (?)", (data,))
        # Store source file metadata for validity check
        stat = self._source_path.stat()
        self._conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('source_mtime', ?)",
            (str(stat.st_mtime),),
        )
        self._conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('source_size', ?)",
            (str(stat.st_size),),
        )
        self._conn.commit()

    def load_folders(self) -> list[Folder]:
        if self._conn is None:
            return []
        row = self._conn.execute("SELECT data FROM folders LIMIT 1").fetchone()
        if row is None:
            return []
        return self._deserialize_folders(json.loads(row[0]))

    def store_message_metadata(self, folder_id: str, messages: list[dict]) -> None:
        if self._conn is None:
            return
        data = json.dumps(messages)
        self._conn.execute("DELETE FROM messages WHERE folder_id = ?", (folder_id,))
        self._conn.execute("INSERT INTO messages (folder_id, data) VALUES (?, ?)", (folder_id, data))
        self._conn.commit()

    def load_message_metadata(self, folder_id: str) -> list[dict]:
        if self._conn is None:
            return []
        row = self._conn.execute(
            "SELECT data FROM messages WHERE folder_id = ?", (folder_id,)
        ).fetchone()
        if row is None:
            return []
        return json.loads(row[0])

    def _serialize_folders(self, folders: list[Folder]) -> list[dict]:
        return [
            {
                "name": f.name,
                "message_count": f.message_count,
                "folder_id": f._folder_id,
                "children": self._serialize_folders(f.children),
            }
            for f in folders
        ]

    def _deserialize_folders(self, data: list[dict]) -> list[Folder]:
        return [
            Folder(
                name=d["name"],
                message_count=d["message_count"],
                children=self._deserialize_folders(d.get("children", [])),
                _folder_id=d["folder_id"],
            )
            for d in data
        ]

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/ai-dev/projects/ost_explorer && source .venv/bin/activate && python -m pytest tests/test_cache.py -v`

Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ost_explorer/parser/cache.py tests/test_cache.py
git commit -m "feat: add SQLite metadata cache for fast repeated opens"
```

---

## Task 6: Rule Loader

**Files:**
- Create: `src/ost_explorer/rules/__init__.py`
- Create: `src/ost_explorer/rules/loader.py`
- Create: `tests/test_rules_loader.py`

- [ ] **Step 1: Write failing tests for rule loader**

`tests/test_rules_loader.py`:

```python
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
  pattern: "EMP-\\\\d{6}"
  severity: low
"""
    rules = load_rules_from_string(yaml_str)
    assert rules[0].matches("Employee EMP-123456 started today")
    assert not rules[0].matches("EMP-12345")  # too short


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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/ai-dev/projects/ost_explorer && source .venv/bin/activate && python -m pytest tests/test_rules_loader.py -v`

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement rule loader**

`src/ost_explorer/rules/__init__.py`:

```python
from ost_explorer.rules.loader import Rule, load_rules_from_yaml, load_rules_from_string

__all__ = ["Rule", "load_rules_from_yaml", "load_rules_from_string"]
```

`src/ost_explorer/rules/loader.py`:

```python
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

VALID_SEVERITIES = {"low", "medium", "high", "critical"}


class RuleValidationError(Exception):
    pass


@dataclass
class Rule:
    name: str
    severity: str
    note: str
    _compiled_patterns: list[re.Pattern] = field(repr=False, default_factory=list)

    def matches(self, text: str) -> bool:
        return any(p.search(text) for p in self._compiled_patterns)

    def find_all(self, text: str) -> list[re.Match]:
        results: list[re.Match] = []
        for p in self._compiled_patterns:
            results.extend(p.finditer(text))
        return results


def load_rules_from_string(yaml_str: str) -> list[Rule]:
    data = yaml.safe_load(yaml_str)
    if not isinstance(data, list):
        raise RuleValidationError("Rules file must be a YAML list")
    return [_parse_rule(entry, idx) for idx, entry in enumerate(data)]


def load_rules_from_yaml(path: Path) -> list[Rule]:
    text = path.read_text()
    return load_rules_from_string(text)


def _parse_rule(entry: dict, index: int) -> Rule:
    if not isinstance(entry, dict):
        raise RuleValidationError(f"Rule at index {index}: expected a mapping, got {type(entry).__name__}")

    name = entry.get("name")
    if not name:
        raise RuleValidationError(f"Rule at index {index}: missing 'name' field")

    severity = entry.get("severity", "medium")
    if severity not in VALID_SEVERITIES:
        raise RuleValidationError(
            f"Rule '{name}': invalid severity '{severity}' (must be one of: {', '.join(sorted(VALID_SEVERITIES))})"
        )

    note = entry.get("note", "")

    patterns: list[re.Pattern] = []

    if "find" in entry:
        # Plain text, case-insensitive
        escaped = re.escape(entry["find"])
        patterns.append(re.compile(escaped, re.IGNORECASE))
    elif "find_any" in entry:
        keywords = entry["find_any"]
        if not isinstance(keywords, list) or len(keywords) == 0:
            raise RuleValidationError(f"Rule '{name}': 'find_any' must be a non-empty list")
        for kw in keywords:
            escaped = re.escape(str(kw))
            patterns.append(re.compile(escaped, re.IGNORECASE))
    elif "pattern" in entry:
        raw = entry["pattern"]
        try:
            patterns.append(re.compile(raw, re.IGNORECASE))
        except re.error as e:
            raise RuleValidationError(f"Rule '{name}': invalid regex pattern: {e}")
    else:
        raise RuleValidationError(f"Rule '{name}': missing 'find', 'find_any', or 'pattern' field")

    return Rule(name=name, severity=severity, note=note, _compiled_patterns=patterns)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/ai-dev/projects/ost_explorer && source .venv/bin/activate && python -m pytest tests/test_rules_loader.py -v`

Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ost_explorer/rules/ tests/test_rules_loader.py
git commit -m "feat: add YAML rule loader with find/find_any/pattern support and validation"
```

---

## Task 7: Default Rules File

**Files:**
- Create: `src/ost_explorer/rules/default_rules.yaml`
- Create: `rules/example_rules.yaml`

- [ ] **Step 1: Create comprehensive default rules**

`src/ost_explorer/rules/default_rules.yaml`:

```yaml
# =============================================================================
# ost_explorer — Built-in Detection Rules
# =============================================================================
# These rules ship with the tool. Add your own in separate YAML files
# and load them with --rules custom.yaml
# =============================================================================

# ---------------------------------------------------------------------------
# CREDENTIALS & SECRETS
# ---------------------------------------------------------------------------

- name: password_plain
  pattern: "(?:password|passwd|pwd|pass)\\s*[:=]\\s*\\S+"
  severity: critical
  note: "Password in plaintext"

- name: credentials_keyword
  find_any:
    - "credentials:"
    - "login:"
    - "username:"
    - "auth_token"
  severity: high
  note: "Credential-related keywords"

- name: aws_access_key
  pattern: "AKIA[0-9A-Z]{16}"
  severity: critical
  note: "AWS Access Key ID"

- name: aws_secret_key
  pattern: "(?:aws_secret_access_key|secret_key)\\s*[:=]\\s*[A-Za-z0-9/+=]{40}"
  severity: critical
  note: "AWS Secret Access Key"

- name: azure_key
  pattern: "(?:AccountKey|azure[_-]?(?:storage|key|secret))\\s*[:=]\\s*[A-Za-z0-9+/=]{44,}"
  severity: critical
  note: "Azure storage or service key"

- name: gcp_service_key
  find_any:
    - "\"type\": \"service_account\""
    - "private_key_id"
    - "client_x509_cert_url"
  severity: critical
  note: "GCP service account key indicator"

- name: github_token
  pattern: "gh[ps]_[A-Za-z0-9_]{36,}"
  severity: critical
  note: "GitHub personal access or service token"

- name: gitlab_token
  pattern: "glpat-[A-Za-z0-9_\\-]{20,}"
  severity: critical
  note: "GitLab personal access token"

- name: slack_token
  pattern: "xox[baprs]-[A-Za-z0-9\\-]{10,}"
  severity: critical
  note: "Slack API token"

- name: stripe_key
  pattern: "(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}"
  severity: critical
  note: "Stripe API key"

- name: twilio_key
  pattern: "SK[0-9a-fA-F]{32}"
  severity: high
  note: "Twilio API key"

- name: sendgrid_key
  pattern: "SG\\.[A-Za-z0-9_\\-]{22}\\.[A-Za-z0-9_\\-]{43}"
  severity: critical
  note: "SendGrid API key"

- name: mailgun_key
  pattern: "key-[A-Za-z0-9]{32}"
  severity: high
  note: "Mailgun API key"

- name: jwt_token
  pattern: "eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}"
  severity: high
  note: "JSON Web Token"

- name: private_key_pem
  find_any:
    - "-----BEGIN RSA PRIVATE KEY-----"
    - "-----BEGIN PRIVATE KEY-----"
    - "-----BEGIN EC PRIVATE KEY-----"
    - "-----BEGIN OPENSSH PRIVATE KEY-----"
    - "-----BEGIN DSA PRIVATE KEY-----"
  severity: critical
  note: "Private key in PEM format"

- name: pgp_private_key
  find: "-----BEGIN PGP PRIVATE KEY BLOCK-----"
  severity: critical
  note: "PGP private key block"

- name: ssh_private_key
  find: "-----BEGIN OPENSSH PRIVATE KEY-----"
  severity: critical
  note: "SSH private key"

- name: connection_string_jdbc
  pattern: "jdbc:[a-z]+://[^\\s]+"
  severity: high
  note: "JDBC connection string"

- name: connection_string_mongodb
  pattern: "mongodb(?:\\+srv)?://[^\\s]+"
  severity: high
  note: "MongoDB connection string"

- name: connection_string_redis
  pattern: "redis://[^\\s]+"
  severity: high
  note: "Redis connection string"

- name: connection_string_postgres
  pattern: "postgres(?:ql)?://[^\\s]+"
  severity: high
  note: "PostgreSQL connection string"

- name: connection_string_mysql
  pattern: "mysql://[^\\s]+"
  severity: high
  note: "MySQL connection string"

- name: connection_string_odbc
  pattern: "(?:DSN|Driver)\\s*=\\s*[^;]+;.*(?:Uid|User)\\s*=\\s*[^;]+"
  severity: high
  note: "ODBC connection string"

- name: basic_auth_url
  pattern: "https?://[^:]+:[^@]+@[^\\s]+"
  severity: critical
  note: "Basic auth credentials in URL"

- name: bearer_token
  pattern: "(?:Bearer|Authorization)\\s+[A-Za-z0-9_\\-.~+/]+=*"
  severity: high
  note: "Bearer/authorization token"

- name: oauth_token
  pattern: "(?:access_token|refresh_token|oauth_token)\\s*[:=]\\s*[A-Za-z0-9_\\-.]{10,}"
  severity: high
  note: "OAuth token"

- name: session_id
  pattern: "(?:session_id|sessionid|PHPSESSID|JSESSIONID|ASP\\.NET_SessionId)\\s*[:=]\\s*[A-Za-z0-9_\\-]{10,}"
  severity: medium
  note: "Session identifier"

- name: keepass_reference
  find_any:
    - ".kdbx"
    - "KeePass"
    - "keepass"
  severity: high
  note: "KeePass password database reference"

- name: lastpass_reference
  find_any:
    - "LastPass"
    - "lastpass"
  severity: medium
  note: "LastPass reference"

- name: onepassword_reference
  find_any:
    - "1Password"
    - ".1pif"
  severity: medium
  note: "1Password reference"

# ---------------------------------------------------------------------------
# NETWORK & INFRASTRUCTURE
# ---------------------------------------------------------------------------

- name: internal_ip_rfc1918
  pattern: "(?:^|[\\s,;(])(?:10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|172\\.(?:1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3})(?:[\\s,;):]|$)"
  severity: medium
  note: "Internal IP address (RFC1918)"

- name: unc_path
  pattern: "\\\\\\\\[A-Za-z0-9_.\\-]+\\\\[A-Za-z0-9_.\\-\\$]+"
  severity: medium
  note: "UNC network path"

- name: vpn_config
  find_any:
    - "vpn gateway"
    - "vpn server"
    - "openvpn"
    - ".ovpn"
    - "ipsec"
    - "wireguard"
  severity: high
  note: "VPN configuration reference"

- name: rdp_connection
  find_any:
    - "mstsc"
    - ".rdp"
    - "remote desktop"
    - "rdp://"
    - "port 3389"
  severity: medium
  note: "RDP connection reference"

- name: ssh_connection
  pattern: "ssh\\s+(?:-[A-Za-z]\\s+)*[A-Za-z0-9_.@\\-]+(?:\\s+-p\\s+\\d+)?"
  severity: medium
  note: "SSH connection command"

- name: wifi_password
  pattern: "(?:wifi|wi-fi|wireless|wlan|ssid)\\s*(?:password|key|pass|psk)\\s*[:=]\\s*\\S+"
  severity: high
  note: "WiFi password"

- name: dns_record
  find_any:
    - "A record"
    - "CNAME record"
    - "MX record"
    - "TXT record"
    - "NS record"
  severity: low
  note: "DNS record reference"

- name: firewall_rule
  find_any:
    - "iptables"
    - "firewall rule"
    - "ufw allow"
    - "netsh advfirewall"
    - "security group"
  severity: medium
  note: "Firewall rule reference"

# ---------------------------------------------------------------------------
# PII & COMPLIANCE
# ---------------------------------------------------------------------------

- name: ssn
  pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b"
  severity: critical
  note: "Social Security Number (validate manually — Luhn check recommended)"

- name: credit_card_visa
  pattern: "\\b4\\d{3}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b"
  severity: critical
  note: "Visa credit card number (validate with Luhn)"

- name: credit_card_mastercard
  pattern: "\\b5[1-5]\\d{2}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b"
  severity: critical
  note: "Mastercard credit card number (validate with Luhn)"

- name: credit_card_amex
  pattern: "\\b3[47]\\d{2}[\\s-]?\\d{6}[\\s-]?\\d{5}\\b"
  severity: critical
  note: "American Express card number"

- name: bank_routing
  pattern: "(?:routing|aba|transit)\\s*(?:number|#|no\\.?)\\s*[:=]?\\s*\\d{9}"
  severity: critical
  note: "Bank routing/ABA number"

- name: bank_account
  pattern: "(?:account|acct)\\s*(?:number|#|no\\.?)\\s*[:=]?\\s*\\d{8,17}"
  severity: critical
  note: "Bank account number"

- name: passport_us
  pattern: "(?:passport)\\s*(?:number|#|no\\.?)\\s*[:=]?\\s*[A-Z]?\\d{8,9}"
  severity: critical
  note: "US passport number"

- name: drivers_license
  pattern: "(?:driver'?s?\\s*(?:license|licence|lic))\\s*(?:number|#|no\\.?)\\s*[:=]?\\s*[A-Z0-9]{5,15}"
  severity: high
  note: "Driver's license number"

- name: phone_us
  pattern: "(?:\\+?1[\\s.-]?)?\\(?\\d{3}\\)?[\\s.-]?\\d{3}[\\s.-]?\\d{4}"
  severity: low
  note: "US phone number"

- name: phone_international
  pattern: "\\+\\d{1,3}[\\s.-]?\\d{4,14}"
  severity: low
  note: "International phone number"

- name: dob_pattern
  pattern: "(?:date\\s*of\\s*birth|DOB|born|birthday)\\s*[:=]?\\s*\\d{1,2}[/\\-]\\d{1,2}[/\\-]\\d{2,4}"
  severity: high
  note: "Date of birth"

# ---------------------------------------------------------------------------
# SENSITIVE FILE TYPES (attachment names)
# ---------------------------------------------------------------------------

- name: private_key_file
  find_any:
    - ".pem"
    - ".key"
    - ".ppk"
    - ".pfx"
    - ".p12"
  severity: high
  note: "Private key file"

- name: password_database_file
  find_any:
    - ".kdbx"
    - ".kdb"
    - ".1pif"
    - ".agilekeychain"
  severity: critical
  note: "Password database file"

- name: config_file
  find_any:
    - ".env"
    - ".htpasswd"
    - "wp-config.php"
    - "web.config"
    - "appsettings.json"
  severity: high
  note: "Configuration file with potential secrets"

- name: script_file
  find_any:
    - ".ps1"
    - ".bat"
    - ".cmd"
    - ".sh"
    - ".bash"
  severity: medium
  note: "Script file (may contain credentials)"

- name: macro_document
  find_any:
    - ".xlsm"
    - ".docm"
    - ".pptm"
  severity: medium
  note: "Office document with macros"

- name: archive_file
  find_any:
    - ".zip"
    - ".7z"
    - ".rar"
    - ".tar.gz"
    - ".tgz"
  severity: low
  note: "Archive file (review contents manually)"

- name: certificate_file
  find_any:
    - ".crt"
    - ".cer"
    - ".der"
  severity: medium
  note: "Certificate file"

- name: database_dump
  find_any:
    - ".sql"
    - ".bak"
    - ".dump"
    - ".sqlite"
    - ".mdb"
  severity: high
  note: "Database dump or backup file"

# ---------------------------------------------------------------------------
# CONTEXTUAL PATTERNS
# ---------------------------------------------------------------------------

- name: confidential_marking
  find_any:
    - "do not share"
    - "do not distribute"
    - "confidential"
    - "internal only"
    - "eyes only"
    - "restricted"
    - "proprietary"
    - "not for external"
  severity: medium
  note: "Confidentiality marking — message may contain sensitive info"

- name: credential_issuance
  find_any:
    - "temporary password"
    - "temp password"
    - "one-time code"
    - "reset link"
    - "your new password"
    - "initial password"
    - "default password"
  severity: high
  note: "Credential issuance language — likely contains a password"

- name: credential_exchange
  find_any:
    - "here are the credentials"
    - "here are the creds"
    - "here is the password"
    - "as requested, the password"
    - "login details below"
    - "access details"
    - "attached are the credentials"
  severity: high
  note: "Credential exchange pattern"

- name: wire_transfer
  find_any:
    - "wire transfer"
    - "wire instructions"
    - "bank details"
    - "routing number"
    - "swift code"
    - "IBAN"
  severity: high
  note: "Wire transfer / banking details"

- name: sensitive_attachment_context
  find_any:
    - "see attached password"
    - "attached is the key"
    - "attached config"
    - "attached credentials"
    - "find attached the"
  severity: high
  note: "Sensitive attachment language"
```

- [ ] **Step 2: Create example custom rules file**

`rules/example_rules.yaml`:

```yaml
# =============================================================================
# Example Custom Rules for ost_explorer
# =============================================================================
# Copy this file and modify it for your engagement.
# Load with: ost_explorer scan mailbox.pst --rules my_rules.yaml
#
# Three ways to match:
#   find:     - Simple keyword (case-insensitive). Anyone can use this.
#   find_any: - List of keywords, matches any. Still no regex.
#   pattern:  - Full regex for advanced users.
#
# Severity levels: low, medium, high, critical
# =============================================================================

# Simple keyword match
- name: client project name
  find: "Project Nightfall"
  severity: high
  note: "Client's confidential project codename"

# Match any of these keywords
- name: internal tools
  find_any:
    - "admin portal"
    - "internal dashboard"
    - "staging environment"
  severity: medium
  note: "References to internal tools and environments"

# Regex for structured patterns
- name: employee id
  pattern: "EMP-\\d{6}"
  severity: low
  note: "Employee ID format"
```

- [ ] **Step 3: Write a quick test that default rules load without errors**

Add to `tests/test_rules_loader.py`:

```python
def test_default_rules_load():
    from importlib.resources import files
    rules_path = Path(str(files("ost_explorer.rules").joinpath("default_rules.yaml")))
    rules = load_rules_from_yaml(rules_path)
    assert len(rules) > 50  # We have a comprehensive set
    # All rules should have names and valid severities
    for rule in rules:
        assert rule.name
        assert rule.severity in {"low", "medium", "high", "critical"}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/ai-dev/projects/ost_explorer && source .venv/bin/activate && python -m pytest tests/test_rules_loader.py -v`

Expected: All tests PASS (including default rules validation).

- [ ] **Step 5: Commit**

```bash
git add src/ost_explorer/rules/default_rules.yaml rules/example_rules.yaml tests/test_rules_loader.py
git commit -m "feat: add comprehensive default detection rules and example custom rules"
```

---

## Task 8: Sensitive Data Scanner

**Files:**
- Create: `src/ost_explorer/engine/__init__.py`
- Create: `src/ost_explorer/engine/scanner.py`
- Create: `tests/test_scanner.py`

- [ ] **Step 1: Write failing tests for scanner**

`tests/test_scanner.py`:

```python
from __future__ import annotations

import datetime
from pathlib import Path

import pytest

from ost_explorer.engine.scanner import Scanner
from ost_explorer.models import Attachment, Message, Severity


def _make_message(body: str, subject: str = "Test", sender: str = "a@b.com",
                  attachments: list[Attachment] | None = None) -> Message:
    return Message(
        subject=subject,
        sender=sender,
        recipients_to=["to@b.com"],
        recipients_cc=[],
        recipients_bcc=[],
        date=datetime.datetime(2025, 3, 15),
        body_plain=body,
        body_html="",
        headers={},
        attachments=attachments or [],
        is_read=True,
        is_flagged=False,
    )


def test_scanner_detects_password():
    scanner = Scanner()
    msg = _make_message("Here is the password: Summer2025!")
    findings = scanner.scan_message(msg, folder_path="Inbox")
    matching = [f for f in findings if f.rule_name == "password_plain"]
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
    matching = [f for f in findings if f.rule_name == "password_database_file"]
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
    # Should have zero or very few low-severity findings
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
    matching = [f for f in findings if f.rule_name == "password_plain"]
    assert len(matching) >= 1
    assert "Password: Secret123" in matching[0].context


def test_scanner_severity_filter():
    scanner = Scanner()
    msg = _make_message("password: test123 and phone 555-123-4567")
    all_findings = scanner.scan_message(msg, folder_path="Inbox")
    high_only = scanner.scan_message(msg, folder_path="Inbox", min_severity=Severity.HIGH)
    assert len(high_only) <= len(all_findings)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/ai-dev/projects/ost_explorer && source .venv/bin/activate && python -m pytest tests/test_scanner.py -v`

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement scanner**

`src/ost_explorer/engine/__init__.py`:

```python
```

`src/ost_explorer/engine/scanner.py`:

```python
from __future__ import annotations

import logging
from importlib.resources import files
from pathlib import Path

from ost_explorer.models import Message, ScanFinding, Severity
from ost_explorer.rules.loader import Rule, load_rules_from_yaml

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

_CONTEXT_LINES = 2  # lines before/after match to include


class Scanner:
    def __init__(self, custom_rule_paths: list[Path] | None = None) -> None:
        self._rules: list[Rule] = []
        self._load_default_rules()
        if custom_rule_paths:
            for path in custom_rule_paths:
                self._rules.extend(load_rules_from_yaml(path))
        logger.info("Scanner loaded %d rules", len(self._rules))

    def _load_default_rules(self) -> None:
        default_path = Path(str(files("ost_explorer.rules").joinpath("default_rules.yaml")))
        self._rules.extend(load_rules_from_yaml(default_path))

    def scan_message(
        self,
        message: Message,
        folder_path: str,
        min_severity: Severity = Severity.LOW,
    ) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        # Scan body text
        text = message.body_plain or ""
        findings.extend(self._scan_text(text, message, folder_path, min_severity))

        # Scan subject
        findings.extend(self._scan_text(message.subject, message, folder_path, min_severity))

        # Scan attachment filenames
        for att in message.attachments:
            findings.extend(self._scan_text(att.filename, message, folder_path, min_severity))

        return findings

    def scan_messages(
        self,
        messages: list[Message],
        folder_path: str,
        min_severity: Severity = Severity.LOW,
    ) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        for msg in messages:
            findings.extend(self.scan_message(msg, folder_path, min_severity))
        return findings

    def _scan_text(
        self,
        text: str,
        message: Message,
        folder_path: str,
        min_severity: Severity,
    ) -> list[ScanFinding]:
        if not text:
            return []

        findings: list[ScanFinding] = []
        lines = text.split("\n")

        for rule in self._rules:
            severity = _SEVERITY_MAP.get(rule.severity, Severity.MEDIUM)
            if severity < min_severity:
                continue

            matches = rule.find_all(text)
            for match in matches:
                # Extract context: find which line the match is on
                match_start = match.start()
                char_count = 0
                match_line_idx = 0
                for idx, line in enumerate(lines):
                    char_count += len(line) + 1  # +1 for newline
                    if char_count > match_start:
                        match_line_idx = idx
                        break

                context_start = max(0, match_line_idx - _CONTEXT_LINES)
                context_end = min(len(lines), match_line_idx + _CONTEXT_LINES + 1)
                context = "\n".join(lines[context_start:context_end])

                findings.append(
                    ScanFinding(
                        rule_name=rule.name,
                        severity=severity,
                        matched_text=match.group(),
                        context=context,
                        message_subject=message.subject,
                        message_sender=message.sender,
                        message_date=message.date,
                        folder_path=folder_path,
                    )
                )

        return findings
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/ai-dev/projects/ost_explorer && source .venv/bin/activate && python -m pytest tests/test_scanner.py -v`

Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ost_explorer/engine/ tests/test_scanner.py
git commit -m "feat: add sensitive data scanner with default and custom rule support"
```

---

## Task 9: Search Engine

**Files:**
- Create: `src/ost_explorer/engine/search.py`
- Create: `tests/test_search.py`

- [ ] **Step 1: Write failing tests for search engine**

`tests/test_search.py`:

```python
from __future__ import annotations

import datetime

import pytest

from ost_explorer.engine.search import parse_query, SearchQuery, search_messages
from ost_explorer.models import Attachment, Message


def _make_msg(
    subject: str = "Test",
    sender: str = "alice@corp.com",
    to: list[str] | None = None,
    body: str = "Hello world",
    date: datetime.datetime | None = None,
    attachments: list[Attachment] | None = None,
) -> Message:
    return Message(
        subject=subject,
        sender=sender,
        recipients_to=to or ["bob@corp.com"],
        recipients_cc=[],
        recipients_bcc=[],
        date=date or datetime.datetime(2025, 3, 15),
        body_plain=body,
        body_html="",
        headers={},
        attachments=attachments or [],
        is_read=True,
        is_flagged=False,
    )


def test_parse_simple_query():
    q = parse_query("hello world")
    assert q.text == "hello world"
    assert q.from_filter is None
    assert q.to_filter is None


def test_parse_from_filter():
    q = parse_query("from:alice@corp.com")
    assert q.from_filter == "alice@corp.com"
    assert q.text == ""


def test_parse_to_filter():
    q = parse_query("to:bob")
    assert q.to_filter == "bob"


def test_parse_has_attachment():
    q = parse_query("has:attachment")
    assert q.has_attachment is True


def test_parse_filename_filter():
    q = parse_query("filename:*.xlsx")
    assert q.filename_glob == "*.xlsx"


def test_parse_date_range():
    q = parse_query("date:2025-01..2025-03")
    assert q.date_start == datetime.datetime(2025, 1, 1)
    assert q.date_end == datetime.datetime(2025, 3, 31, 23, 59, 59)


def test_parse_folder_filter():
    q = parse_query("folder:Inbox")
    assert q.folder_filter == "Inbox"


def test_parse_combined_query():
    q = parse_query("from:ceo has:attachment budget")
    assert q.from_filter == "ceo"
    assert q.has_attachment is True
    assert q.text == "budget"


def test_search_text_match():
    messages = [
        _make_msg(body="The VPN password is Summer2025"),
        _make_msg(body="Meeting at 3pm tomorrow"),
    ]
    results = search_messages(messages, parse_query("password"))
    assert len(results) == 1
    assert "password" in results[0].body_plain.lower()


def test_search_from_filter():
    messages = [
        _make_msg(sender="alice@corp.com"),
        _make_msg(sender="bob@corp.com"),
    ]
    results = search_messages(messages, parse_query("from:alice"))
    assert len(results) == 1


def test_search_to_filter():
    messages = [
        _make_msg(to=["admin@corp.com"]),
        _make_msg(to=["user@corp.com"]),
    ]
    results = search_messages(messages, parse_query("to:admin"))
    assert len(results) == 1


def test_search_has_attachment():
    att = Attachment(filename="doc.pdf", size=100, mime_type="application/pdf", _extract_fn=None)
    messages = [
        _make_msg(attachments=[att]),
        _make_msg(attachments=[]),
    ]
    results = search_messages(messages, parse_query("has:attachment"))
    assert len(results) == 1


def test_search_filename_glob():
    att = Attachment(filename="report.xlsx", size=100, mime_type="application/vnd.ms-excel", _extract_fn=None)
    messages = [
        _make_msg(attachments=[att]),
        _make_msg(attachments=[Attachment(filename="notes.txt", size=50, mime_type="text/plain", _extract_fn=None)]),
    ]
    results = search_messages(messages, parse_query("filename:*.xlsx"))
    assert len(results) == 1


def test_search_date_range():
    messages = [
        _make_msg(date=datetime.datetime(2025, 1, 15)),
        _make_msg(date=datetime.datetime(2025, 3, 15)),
        _make_msg(date=datetime.datetime(2025, 6, 15)),
    ]
    results = search_messages(messages, parse_query("date:2025-01..2025-03"))
    assert len(results) == 2


def test_search_combined_filters():
    att = Attachment(filename="creds.xlsx", size=100, mime_type="application/vnd.ms-excel", _extract_fn=None)
    messages = [
        _make_msg(sender="ceo@corp.com", attachments=[att], body="Budget details"),
        _make_msg(sender="ceo@corp.com", body="Lunch plans"),
        _make_msg(sender="intern@corp.com", attachments=[att]),
    ]
    results = search_messages(messages, parse_query("from:ceo has:attachment"))
    assert len(results) == 1


def test_search_subject_match():
    messages = [
        _make_msg(subject="RE: VPN credentials"),
        _make_msg(subject="Weekly standup notes"),
    ]
    results = search_messages(messages, parse_query("VPN"))
    assert len(results) == 1


def test_search_case_insensitive():
    messages = [_make_msg(body="The PASSWORD is here")]
    results = search_messages(messages, parse_query("password"))
    assert len(results) == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/ai-dev/projects/ost_explorer && source .venv/bin/activate && python -m pytest tests/test_search.py -v`

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement search engine**

`src/ost_explorer/engine/search.py`:

```python
from __future__ import annotations

import datetime
import fnmatch
import re
from dataclasses import dataclass, field
from typing import Optional

from ost_explorer.models import Message


@dataclass
class SearchQuery:
    text: str = ""
    from_filter: Optional[str] = None
    to_filter: Optional[str] = None
    has_attachment: bool = False
    filename_glob: Optional[str] = None
    date_start: Optional[datetime.datetime] = None
    date_end: Optional[datetime.datetime] = None
    folder_filter: Optional[str] = None


_FILTER_RE = re.compile(
    r"(from|to|has|filename|date|folder):(\S+)", re.IGNORECASE
)


def parse_query(query_str: str) -> SearchQuery:
    q = SearchQuery()
    remaining_parts: list[str] = []

    pos = 0
    for match in _FILTER_RE.finditer(query_str):
        # Capture text before this filter
        before = query_str[pos : match.start()].strip()
        if before:
            remaining_parts.append(before)
        pos = match.end()

        key = match.group(1).lower()
        value = match.group(2)

        if key == "from":
            q.from_filter = value
        elif key == "to":
            q.to_filter = value
        elif key == "has" and value.lower() == "attachment":
            q.has_attachment = True
        elif key == "filename":
            q.filename_glob = value
        elif key == "date":
            q.date_start, q.date_end = _parse_date_range(value)
        elif key == "folder":
            q.folder_filter = value

    # Capture any remaining text after last filter
    after = query_str[pos:].strip()
    if after:
        remaining_parts.append(after)

    q.text = " ".join(remaining_parts)
    return q


def _parse_date_range(value: str) -> tuple[datetime.datetime, datetime.datetime]:
    parts = value.split("..")
    if len(parts) != 2:
        raise ValueError(f"Invalid date range: {value} (expected YYYY-MM..YYYY-MM)")

    start = _parse_month(parts[0])
    end_month = _parse_month(parts[1])
    # End of the last day of the month
    if end_month.month == 12:
        end = datetime.datetime(end_month.year + 1, 1, 1) - datetime.timedelta(seconds=1)
    else:
        end = datetime.datetime(end_month.year, end_month.month + 1, 1) - datetime.timedelta(seconds=1)
    return start, end


def _parse_month(s: str) -> datetime.datetime:
    parts = s.split("-")
    if len(parts) == 2:
        return datetime.datetime(int(parts[0]), int(parts[1]), 1)
    elif len(parts) == 3:
        return datetime.datetime(int(parts[0]), int(parts[1]), int(parts[2]))
    else:
        raise ValueError(f"Cannot parse date: {s}")


def search_messages(messages: list[Message], query: SearchQuery) -> list[Message]:
    results: list[Message] = []
    for msg in messages:
        if _matches(msg, query):
            results.append(msg)
    return results


def _matches(msg: Message, q: SearchQuery) -> bool:
    # Text search (subject + body)
    if q.text:
        text_lower = q.text.lower()
        searchable = f"{msg.subject} {msg.body_plain} {msg.sender}".lower()
        if text_lower not in searchable:
            return False

    # From filter
    if q.from_filter:
        if q.from_filter.lower() not in msg.sender.lower():
            return False

    # To filter
    if q.to_filter:
        all_to = " ".join(msg.recipients_to + msg.recipients_cc + msg.recipients_bcc).lower()
        if q.to_filter.lower() not in all_to:
            return False

    # Has attachment
    if q.has_attachment:
        if not msg.has_attachments:
            return False

    # Filename glob
    if q.filename_glob:
        matched_any = any(
            fnmatch.fnmatch(att.filename.lower(), q.filename_glob.lower())
            for att in msg.attachments
        )
        if not matched_any:
            return False

    # Date range
    if q.date_start and msg.date < q.date_start:
        return False
    if q.date_end and msg.date > q.date_end:
        return False

    return True
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/ai-dev/projects/ost_explorer && source .venv/bin/activate && python -m pytest tests/test_search.py -v`

Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ost_explorer/engine/search.py tests/test_search.py
git commit -m "feat: add search engine with filter syntax (from, to, date, filename, has:attachment)"
```

---

## Task 10: Export Engine

**Files:**
- Create: `src/ost_explorer/engine/export.py`
- Create: `src/ost_explorer/templates/report.html`
- Create: `tests/test_export.py`

- [ ] **Step 1: Write failing tests for export**

`tests/test_export.py`:

```python
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
        subject=subject,
        sender="alice@corp.com",
        recipients_to=["bob@corp.com"],
        recipients_cc=[],
        recipients_bcc=[],
        date=datetime.datetime(2025, 3, 15, 10, 30),
        body_plain=body,
        body_html="",
        headers={"Message-ID": "<test@corp.com>"},
        attachments=[],
        is_read=True,
        is_flagged=False,
    )


def _make_finding() -> ScanFinding:
    return ScanFinding(
        rule_name="password_plain",
        severity=Severity.CRITICAL,
        matched_text="password: Summer2025!",
        context="Here is the password: Summer2025!",
        message_subject="VPN creds",
        message_sender="jane@corp.com",
        message_date=datetime.datetime(2025, 3, 15),
        folder_path="Inbox",
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
    assert data["findings"][0]["rule_name"] == "password_plain"


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
    assert rows[0]["rule_name"] == "password_plain"


def test_export_html(tmp_path: Path):
    messages = [_make_msg("Email 1", "Body text")]
    findings = [_make_finding()]
    output = tmp_path / "report.html"
    export_html(messages, findings, output, mailbox_name="test.pst")

    html = output.read_text()
    assert "<html" in html
    assert "test.pst" in html
    assert "password_plain" in html
    assert "Email 1" in html


def test_export_json_empty(tmp_path: Path):
    output = tmp_path / "empty.json"
    export_json([], [], output)
    data = json.loads(output.read_text())
    assert data["messages"] == []
    assert data["findings"] == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/ai-dev/projects/ost_explorer && source .venv/bin/activate && python -m pytest tests/test_export.py -v`

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Create HTML report template**

`src/ost_explorer/templates/report.html`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ost_explorer Report — {{ mailbox_name }}</title>
<style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #0a0a0a; color: #e0e0e0; padding: 2rem; }
    h1 { color: #00ff88; margin-bottom: 0.5rem; }
    h2 { color: #00cc6a; margin: 2rem 0 1rem; border-bottom: 1px solid #333; padding-bottom: 0.5rem; }
    h3 { color: #999; margin: 1rem 0 0.5rem; }
    .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin: 1rem 0; }
    .stat { background: #1a1a1a; border: 1px solid #333; border-radius: 8px; padding: 1.5rem; text-align: center; }
    .stat .number { font-size: 2.5rem; font-weight: bold; color: #00ff88; }
    .stat .label { color: #888; margin-top: 0.5rem; }
    table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
    th { background: #1a1a1a; color: #00cc6a; text-align: left; padding: 0.75rem; border-bottom: 2px solid #333; }
    td { padding: 0.75rem; border-bottom: 1px solid #222; }
    tr:hover { background: #111; }
    .severity-critical { color: #ff4444; font-weight: bold; }
    .severity-high { color: #ff8800; font-weight: bold; }
    .severity-medium { color: #ffcc00; }
    .severity-low { color: #888; }
    .context { background: #111; padding: 0.5rem; border-radius: 4px; font-family: monospace; font-size: 0.85rem; white-space: pre-wrap; margin-top: 0.25rem; }
    .meta { color: #666; font-size: 0.85rem; }
    footer { margin-top: 3rem; text-align: center; color: #444; font-size: 0.8rem; }
</style>
</head>
<body>
<h1>ost_explorer Report</h1>
<p class="meta">Mailbox: {{ mailbox_name }} | Generated: {{ generated_at }} | Total Messages: {{ total_messages }}</p>

<h2>Summary</h2>
<div class="summary">
    <div class="stat">
        <div class="number">{{ total_messages }}</div>
        <div class="label">Messages</div>
    </div>
    <div class="stat">
        <div class="number">{{ total_findings }}</div>
        <div class="label">Findings</div>
    </div>
    <div class="stat">
        <div class="number severity-critical">{{ critical_count }}</div>
        <div class="label">Critical</div>
    </div>
    <div class="stat">
        <div class="number severity-high">{{ high_count }}</div>
        <div class="label">High</div>
    </div>
</div>

{% if findings %}
<h2>Findings</h2>
<table>
<thead>
<tr><th>Severity</th><th>Rule</th><th>Match</th><th>Message</th><th>Sender</th><th>Date</th></tr>
</thead>
<tbody>
{% for f in findings %}
<tr>
    <td class="severity-{{ f.severity_name }}">{{ f.severity_name | upper }}</td>
    <td>{{ f.rule_name }}</td>
    <td><code>{{ f.matched_text }}</code></td>
    <td>{{ f.message_subject }}</td>
    <td>{{ f.message_sender }}</td>
    <td>{{ f.message_date }}</td>
</tr>
{% endfor %}
</tbody>
</table>
{% endif %}

{% if messages %}
<h2>Messages</h2>
<table>
<thead>
<tr><th>Date</th><th>From</th><th>To</th><th>Subject</th><th>Attachments</th></tr>
</thead>
<tbody>
{% for m in messages %}
<tr>
    <td>{{ m.date.strftime('%Y-%m-%d %H:%M') }}</td>
    <td>{{ m.sender }}</td>
    <td>{{ m.recipients_to | join(', ') }}</td>
    <td>{{ m.subject }}</td>
    <td>{{ m.attachments | length }}</td>
</tr>
{% endfor %}
</tbody>
</table>
{% endif %}

<footer>Generated by ost_explorer v{{ version }}</footer>
</body>
</html>
```

- [ ] **Step 4: Implement export engine**

`src/ost_explorer/engine/export.py`:

```python
from __future__ import annotations

import csv
import datetime
import json
from importlib.resources import files
from pathlib import Path

from jinja2 import Template

from ost_explorer import __version__
from ost_explorer.models import Message, ScanFinding, Severity

_SEVERITY_NAMES = {
    Severity.LOW: "low",
    Severity.MEDIUM: "medium",
    Severity.HIGH: "high",
    Severity.CRITICAL: "critical",
}


def export_json(
    messages: list[Message],
    findings: list[ScanFinding],
    output_path: Path,
) -> None:
    data = {
        "generated_at": datetime.datetime.now().isoformat(),
        "messages": [_message_to_dict(m) for m in messages],
        "findings": [_finding_to_dict(f) for f in findings],
    }
    output_path.write_text(json.dumps(data, indent=2, default=str))


def export_csv(
    messages: list[Message],
    findings: list[ScanFinding],
    output_path: Path,
) -> None:
    with open(output_path, "w", newline="") as f:
        if messages:
            writer = csv.DictWriter(
                f,
                fieldnames=["date", "sender", "recipients_to", "subject", "has_attachments", "body_preview"],
            )
            writer.writeheader()
            for msg in messages:
                writer.writerow({
                    "date": msg.date.isoformat(),
                    "sender": msg.sender,
                    "recipients_to": "; ".join(msg.recipients_to),
                    "subject": msg.subject,
                    "has_attachments": msg.has_attachments,
                    "body_preview": (msg.body_plain or "")[:200],
                })

        if findings:
            if messages:
                f.write("\n")
            writer = csv.DictWriter(
                f,
                fieldnames=["severity", "rule_name", "matched_text", "message_subject", "message_sender", "message_date", "folder_path"],
            )
            writer.writeheader()
            for finding in findings:
                writer.writerow({
                    "severity": _SEVERITY_NAMES.get(finding.severity, "medium"),
                    "rule_name": finding.rule_name,
                    "matched_text": finding.matched_text,
                    "message_subject": finding.message_subject,
                    "message_sender": finding.message_sender,
                    "message_date": finding.message_date.isoformat(),
                    "folder_path": finding.folder_path,
                })


def export_html(
    messages: list[Message],
    findings: list[ScanFinding],
    output_path: Path,
    mailbox_name: str = "unknown",
) -> None:
    template_path = Path(str(files("ost_explorer.templates").joinpath("report.html")))
    template = Template(template_path.read_text())

    # Add severity_name to findings for template
    enriched_findings = []
    for f in findings:
        enriched_findings.append(type("Finding", (), {
            "severity_name": _SEVERITY_NAMES.get(f.severity, "medium"),
            "rule_name": f.rule_name,
            "matched_text": f.matched_text,
            "context": f.context,
            "message_subject": f.message_subject,
            "message_sender": f.message_sender,
            "message_date": f.message_date.strftime("%Y-%m-%d"),
        })())

    html = template.render(
        mailbox_name=mailbox_name,
        generated_at=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total_messages=len(messages),
        total_findings=len(findings),
        critical_count=sum(1 for f in findings if f.severity == Severity.CRITICAL),
        high_count=sum(1 for f in findings if f.severity == Severity.HIGH),
        findings=enriched_findings,
        messages=messages,
        version=__version__,
    )
    output_path.write_text(html)


def export_attachments(
    messages: list[Message],
    output_dir: Path,
    folder_name: str = "attachments",
) -> int:
    count = 0
    for msg in messages:
        for att in msg.attachments:
            # Create folder structure: output_dir/folder/subject_date/filename
            safe_subject = "".join(c if c.isalnum() or c in " -_" else "_" for c in msg.subject)[:50]
            msg_dir = output_dir / folder_name / f"{safe_subject}_{msg.date.strftime('%Y%m%d')}"
            msg_dir.mkdir(parents=True, exist_ok=True)
            att_path = msg_dir / att.filename
            att_path.write_bytes(att.extract_bytes())
            count += 1
    return count


def _message_to_dict(msg: Message) -> dict:
    return {
        "subject": msg.subject,
        "sender": msg.sender,
        "recipients_to": msg.recipients_to,
        "recipients_cc": msg.recipients_cc,
        "recipients_bcc": msg.recipients_bcc,
        "date": msg.date.isoformat(),
        "body_plain": msg.body_plain,
        "has_attachments": msg.has_attachments,
        "attachment_names": [a.filename for a in msg.attachments],
        "is_read": msg.is_read,
        "is_flagged": msg.is_flagged,
    }


def _finding_to_dict(f: ScanFinding) -> dict:
    return {
        "rule_name": f.rule_name,
        "severity": _SEVERITY_NAMES.get(f.severity, "medium"),
        "matched_text": f.matched_text,
        "context": f.context,
        "message_subject": f.message_subject,
        "message_sender": f.message_sender,
        "message_date": f.message_date.isoformat(),
        "folder_path": f.folder_path,
    }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /home/ai-dev/projects/ost_explorer && source .venv/bin/activate && python -m pytest tests/test_export.py -v`

Expected: All tests PASS.

- [ ] **Step 6: Commit**

```bash
git add src/ost_explorer/engine/export.py src/ost_explorer/templates/ tests/test_export.py
git commit -m "feat: add export engine (JSON, CSV, HTML report) with Jinja2 template"
```

---

## Task 11: CLI Interface

**Files:**
- Create: `src/ost_explorer/cli.py`
- Create: `tests/test_cli.py`

- [ ] **Step 1: Write failing tests for CLI**

`tests/test_cli.py`:

```python
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

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
    assert "scan" in result.output.lower() or "file" in result.output.lower()


def test_cli_export_command_exists(runner: CliRunner):
    result = runner.invoke(cli, ["export", "--help"])
    assert result.exit_code == 0


def test_cli_browse_command_exists(runner: CliRunner):
    result = runner.invoke(cli, ["browse", "--help"])
    assert result.exit_code == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/ai-dev/projects/ost_explorer && source .venv/bin/activate && python -m pytest tests/test_cli.py -v`

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement CLI**

`src/ost_explorer/cli.py`:

```python
from __future__ import annotations

import logging
import sys
from pathlib import Path

import click

from ost_explorer import __version__


@click.group()
@click.version_option(__version__, prog_name="ost_explorer")
@click.option("--quiet", "-q", is_flag=True, help="Suppress banner and progress output")
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging")
@click.pass_context
def cli(ctx: click.Context, quiet: bool, verbose: bool) -> None:
    """ost_explorer — PST/OST email archive triage tool for penetration testing."""
    ctx.ensure_object(dict)
    ctx.obj["quiet"] = quiet

    level = logging.DEBUG if verbose else (logging.WARNING if quiet else logging.INFO)
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")

    if not quiet:
        click.echo(f"ost_explorer v{__version__}")


@cli.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.pass_context
def info(ctx: click.Context, file: Path) -> None:
    """Show summary information about a PST/OST file."""
    from ost_explorer.parser import open_mailbox
    from ost_explorer.parser.detect import detect_format

    fmt = detect_format(file)
    click.echo(f"File:     {file}")
    click.echo(f"Format:   {fmt}")
    click.echo(f"Size:     {file.stat().st_size:,} bytes")

    try:
        mailbox, parser = open_mailbox(file)
        click.echo(f"Folders:  {len(mailbox.folders)}")
        click.echo(f"Messages: {mailbox.total_messages}")

        def _print_tree(folders, indent=0):
            for f in folders:
                click.echo(f"{'  ' * indent}  {f.name} ({f.message_count})")
                _print_tree(f.children, indent + 1)

        click.echo("Folder tree:")
        _print_tree(mailbox.folders)
        parser.close()
    except Exception as e:
        click.echo(f"Warning: Could not fully parse file: {e}", err=True)


@cli.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.option("--rules", "-r", multiple=True, type=click.Path(exists=True, path_type=Path), help="Custom rule YAML files")
@click.option("--output", "-o", type=click.Path(path_type=Path), help="Output file path")
@click.option("--format", "-f", "fmt", type=click.Choice(["json", "csv", "text"]), default="text", help="Output format")
@click.option("--severity", type=click.Choice(["low", "medium", "high", "critical"]), default="low", help="Minimum severity")
@click.option("--folder", type=str, default=None, help="Scope to specific folder")
@click.option("--include-deleted/--no-deleted", default=True, help="Include recovered/deleted items")
@click.option("--no-cache", is_flag=True, help="Skip SQLite cache")
@click.pass_context
def scan(
    ctx: click.Context,
    file: Path,
    rules: tuple[Path, ...],
    output: Path | None,
    fmt: str,
    severity: str,
    folder: str | None,
    include_deleted: bool,
    no_cache: bool,
) -> None:
    """Scan a PST/OST file for credentials, secrets, and sensitive data."""
    from ost_explorer.engine.scanner import Scanner
    from ost_explorer.engine.export import export_json, export_csv
    from ost_explorer.models import Severity
    from ost_explorer.parser import open_mailbox

    severity_map = {"low": Severity.LOW, "medium": Severity.MEDIUM, "high": Severity.HIGH, "critical": Severity.CRITICAL}
    min_severity = severity_map[severity]

    scanner = Scanner(custom_rule_paths=list(rules) if rules else None)
    mailbox, parser = open_mailbox(file)

    all_findings = []

    def _scan_folders(folders):
        for f in folders:
            if folder and f.name.lower() != folder.lower():
                _scan_folders(f.children)
                continue
            if not ctx.obj.get("quiet"):
                click.echo(f"Scanning: {f.name} ({f.message_count} messages)")
            offset = 0
            while True:
                messages = parser.get_messages(f, offset=offset, limit=50)
                if not messages:
                    break
                findings = scanner.scan_messages(messages, folder_path=f.name, min_severity=min_severity)
                all_findings.extend(findings)
                offset += 50
            _scan_folders(f.children)

    _scan_folders(mailbox.folders)

    if include_deleted:
        if not ctx.obj.get("quiet"):
            click.echo("Scanning recovered/deleted items...")
        recovered = parser.get_recovered_messages()
        if recovered:
            findings = scanner.scan_messages(recovered, folder_path="Recovered", min_severity=min_severity)
            all_findings.extend(findings)

    parser.close()

    # Output results
    if output and fmt == "json":
        export_json([], all_findings, output)
        click.echo(f"Findings exported to {output}")
    elif output and fmt == "csv":
        export_csv([], all_findings, output)
        click.echo(f"Findings exported to {output}")
    else:
        for f in all_findings:
            sev = f.severity.name
            click.echo(f"[{sev}] {f.rule_name}: {f.matched_text}")
            click.echo(f"  Message: {f.message_subject} (from: {f.message_sender}, {f.message_date})")
            click.echo(f"  Folder:  {f.folder_path}")
            click.echo()

    click.echo(f"\nTotal findings: {len(all_findings)}")
    sys.exit(1 if all_findings else 0)


@cli.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.option("--format", "-f", "fmt", type=click.Choice(["json", "csv", "html"]), required=True, help="Export format")
@click.option("--output", "-o", type=click.Path(path_type=Path), required=True, help="Output file path")
@click.option("--output-dir", type=click.Path(path_type=Path), help="Output directory for attachments")
@click.option("--attachments", is_flag=True, help="Extract attachments")
@click.option("--folder", type=str, default=None, help="Scope to specific folder")
@click.pass_context
def export(
    ctx: click.Context,
    file: Path,
    fmt: str,
    output: Path,
    output_dir: Path | None,
    attachments: bool,
    folder: str | None,
) -> None:
    """Export messages, findings, and attachments from a PST/OST file."""
    from ost_explorer.engine.export import export_json, export_csv, export_html, export_attachments
    from ost_explorer.engine.scanner import Scanner
    from ost_explorer.parser import open_mailbox

    mailbox, parser = open_mailbox(file)
    scanner = Scanner()

    all_messages = []
    all_findings = []

    def _collect(folders):
        for f in folders:
            if folder and f.name.lower() != folder.lower():
                _collect(f.children)
                continue
            offset = 0
            while True:
                messages = parser.get_messages(f, offset=offset, limit=50)
                if not messages:
                    break
                all_messages.extend(messages)
                all_findings.extend(scanner.scan_messages(messages, folder_path=f.name))
                offset += 50
            _collect(f.children)

    _collect(mailbox.folders)
    parser.close()

    if fmt == "json":
        export_json(all_messages, all_findings, output)
    elif fmt == "csv":
        export_csv(all_messages, all_findings, output)
    elif fmt == "html":
        export_html(all_messages, all_findings, output, mailbox_name=file.name)

    click.echo(f"Exported {len(all_messages)} messages and {len(all_findings)} findings to {output}")

    if attachments and output_dir:
        count = export_attachments(all_messages, output_dir)
        click.echo(f"Extracted {count} attachments to {output_dir}")


@cli.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.pass_context
def browse(ctx: click.Context, file: Path) -> None:
    """Open interactive TUI browser for a PST/OST file."""
    from ost_explorer.tui.app import OstExplorerApp

    app = OstExplorerApp(file)
    app.run()


@cli.command()
@click.argument("rules_file", type=click.Path(exists=True, path_type=Path))
def validate(rules_file: Path) -> None:
    """Validate a custom rules YAML file."""
    from ost_explorer.rules.loader import load_rules_from_yaml, RuleValidationError

    try:
        rules = load_rules_from_yaml(rules_file)
        click.echo(f"Valid: {len(rules)} rule(s) loaded successfully from {rules_file}")
    except RuleValidationError as e:
        click.echo(f"Validation error: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    cli()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/ai-dev/projects/ost_explorer && source .venv/bin/activate && python -m pytest tests/test_cli.py -v`

Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ost_explorer/cli.py tests/test_cli.py
git commit -m "feat: add CLI interface (browse, scan, export, info, validate commands)"
```

---

## Task 12: TUI — Main App Shell and Folder Tree

**Files:**
- Create: `src/ost_explorer/tui/__init__.py`
- Create: `src/ost_explorer/tui/app.py`
- Create: `src/ost_explorer/tui/folder_tree.py`

- [ ] **Step 1: Create TUI package init**

`src/ost_explorer/tui/__init__.py`:

```python
```

- [ ] **Step 2: Implement folder tree widget**

`src/ost_explorer/tui/folder_tree.py`:

```python
from __future__ import annotations

from textual.widgets import Tree
from textual.widgets._tree import TreeNode

from ost_explorer.models import Folder


class FolderTree(Tree):
    """Folder navigation tree pane."""

    def __init__(self, **kwargs) -> None:
        super().__init__("Mailbox", **kwargs)
        self.guide_depth = 3

    def load_folders(self, folders: list[Folder], recovered_count: int = 0) -> None:
        self.clear()
        self.root.expand()
        for folder in folders:
            self._add_folder(self.root, folder)
        if recovered_count > 0:
            node = self.root.add(f"Recovered ({recovered_count})")
            node.data = "__recovered__"
        self.root.expand()

    def _add_folder(self, parent: TreeNode, folder: Folder) -> None:
        label = f"{folder.name} ({folder.message_count})"
        node = parent.add(label)
        node.data = folder
        for child in folder.children:
            self._add_folder(node, child)
```

- [ ] **Step 3: Implement main TUI app**

`src/ost_explorer/tui/app.py`:

```python
from __future__ import annotations

import logging
from pathlib import Path

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Footer, Header, RichLog, Static, Input
from textual.widgets._tree import TreeNode

from ost_explorer.models import Folder, Message, Severity
from ost_explorer.parser import open_mailbox
from ost_explorer.parser.base import MailboxParser
from ost_explorer.tui.folder_tree import FolderTree

logger = logging.getLogger(__name__)


class OstExplorerApp(App):
    """Interactive PST/OST browser TUI."""

    CSS = """
    #main {
        height: 1fr;
    }
    #folder-pane {
        width: 25;
        border-right: solid $primary;
    }
    #message-pane {
        width: 1fr;
    }
    #message-list {
        height: 40%;
        border-bottom: solid $primary;
    }
    #message-view {
        height: 60%;
        padding: 1;
    }
    #search-bar {
        dock: top;
        display: none;
        padding: 0 1;
    }
    #search-bar.visible {
        display: block;
    }
    #status-bar {
        dock: bottom;
        height: 1;
        background: $primary-background;
        color: $text;
        padding: 0 1;
    }
    """

    BINDINGS = [
        Binding("slash", "toggle_search", "Search", show=True),
        Binding("s", "run_scan", "Scan", show=True),
        Binding("e", "show_export", "Export", show=True),
        Binding("a", "extract_attachment", "Save Attachment", show=True),
        Binding("shift+a", "extract_all_attachments", "Save All Attachments"),
        Binding("f", "flag_message", "Flag", show=True),
        Binding("t", "toggle_html", "Toggle HTML", show=True),
        Binding("n", "next_message", "Next"),
        Binding("p", "prev_message", "Prev"),
        Binding("f1", "focus_folders", "Folders"),
        Binding("f2", "focus_messages", "Messages"),
        Binding("f3", "focus_viewer", "Viewer"),
        Binding("question_mark", "show_help", "Help", show=True),
        Binding("q", "quit", "Quit", show=True),
    ]

    def __init__(self, file_path: Path, **kwargs) -> None:
        super().__init__(**kwargs)
        self._file_path = file_path
        self._parser: MailboxParser | None = None
        self._current_folder: Folder | None = None
        self._current_messages: list[Message] = []
        self._current_message: Message | None = None
        self._show_html = False
        self._recovered_messages: list[Message] = []

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="main"):
            yield FolderTree(id="folder-pane")
            with Vertical(id="message-pane"):
                yield DataTable(id="message-list")
                yield RichLog(id="message-view", wrap=True, markup=True)
        yield Input(placeholder="Search: type query and press Enter (e.g. from:ceo has:attachment)", id="search-bar")
        yield Static("", id="status-bar")
        yield Footer()

    def on_mount(self) -> None:
        self.title = f"ost_explorer — {self._file_path.name}"

        # Set up message list table
        table = self.query_one("#message-list", DataTable)
        table.add_columns("*", "From", "Subject", "Date", "Att")
        table.cursor_type = "row"

        # Open mailbox
        try:
            mailbox, self._parser = open_mailbox(self._file_path)

            # Load folder tree
            tree = self.query_one("#folder-pane", FolderTree)
            recovered = self._parser.get_recovered_messages()
            self._recovered_messages = recovered
            tree.load_folders(mailbox.folders, recovered_count=len(recovered))

            # Update status
            self._update_status(
                f"{self._file_path.name} | {mailbox.format_type} | "
                f"{mailbox.total_messages} messages"
            )
        except Exception as e:
            self._update_status(f"Error: {e}")

    def on_tree_node_selected(self, event: FolderTree.NodeSelected) -> None:
        node = event.node
        if node.data is None:
            return

        if node.data == "__recovered__":
            self._current_folder = None
            self._current_messages = self._recovered_messages
            self._populate_message_list(self._current_messages)
            self._update_status(f"Recovered items | {len(self._recovered_messages)} messages")
            return

        if isinstance(node.data, Folder) and self._parser:
            folder = node.data
            self._current_folder = folder
            messages = self._parser.get_messages(folder, offset=0, limit=50)
            self._current_messages = messages
            self._populate_message_list(messages)
            self._update_status(
                f"{self._file_path.name} | {folder.name} | {folder.message_count} messages"
            )

    def _populate_message_list(self, messages: list[Message]) -> None:
        table = self.query_one("#message-list", DataTable)
        table.clear()
        for msg in messages:
            flag = "*" if msg.is_flagged else " "
            date_str = msg.date.strftime("%Y-%m-%d") if msg.date else ""
            att_str = str(len(msg.attachments)) if msg.attachments else ""
            sender = (msg.sender or "")[:25]
            subject = (msg.subject or "")[:40]
            table.add_row(flag, sender, subject, date_str, att_str)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        idx = event.cursor_row
        if 0 <= idx < len(self._current_messages):
            self._current_message = self._current_messages[idx]
            self._display_message(self._current_message)

    def _display_message(self, msg: Message) -> None:
        viewer = self.query_one("#message-view", RichLog)
        viewer.clear()

        # Headers
        viewer.write(f"[bold]From:[/bold] {msg.sender}")
        viewer.write(f"[bold]To:[/bold] {', '.join(msg.recipients_to)}")
        if msg.recipients_cc:
            viewer.write(f"[bold]Cc:[/bold] {', '.join(msg.recipients_cc)}")
        viewer.write(f"[bold]Subject:[/bold] {msg.subject}")
        viewer.write(f"[bold]Date:[/bold] {msg.date}")

        if msg.attachments:
            att_names = [f"[{a.filename}]" for a in msg.attachments]
            viewer.write(f"[bold]Attachments:[/bold] {' '.join(att_names)}")

        viewer.write("─" * 60)

        # Body
        if self._show_html and msg.body_html:
            viewer.write(msg.body_html)
        else:
            body = msg.body_plain or msg.body_html or "(no body)"
            # Highlight scan findings inline
            viewer.write(self._highlight_findings(body))

    def _highlight_findings(self, text: str) -> str:
        from ost_explorer.engine.scanner import Scanner
        if not self._current_message:
            return text
        scanner = Scanner()
        findings = scanner.scan_message(self._current_message, folder_path=self._current_folder.name if self._current_folder else "")
        # Mark matched text with rich markup
        for finding in sorted(findings, key=lambda f: len(f.matched_text), reverse=True):
            if finding.matched_text in text:
                color = {
                    Severity.CRITICAL: "red",
                    Severity.HIGH: "yellow",
                    Severity.MEDIUM: "cyan",
                    Severity.LOW: "dim",
                }.get(finding.severity, "white")
                text = text.replace(
                    finding.matched_text,
                    f"[bold {color}]{finding.matched_text}[/bold {color}]",
                    1,
                )
        return text

    def _update_status(self, text: str) -> None:
        status = self.query_one("#status-bar", Static)
        status.update(text)

    # --- Actions ---

    def action_toggle_search(self) -> None:
        search = self.query_one("#search-bar", Input)
        if search.has_class("visible"):
            search.remove_class("visible")
        else:
            search.add_class("visible")
            search.focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "search-bar":
            query_str = event.value
            event.input.remove_class("visible")

            if not query_str.strip():
                return

            from ost_explorer.engine.search import parse_query, search_messages

            query = parse_query(query_str)

            # Search across all loaded messages — for now search current folder
            # TODO: search across all folders by loading them
            results = search_messages(self._current_messages, query)
            self._current_messages = results
            self._populate_message_list(results)
            self._update_status(f"Search: '{query_str}' | {len(results)} results")

    def action_run_scan(self) -> None:
        if not self._current_messages:
            return
        from ost_explorer.engine.scanner import Scanner
        scanner = Scanner()
        folder_name = self._current_folder.name if self._current_folder else "Recovered"
        findings = scanner.scan_messages(self._current_messages, folder_path=folder_name)

        viewer = self.query_one("#message-view", RichLog)
        viewer.clear()
        viewer.write(f"[bold]Scan Results — {len(findings)} findings[/bold]\n")
        for f in findings:
            color = {"critical": "red", "high": "yellow", "medium": "cyan", "low": "dim"}.get(
                f.severity.name.lower(), "white"
            )
            viewer.write(
                f"[{color}][{f.severity.name}][/{color}] {f.rule_name}: {f.matched_text}\n"
                f"  Message: {f.message_subject} ({f.message_sender})\n"
            )

    def action_show_export(self) -> None:
        from ost_explorer.tui.export_dialog import ExportDialog
        self.push_screen(ExportDialog(self._current_messages, self._file_path))

    def action_extract_attachment(self) -> None:
        if not self._current_message or not self._current_message.attachments:
            return
        att = self._current_message.attachments[0]
        out_path = Path.cwd() / att.filename
        out_path.write_bytes(att.extract_bytes())
        self._update_status(f"Saved: {out_path}")

    def action_extract_all_attachments(self) -> None:
        if not self._current_message:
            return
        count = 0
        for att in self._current_message.attachments:
            out_path = Path.cwd() / att.filename
            out_path.write_bytes(att.extract_bytes())
            count += 1
        self._update_status(f"Saved {count} attachments to {Path.cwd()}")

    def action_flag_message(self) -> None:
        if self._current_message:
            self._current_message.is_flagged = not self._current_message.is_flagged
            self._populate_message_list(self._current_messages)

    def action_toggle_html(self) -> None:
        self._show_html = not self._show_html
        if self._current_message:
            self._display_message(self._current_message)

    def action_next_message(self) -> None:
        if not self._current_messages or not self._current_message:
            return
        try:
            idx = self._current_messages.index(self._current_message)
            if idx + 1 < len(self._current_messages):
                self._current_message = self._current_messages[idx + 1]
                self._display_message(self._current_message)
                table = self.query_one("#message-list", DataTable)
                table.move_cursor(row=idx + 1)
        except ValueError:
            pass

    def action_prev_message(self) -> None:
        if not self._current_messages or not self._current_message:
            return
        try:
            idx = self._current_messages.index(self._current_message)
            if idx > 0:
                self._current_message = self._current_messages[idx - 1]
                self._display_message(self._current_message)
                table = self.query_one("#message-list", DataTable)
                table.move_cursor(row=idx - 1)
        except ValueError:
            pass

    def action_focus_folders(self) -> None:
        self.query_one("#folder-pane").focus()

    def action_focus_messages(self) -> None:
        self.query_one("#message-list").focus()

    def action_focus_viewer(self) -> None:
        self.query_one("#message-view").focus()

    def action_show_help(self) -> None:
        viewer = self.query_one("#message-view", RichLog)
        viewer.clear()
        viewer.write("[bold]Keybindings[/bold]\n")
        viewer.write("F1/F2/F3  — Focus folder tree / message list / viewer")
        viewer.write("/         — Search (filter syntax: from: to: has:attachment filename: date: folder:)")
        viewer.write("s         — Run scanner on current folder")
        viewer.write("e         — Export dialog")
        viewer.write("a         — Extract selected attachment")
        viewer.write("A         — Extract all attachments from current message")
        viewer.write("f         — Flag/unflag message")
        viewer.write("t         — Toggle HTML/plain text view")
        viewer.write("n/p       — Next/previous message")
        viewer.write("?         — This help")
        viewer.write("q         — Quit")

    def on_unmount(self) -> None:
        if self._parser:
            self._parser.close()
```

- [ ] **Step 4: Commit**

```bash
git add src/ost_explorer/tui/
git commit -m "feat: add Textual TUI with folder tree, message list, viewer, and keybindings"
```

---

## Task 13: TUI — Export Dialog and Search Bar

**Files:**
- Create: `src/ost_explorer/tui/export_dialog.py`
- Create: `src/ost_explorer/tui/search_bar.py`

- [ ] **Step 1: Implement export dialog**

`src/ost_explorer/tui/export_dialog.py`:

```python
from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, RadioButton, RadioSet

from ost_explorer.models import Message


class ExportDialog(ModalScreen):
    """Modal dialog for export options."""

    CSS = """
    ExportDialog {
        align: center middle;
    }
    #export-container {
        width: 60;
        height: auto;
        max-height: 80%;
        border: solid $primary;
        background: $surface;
        padding: 1 2;
    }
    #export-container Label {
        margin: 1 0 0 0;
    }
    #export-path {
        margin: 1 0;
    }
    #export-buttons {
        margin-top: 1;
        height: 3;
    }
    """

    def __init__(self, messages: list[Message], file_path: Path, **kwargs) -> None:
        super().__init__(**kwargs)
        self._messages = messages
        self._file_path = file_path

    def compose(self) -> ComposeResult:
        with Vertical(id="export-container"):
            yield Label("Export Format:")
            with RadioSet(id="format-select"):
                yield RadioButton("JSON", value=True)
                yield RadioButton("CSV")
                yield RadioButton("HTML Report")
            yield Label("Output path:")
            yield Input(
                value=str(Path.cwd() / f"{self._file_path.stem}_export"),
                id="export-path",
            )
            yield Button("Export", variant="primary", id="export-btn")
            yield Button("Cancel", id="cancel-btn")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel-btn":
            self.dismiss()
            return

        if event.button.id == "export-btn":
            radio_set = self.query_one("#format-select", RadioSet)
            path_input = self.query_one("#export-path", Input)
            output_base = Path(path_input.value)

            idx = radio_set.pressed_index
            formats = {0: "json", 1: "csv", 2: "html"}
            fmt = formats.get(idx, "json")

            output_path = output_base.with_suffix(f".{fmt}")

            from ost_explorer.engine.export import export_json, export_csv, export_html
            from ost_explorer.engine.scanner import Scanner

            scanner = Scanner()
            findings = scanner.scan_messages(self._messages, folder_path="export")

            if fmt == "json":
                export_json(self._messages, findings, output_path)
            elif fmt == "csv":
                export_csv(self._messages, findings, output_path)
            elif fmt == "html":
                export_html(self._messages, findings, output_path, mailbox_name=self._file_path.name)

            self.dismiss()
            self.app.query_one("#status-bar").update(f"Exported to {output_path}")
```

- [ ] **Step 2: Create search_bar.py (thin wrapper)**

`src/ost_explorer/tui/search_bar.py`:

```python
from __future__ import annotations

from textual.widgets import Input


class SearchBar(Input):
    """Search input with filter syntax support."""

    def __init__(self, **kwargs) -> None:
        super().__init__(
            placeholder="Search: from:user has:attachment keyword date:2025-01..2025-03",
            **kwargs,
        )
```

- [ ] **Step 3: Create templates __init__.py**

`src/ost_explorer/templates/__init__.py`:

```python
```

- [ ] **Step 4: Commit**

```bash
git add src/ost_explorer/tui/export_dialog.py src/ost_explorer/tui/search_bar.py src/ost_explorer/templates/__init__.py
git commit -m "feat: add TUI export dialog and search bar widgets"
```

---

## Task 14: Integration Test and Final Wiring

**Files:**
- Modify: `src/ost_explorer/parser/__init__.py`
- Create: `tests/test_integration.py`

- [ ] **Step 1: Write integration test using mock data**

`tests/test_integration.py`:

```python
from __future__ import annotations

import datetime
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ost_explorer.models import Attachment, Folder, Mailbox, Message


def _build_mock_mailbox(tmp_path: Path):
    """Build a fake mailbox with messages containing detectable secrets."""
    messages = [
        Message(
            subject="RE: VPN credentials",
            sender="jane@corp.com",
            recipients_to=["user@corp.com"],
            recipients_cc=[],
            recipients_bcc=[],
            date=datetime.datetime(2025, 3, 15, 10, 30),
            body_plain="Hey, here are the creds:\nUsername: jdoe\nPassword: Summer2025!\n",
            body_html="",
            headers={},
            attachments=[
                Attachment(
                    filename="vpn_config.ovpn",
                    size=512,
                    mime_type="application/x-openvpn-profile",
                    _extract_fn=lambda: b"client\nremote vpn.corp.com 1194\nauth-user-pass",
                )
            ],
            is_read=True,
            is_flagged=False,
        ),
        Message(
            subject="AWS Keys for staging",
            sender="devops@corp.com",
            recipients_to=["dev@corp.com"],
            recipients_cc=[],
            recipients_bcc=[],
            date=datetime.datetime(2025, 3, 10, 14, 0),
            body_plain="Here are the staging keys:\nAKIAIOSFODNN7EXAMPLE\nwJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            body_html="",
            headers={},
            attachments=[],
            is_read=True,
            is_flagged=False,
        ),
        Message(
            subject="Lunch plans",
            sender="bob@corp.com",
            recipients_to=["alice@corp.com"],
            recipients_cc=[],
            recipients_bcc=[],
            date=datetime.datetime(2025, 3, 12),
            body_plain="Hey, want to grab sushi at noon?",
            body_html="",
            headers={},
            attachments=[],
            is_read=True,
            is_flagged=False,
        ),
    ]
    folder = Folder(name="Inbox", message_count=3, children=[], _folder_id="f1")
    mailbox = Mailbox(
        path=tmp_path / "test.pst",
        format_type="PST",
        folders=[folder],
        total_messages=3,
    )
    return mailbox, folder, messages


def test_full_scan_pipeline(tmp_path: Path):
    """Test: open mailbox -> scan -> detect secrets -> export."""
    mailbox, folder, messages = _build_mock_mailbox(tmp_path)

    # Scan
    from ost_explorer.engine.scanner import Scanner
    scanner = Scanner()
    findings = scanner.scan_messages(messages, folder_path="Inbox")

    # Should detect password and AWS key
    rule_names = {f.rule_name for f in findings}
    assert "password_plain" in rule_names
    assert "aws_access_key" in rule_names

    # Lunch email should produce no high-severity findings
    lunch_findings = scanner.scan_message(messages[2], folder_path="Inbox")
    high_lunch = [f for f in lunch_findings if f.severity.value >= 3]
    assert len(high_lunch) == 0


def test_full_export_pipeline(tmp_path: Path):
    """Test: scan -> export JSON -> verify structure."""
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
    """Test: search for specific messages -> scan results."""
    _, _, messages = _build_mock_mailbox(tmp_path)

    from ost_explorer.engine.search import parse_query, search_messages
    from ost_explorer.engine.scanner import Scanner

    # Search for VPN-related messages
    results = search_messages(messages, parse_query("VPN"))
    assert len(results) == 1
    assert results[0].subject == "RE: VPN credentials"

    # Scan the search results
    scanner = Scanner()
    findings = scanner.scan_messages(results, folder_path="Inbox")
    assert any(f.rule_name == "password_plain" for f in findings)


def test_html_export(tmp_path: Path):
    """Test: full HTML report generation."""
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
    """Test: extract attachment bytes."""
    _, _, messages = _build_mock_mailbox(tmp_path)

    vpn_msg = messages[0]
    assert len(vpn_msg.attachments) == 1
    att = vpn_msg.attachments[0]
    data = att.extract_bytes()
    assert b"vpn.corp.com" in data
```

- [ ] **Step 2: Run all tests**

Run: `cd /home/ai-dev/projects/ost_explorer && source .venv/bin/activate && python -m pytest -v`

Expected: All tests PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/test_integration.py
git commit -m "feat: add integration tests covering scan-search-export pipeline"
```

---

## Task 15: README and Final Polish

**Files:**
- Create: `README.md`

- [ ] **Step 1: Create README**

`README.md`:

```markdown
# ost_explorer

PST/OST email archive triage tool for penetration testing. Browse mailboxes in an Outlook-like terminal interface, automatically detect credentials and secrets, and export findings for reports.

## Install

```bash
# Install libpff (required for full PST/OST parsing)
sudo apt install libpff-dev

# Install ost_explorer
pip install -e ".[dev]"
```

## Usage

### Interactive browsing
```bash
ost_explorer browse mailbox.pst
```

### Scan for secrets
```bash
ost_explorer scan mailbox.pst
ost_explorer scan mailbox.pst --rules custom_rules.yaml --severity high
ost_explorer scan mailbox.pst --output findings.json --format json
```

### Export data
```bash
ost_explorer export mailbox.pst --format html --output report.html
ost_explorer export mailbox.pst --format json --output dump.json
ost_explorer export mailbox.pst --format csv --output data.csv
ost_explorer export mailbox.pst --attachments --output-dir ./attachments/
```

### File info
```bash
ost_explorer info mailbox.pst
```

### Validate custom rules
```bash
ost_explorer validate my_rules.yaml
```

## Custom Rules

Create YAML files with simple keyword or regex patterns:

```yaml
# Simple keyword — anyone can write these
- name: project codename
  find: "Project Nightfall"
  severity: high
  note: "Client M&A codename"

# Multiple keywords
- name: internal tools
  find_any:
    - "admin portal"
    - "staging server"
  severity: medium

# Regex for advanced patterns
- name: employee id
  pattern: "EMP-\\d{6}"
  severity: low
```

## TUI Keybindings

| Key | Action |
|-----|--------|
| `/` | Search |
| `s` | Scan current folder |
| `e` | Export dialog |
| `a` | Save attachment |
| `A` | Save all attachments |
| `f` | Flag message |
| `t` | Toggle HTML/plain text |
| `n/p` | Next/previous message |
| `F1/F2/F3` | Focus folders/messages/viewer |
| `?` | Help |
| `q` | Quit |
```

- [ ] **Step 2: Run full test suite one final time**

Run: `cd /home/ai-dev/projects/ost_explorer && source .venv/bin/activate && python -m pytest -v`

Expected: All tests PASS.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: add README with install, usage, and custom rules documentation"
```
