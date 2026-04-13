from __future__ import annotations
import datetime
import fnmatch
import re
from dataclasses import dataclass
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

_FILTER_RE = re.compile(r"(from|to|has|filename|date|folder):(\S+)", re.IGNORECASE)

def parse_query(query_str: str) -> SearchQuery:
    q = SearchQuery()
    remaining_parts: list[str] = []
    pos = 0
    for match in _FILTER_RE.finditer(query_str):
        before = query_str[pos:match.start()].strip()
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
    after = query_str[pos:].strip()
    if after:
        remaining_parts.append(after)
    q.text = " ".join(remaining_parts)
    return q

def _parse_date_range(value: str) -> tuple[datetime.datetime, datetime.datetime]:
    parts = value.split("..")
    if len(parts) != 2:
        raise ValueError(f"Invalid date range: {value}")
    start = _parse_month(parts[0])
    end_month = _parse_month(parts[1])
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
    raise ValueError(f"Cannot parse date: {s}")

def search_messages(messages: list[Message], query: SearchQuery) -> list[Message]:
    return [msg for msg in messages if _matches(msg, query)]

def _matches(msg: Message, q: SearchQuery) -> bool:
    if q.text:
        searchable = f"{msg.subject} {msg.body_plain} {msg.sender}".lower()
        if q.text.lower() not in searchable:
            return False
    if q.from_filter and q.from_filter.lower() not in msg.sender.lower():
        return False
    if q.to_filter:
        all_to = " ".join(msg.recipients_to + msg.recipients_cc + msg.recipients_bcc).lower()
        if q.to_filter.lower() not in all_to:
            return False
    if q.has_attachment and not msg.has_attachments:
        return False
    if q.filename_glob:
        if not any(fnmatch.fnmatch(a.filename.lower(), q.filename_glob.lower()) for a in msg.attachments):
            return False
    if q.date_start and msg.date < q.date_start:
        return False
    if q.date_end and msg.date > q.date_end:
        return False
    return True
