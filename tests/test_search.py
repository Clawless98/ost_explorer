from __future__ import annotations
import datetime
import pytest
from ost_explorer.engine.search import parse_query, SearchQuery, search_messages
from ost_explorer.models import Attachment, Message

def _make_msg(subject: str = "Test", sender: str = "alice@corp.com",
              to: list[str] | None = None, body: str = "Hello world",
              date: datetime.datetime | None = None,
              attachments: list[Attachment] | None = None) -> Message:
    return Message(
        subject=subject, sender=sender,
        recipients_to=to or ["bob@corp.com"], recipients_cc=[], recipients_bcc=[],
        date=date or datetime.datetime(2025, 3, 15),
        body_plain=body, body_html="", headers={},
        attachments=attachments or [],
        is_read=True, is_flagged=False,
    )

def test_parse_simple_query():
    q = parse_query("hello world")
    assert q.text == "hello world"
    assert q.from_filter is None

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
    messages = [_make_msg(body="The VPN password is Summer2025"), _make_msg(body="Meeting at 3pm tomorrow")]
    results = search_messages(messages, parse_query("password"))
    assert len(results) == 1

def test_search_from_filter():
    messages = [_make_msg(sender="alice@corp.com"), _make_msg(sender="bob@corp.com")]
    results = search_messages(messages, parse_query("from:alice"))
    assert len(results) == 1

def test_search_to_filter():
    messages = [_make_msg(to=["admin@corp.com"]), _make_msg(to=["user@corp.com"])]
    results = search_messages(messages, parse_query("to:admin"))
    assert len(results) == 1

def test_search_has_attachment():
    att = Attachment(filename="doc.pdf", size=100, mime_type="application/pdf", _extract_fn=None)
    messages = [_make_msg(attachments=[att]), _make_msg(attachments=[])]
    results = search_messages(messages, parse_query("has:attachment"))
    assert len(results) == 1

def test_search_filename_glob():
    att = Attachment(filename="report.xlsx", size=100, mime_type="application/vnd.ms-excel", _extract_fn=None)
    messages = [_make_msg(attachments=[att]), _make_msg(attachments=[Attachment(filename="notes.txt", size=50, mime_type="text/plain", _extract_fn=None)])]
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
    messages = [_make_msg(subject="RE: VPN credentials"), _make_msg(subject="Weekly standup notes")]
    results = search_messages(messages, parse_query("VPN"))
    assert len(results) == 1

def test_search_case_insensitive():
    messages = [_make_msg(body="The PASSWORD is here")]
    results = search_messages(messages, parse_query("password"))
    assert len(results) == 1
