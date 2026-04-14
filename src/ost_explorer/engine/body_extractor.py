"""Helpers for turning HTML and RTF into plain text the scanner can read."""
from __future__ import annotations

import html
import re

_HTML_TAG_RE = re.compile(r"<[^>]+>")
_HTML_STYLE_RE = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL)
_WHITESPACE_RE = re.compile(r"[ \t]+")
_MULTINEWLINE_RE = re.compile(r"\n{3,}")

_RTF_CONTROL_WORD = re.compile(r"\\[a-zA-Z]+-?\d*\s?")
_RTF_CONTROL_SYMBOL = re.compile(r"\\[^a-zA-Z]")
_RTF_BRACE = re.compile(r"[{}]")


def strip_html(text: str) -> str:
    """Strip HTML tags and decode entities to recover scannable plain text.

    Not a full HTML parser — just enough to remove tags, kill script/style
    blocks, and decode entities so regex patterns can match on the visible
    text of an HTML-only email body.
    """
    if not text:
        return ""
    # Drop script/style contents entirely
    text = _HTML_STYLE_RE.sub("", text)
    # Convert <br> and </p> to newlines before stripping other tags
    text = re.sub(r"(?i)<br\s*/?>", "\n", text)
    text = re.sub(r"(?i)</p\s*>", "\n\n", text)
    text = re.sub(r"(?i)</div\s*>", "\n", text)
    # Strip remaining tags
    text = _HTML_TAG_RE.sub("", text)
    # Decode entities
    text = html.unescape(text)
    # Collapse whitespace but preserve paragraph breaks
    text = _WHITESPACE_RE.sub(" ", text)
    text = _MULTINEWLINE_RE.sub("\n\n", text)
    return text.strip()


def rtf_to_text(rtf: str) -> str:
    """Strip RTF control words and braces to recover plain text."""
    if not rtf:
        return ""
    rtf = rtf.replace("\\par", "\n").replace("\\line", "\n")
    rtf = _RTF_CONTROL_WORD.sub("", rtf)
    rtf = _RTF_CONTROL_SYMBOL.sub("", rtf)
    rtf = _RTF_BRACE.sub("", rtf)
    return rtf.strip()
