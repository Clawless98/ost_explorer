"""Extract scannable text content from attachments.

Returns a string of text to feed into the scanner, or empty string if the
attachment is binary/junk (images, videos, compiled binaries).
"""
from __future__ import annotations

import io
import logging
import zipfile
from pathlib import PurePosixPath
from typing import Optional
from xml.etree import ElementTree as ET

from ost_explorer.models import Attachment

logger = logging.getLogger(__name__)

# File extensions to decode as text directly
_TEXT_EXTENSIONS = {
    ".txt", ".csv", ".tsv", ".log", ".md", ".rst",
    ".conf", ".config", ".cfg", ".ini", ".env", ".properties",
    ".yaml", ".yml", ".json", ".xml", ".toml",
    ".html", ".htm", ".css", ".js", ".ts",
    ".sh", ".bash", ".zsh", ".bat", ".cmd", ".ps1", ".psm1",
    ".py", ".rb", ".pl", ".go", ".rs", ".java", ".kt", ".c", ".cpp", ".h",
    ".sql", ".graphql",
    ".pem", ".key", ".crt", ".cer", ".pub",  # may contain key material
    ".eml", ".msg.txt",
}

# Skip these — binary junk with no useful text
_BINARY_EXTENSIONS = {
    # Images
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif", ".webp",
    ".svg", ".ico", ".heic", ".raw",
    # Video
    ".mp4", ".avi", ".mov", ".mkv", ".wmv", ".flv", ".webm", ".m4v",
    # Audio
    ".mp3", ".wav", ".flac", ".ogg", ".m4a", ".aac", ".wma",
    # Compiled / binary
    ".exe", ".dll", ".so", ".dylib", ".bin", ".iso", ".img", ".dmg",
    ".o", ".obj", ".class", ".pyc",
    # Fonts
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    # Archives we don't recurse into by default
    ".7z", ".rar", ".gz", ".bz2", ".xz", ".tar",
}

# Office Open XML — unzip and extract text
_OFFICE_OOXML = {".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"}

# Max size to scan per attachment (50 MB)
_MAX_SIZE = 50 * 1024 * 1024


def extract_text(attachment: Attachment) -> str:
    """Return scannable text from an attachment, or empty string if binary/skip."""
    if attachment.size > _MAX_SIZE:
        logger.debug("Skipping %s: too large (%d bytes)", attachment.filename, attachment.size)
        return ""

    ext = _get_extension(attachment.filename)

    if ext in _BINARY_EXTENSIONS:
        return ""

    try:
        data = attachment.extract_bytes()
    except Exception as e:
        logger.warning("Failed to read attachment %s: %s", attachment.filename, e)
        return ""

    if not data:
        return ""

    if ext in _OFFICE_OOXML:
        return _extract_ooxml_text(data, attachment.filename)

    if ext == ".zip":
        return _extract_zip_text(data, attachment.filename)

    if ext in _TEXT_EXTENSIONS:
        return _decode_text(data)

    # Unknown extension — sniff: if it looks like text, scan it
    if _looks_like_text(data):
        return _decode_text(data)

    return ""


def _get_extension(filename: str) -> str:
    name = filename.lower()
    # Handle .tar.gz etc.
    if name.endswith(".tar.gz") or name.endswith(".tar.bz2"):
        return ".tar.gz"
    idx = name.rfind(".")
    return name[idx:] if idx != -1 else ""


def _decode_text(data: bytes) -> str:
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _looks_like_text(data: bytes, sample_size: int = 8192) -> bool:
    """Heuristic: printable-ASCII ratio > 0.85 in first sample_size bytes."""
    sample = data[:sample_size]
    if not sample:
        return False
    # Count printable + whitespace bytes
    printable = sum(1 for b in sample if b in (9, 10, 13) or 32 <= b <= 126)
    return (printable / len(sample)) > 0.85


def _extract_ooxml_text(data: bytes, filename: str) -> str:
    """Extract text from .docx/.xlsx/.pptx by unzipping and reading XML parts."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return ""

    parts: list[str] = []
    try:
        for name in zf.namelist():
            lower = name.lower()
            # Word documents
            if lower == "word/document.xml" or lower.startswith("word/footnotes") or lower.startswith("word/endnotes"):
                parts.append(_xml_text(zf.read(name)))
            # Excel — shared strings + sheet XML
            elif lower == "xl/sharedstrings.xml":
                parts.append(_xml_text(zf.read(name)))
            elif lower.startswith("xl/worksheets/") and lower.endswith(".xml"):
                parts.append(_xml_text(zf.read(name)))
            # PowerPoint slides
            elif lower.startswith("ppt/slides/") and lower.endswith(".xml"):
                parts.append(_xml_text(zf.read(name)))
            elif lower.startswith("ppt/notesslides/") and lower.endswith(".xml"):
                parts.append(_xml_text(zf.read(name)))
    except Exception as e:
        logger.warning("Failed to extract OOXML from %s: %s", filename, e)
    finally:
        zf.close()

    return "\n".join(p for p in parts if p)


def _xml_text(data: bytes) -> str:
    """Extract all text nodes from an XML document."""
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return ""
    return " ".join(t for t in root.itertext() if t and t.strip())


def _extract_zip_text(data: bytes, filename: str) -> str:
    """Recurse into a zip attachment, scanning member files up to size limit."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return ""

    parts: list[str] = []
    total_extracted = 0
    try:
        for info in zf.infolist():
            if info.is_dir():
                continue
            if total_extracted + info.file_size > _MAX_SIZE:
                logger.debug("Zip %s: hit size cap", filename)
                break
            member_name = info.filename
            member_ext = _get_extension(member_name)
            if member_ext in _BINARY_EXTENSIONS:
                continue
            try:
                member_data = zf.read(info)
                total_extracted += len(member_data)
            except Exception:
                continue

            # Header: include path so scanner sees context / filename rules fire
            parts.append(f"--- {member_name} ---")

            if member_ext in _OFFICE_OOXML:
                parts.append(_extract_ooxml_text(member_data, member_name))
            elif member_ext in _TEXT_EXTENSIONS or _looks_like_text(member_data):
                parts.append(_decode_text(member_data))
    except Exception as e:
        logger.warning("Failed to extract zip %s: %s", filename, e)
    finally:
        zf.close()

    return "\n".join(p for p in parts if p)
