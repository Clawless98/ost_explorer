from __future__ import annotations
from pathlib import Path

_PST_MAGIC = b"!BDN"
_MIN_HEADER_SIZE = 512
_PST_VERSIONS = {0x17, 0x0E, 0x24}
_OST_VERSIONS = {0x15}

class FormatError(Exception):
    pass

def detect_format(path: Path) -> str:
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    size = path.stat().st_size
    with open(path, "rb") as f:
        header = f.read(min(_MIN_HEADER_SIZE, size))
    if len(header) < 4:
        raise FormatError(f"File too small to be a PST/OST ({size} bytes)")
    if header[:4] != _PST_MAGIC:
        raise FormatError(f"Unrecognized file format (magic bytes: {header[:4]!r})")
    if size < _MIN_HEADER_SIZE:
        raise FormatError(f"File too small to be a PST/OST ({size} bytes)")
    version_byte = header[14]
    if version_byte in _OST_VERSIONS:
        return "OST"
    return "PST"
