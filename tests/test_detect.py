from __future__ import annotations
from pathlib import Path
import pytest
from ost_explorer.parser.detect import detect_format, FormatError

def test_detect_pst_format(tmp_path: Path):
    pst_file = tmp_path / "test.pst"
    header = b"!BDN" + b"\x00" * 10 + b"\x17" + b"\x00" * 497
    pst_file.write_bytes(header)
    assert detect_format(pst_file) == "PST"

def test_detect_ost_format(tmp_path: Path):
    ost_file = tmp_path / "test.ost"
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
