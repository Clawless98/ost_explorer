from __future__ import annotations
import json
from pathlib import Path
import pytest
from ost_explorer.parser.cache import MetadataCache
from ost_explorer.models import Folder

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
    pst_file.write_bytes(b"modified content that changes mtime and size")
    cache2 = MetadataCache(cache_db, pst_file)
    assert cache2.is_valid() is False

def test_cache_store_and_load_message_metadata(cache_db: Path, pst_file: Path):
    cache = MetadataCache(cache_db, pst_file)
    folders = [Folder(name="Inbox", message_count=1, children=[], _folder_id="f1")]
    cache.store_folders(folders)
    msg = {"subject": "Test", "sender": "a@b.com", "date": "2025-03-15T10:30:00", "has_attachments": True}
    cache.store_message_metadata("f1", [msg])
    loaded = cache.load_message_metadata("f1")
    assert len(loaded) == 1
    assert loaded[0]["subject"] == "Test"
