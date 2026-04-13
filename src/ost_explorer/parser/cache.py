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
        self._conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
        self._conn.execute("CREATE TABLE IF NOT EXISTS folders (id INTEGER PRIMARY KEY AUTOINCREMENT, data TEXT)")
        self._conn.execute("CREATE TABLE IF NOT EXISTS messages (folder_id TEXT, data TEXT)")
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
        return abs(current_stat.st_mtime - stored_mtime) < 0.001 and current_stat.st_size == stored_size

    def store_folders(self, folders: list[Folder]) -> None:
        if self._conn is None:
            return
        data = json.dumps(self._serialize_folders(folders))
        self._conn.execute("DELETE FROM folders")
        self._conn.execute("INSERT INTO folders (data) VALUES (?)", (data,))
        stat = self._source_path.stat()
        self._conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('source_mtime', ?)", (str(stat.st_mtime),))
        self._conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('source_size', ?)", (str(stat.st_size),))
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
        row = self._conn.execute("SELECT data FROM messages WHERE folder_id = ?", (folder_id,)).fetchone()
        if row is None:
            return []
        return json.loads(row[0])

    def _serialize_folders(self, folders: list[Folder]) -> list[dict]:
        return [{"name": f.name, "message_count": f.message_count, "folder_id": f._folder_id, "children": self._serialize_folders(f.children)} for f in folders]

    def _deserialize_folders(self, data: list[dict]) -> list[Folder]:
        return [Folder(name=d["name"], message_count=d["message_count"], children=self._deserialize_folders(d.get("children", [])), _folder_id=d["folder_id"]) for d in data]

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
