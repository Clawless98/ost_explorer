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
    """Fallback parser using olefile for corrupted/partial PST files."""

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
        folders = self._extract_folders()
        total = sum(f.message_count for f in folders)
        return Mailbox(path=path, format_type=format_type, folders=folders, total_messages=total)

    def _extract_folders(self) -> list[Folder]:
        if self._ole is None:
            return []
        folders: list[Folder] = []
        try:
            streams = self._ole.listdir()
            folder_names: set[str] = set()
            for stream in streams:
                if len(stream) > 0:
                    folder_names.add(stream[0])
            for name in sorted(folder_names):
                folders.append(Folder(name=name, message_count=0, children=[], _folder_id=name))
        except Exception as e:
            logger.warning("Failed to extract folder tree: %s", e)
        return folders

    def get_messages(self, folder: Folder, offset: int = 0, limit: int = 50) -> list[Message]:
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
