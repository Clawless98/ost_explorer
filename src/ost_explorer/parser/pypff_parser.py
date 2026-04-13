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
        return Mailbox(path=path, format_type=format_type, folders=folders, total_messages=total)

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
            folder._pff_folder = sub
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
        return messages

    def _convert_message(self, pff_msg: Any) -> Message:
        attachments: list[Attachment] = []
        for j in range(pff_msg.get_number_of_attachments()):
            try:
                pff_att = pff_msg.get_attachment(j)
                att_ref = pff_att
                attachments.append(Attachment(
                    filename=pff_att.get_name() or f"attachment_{j}",
                    size=pff_att.get_size(),
                    mime_type=pff_att.get_content_type() or "application/octet-stream",
                    _extract_fn=lambda a=att_ref: a.read_buffer(a.get_size()),
                ))
            except Exception as e:
                logger.warning("Failed to parse attachment %d: %s", j, e)
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
            is_read=True,
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
                contacts.append(Contact(
                    display_name=item.get_subject() or "",
                    email_addresses=[item.get_sender_name() or ""],
                    phone_numbers=[], organization="", title="",
                ))
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
