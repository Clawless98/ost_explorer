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


from ost_explorer.engine.body_extractor import rtf_to_text as _rtf_to_text


def _safe_attr(obj: Any, *names: str, default: Any = None) -> Any:
    """Try multiple attribute names to handle different pypff API versions.

    Some builds expose get_X() methods, others expose X as properties.
    Properties can raise non-AttributeError exceptions (e.g. IOError) when
    the underlying MAPI value is missing — those must be suppressed here so
    the whole message parse doesn't fail on an optional field.
    """
    for name in names:
        # Try as method first (get_X style)
        getter = f"get_{name}"
        try:
            method = getattr(obj, getter)
        except Exception:
            method = None
        if callable(method):
            try:
                return method()
            except Exception:
                pass
        # Try as property/attribute (catch all exceptions, not just AttributeError,
        # since pypff properties raise IOError when the MAPI value is missing)
        try:
            val = getattr(obj, name)
            if callable(val):
                try:
                    return val()
                except Exception:
                    continue
            return val
        except Exception:
            continue
    return default

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
        num_att = 0
        try:
            num_att = _safe_attr(pff_msg, "number_of_attachments", default=0) or 0
        except Exception:
            pass
        for j in range(num_att):
            try:
                pff_att = pff_msg.get_attachment(j)
                att_ref = pff_att
                att_name = _safe_attr(pff_att, "name", default=None) or f"attachment_{j}"
                att_size = _safe_attr(pff_att, "size", default=0) or 0
                att_mime = _safe_attr(pff_att, "content_type", default=None) or "application/octet-stream"
                attachments.append(Attachment(
                    filename=att_name,
                    size=att_size,
                    mime_type=att_mime,
                    _extract_fn=lambda a=att_ref: self._read_attachment(a),
                ))
            except Exception as e:
                logger.warning("Failed to parse attachment %d: %s", j, e)

        msg_date = _safe_attr(pff_msg, "delivery_time", "creation_time", "modification_time",
                              default=datetime.datetime(1970, 1, 1))

        # Get body — pypff may return bytes or str depending on version
        body_plain = _safe_attr(pff_msg, "plain_text_body", default="") or ""
        body_html = _safe_attr(pff_msg, "html_body", default="") or ""
        body_rtf = _safe_attr(pff_msg, "rtf_body", default="") or ""
        if isinstance(body_plain, bytes):
            body_plain = body_plain.decode("utf-8", errors="replace")
        if isinstance(body_html, bytes):
            body_html = body_html.decode("utf-8", errors="replace")
        if isinstance(body_rtf, bytes):
            body_rtf = body_rtf.decode("utf-8", errors="replace")

        # If plain and html are both empty (common for Notes), fall back to RTF
        # with basic control-word stripping so scanner can see the content.
        if not body_plain and not body_html and body_rtf:
            body_plain = _rtf_to_text(body_rtf)

        return Message(
            subject=_safe_attr(pff_msg, "subject", default="(no subject)") or "(no subject)",
            sender=_safe_attr(pff_msg, "sender_name", default="") or "",
            recipients_to=self._safe_split(_safe_attr(pff_msg, "display_to", default="")),
            recipients_cc=self._safe_split(_safe_attr(pff_msg, "display_cc", default="")),
            recipients_bcc=self._safe_split(_safe_attr(pff_msg, "display_bcc", default="")),
            date=msg_date or datetime.datetime(1970, 1, 1),
            body_plain=body_plain,
            body_html=body_html,
            headers=self._parse_headers(_safe_attr(pff_msg, "transport_headers", default="")),
            attachments=attachments,
            is_read=True,
            is_flagged=False,
            message_class=_safe_attr(pff_msg, "message_class", default="") or "",
        )

    @staticmethod
    def _read_attachment(att: Any) -> bytes:
        """Read attachment bytes, handling different pypff API versions."""
        # Try read_buffer(size) first
        if hasattr(att, "read_buffer"):
            size = _safe_attr(att, "size", default=0) or 0
            if size > 0:
                try:
                    return att.read_buffer(size)
                except Exception:
                    pass
        # Try read()
        if hasattr(att, "read"):
            try:
                return att.read()
            except Exception:
                pass
        return b""

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
                    display_name=_safe_attr(item, "subject", default="") or "",
                    email_addresses=[_safe_attr(item, "sender_name", default="") or ""],
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
