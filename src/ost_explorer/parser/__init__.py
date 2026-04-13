from __future__ import annotations
import logging
from pathlib import Path
from ost_explorer.models import Mailbox
from ost_explorer.parser.base import MailboxParser
from ost_explorer.parser.detect import detect_format

logger = logging.getLogger(__name__)

__all__ = ["detect_format", "open_mailbox"]

def open_mailbox(path: Path) -> tuple[Mailbox, MailboxParser]:
    """Open a PST/OST file with the best available parser.
    Returns (Mailbox, parser_instance) — caller must call parser.close() when done.
    """
    path = Path(path)
    try:
        from ost_explorer.parser.pypff_parser import PypffParser
        parser = PypffParser()
        mailbox = parser.open(path)
        logger.info("Opened %s with pypff parser", path)
        return mailbox, parser
    except ImportError:
        logger.info("pypff not available, trying olefile fallback")
    except IOError as e:
        logger.warning("pypff failed to open %s: %s — trying olefile", path, e)
    try:
        from ost_explorer.parser.ole_parser import OleParser
        parser = OleParser()
        mailbox = parser.open(path)
        logger.info("Opened %s with olefile fallback parser", path)
        return mailbox, parser
    except ImportError:
        raise ImportError("No parser available. Install pypff or olefile.")
    except IOError as e:
        raise IOError(f"No parser could open {path}: {e}") from e
