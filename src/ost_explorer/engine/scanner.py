from __future__ import annotations
import logging
from importlib.resources import files
from pathlib import Path
from ost_explorer.models import Message, ScanFinding, Severity
from ost_explorer.rules.loader import Rule, load_rules_from_yaml

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "low": Severity.LOW, "medium": Severity.MEDIUM,
    "high": Severity.HIGH, "critical": Severity.CRITICAL,
}
# Default: include this many chars of context around each match.
# Large enough to capture the surrounding paragraph / username line.
_CONTEXT_CHARS = 2000

class Scanner:
    def __init__(self, custom_rule_paths: list[Path] | None = None,
                 use_defaults: bool = True,
                 scan_attachments: bool = True,
                 context_chars: int = _CONTEXT_CHARS,
                 full_context: bool = False) -> None:
        self._rules: list[Rule] = []
        self._scan_attachments = scan_attachments
        self._context_chars = context_chars
        self._full_context = full_context
        if use_defaults:
            self._load_default_rules()
        if custom_rule_paths:
            for path in custom_rule_paths:
                self._rules.extend(load_rules_from_yaml(path))
        logger.info("Scanner loaded %d rules", len(self._rules))

    def _load_default_rules(self) -> None:
        default_path = Path(str(files("ost_explorer.rules").joinpath("default_rules.yaml")))
        self._rules.extend(load_rules_from_yaml(default_path))

    def scan_message(self, message: Message, folder_path: str,
                     min_severity: Severity = Severity.LOW) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        text = message.body_plain or ""
        findings.extend(self._scan_text(text, message, folder_path, min_severity))
        findings.extend(self._scan_text(message.subject, message, folder_path, min_severity))
        for att in message.attachments:
            # Scan the filename itself
            findings.extend(self._scan_text(att.filename, message, folder_path, min_severity))
            # Scan the attachment content (text files, office docs, zips)
            if self._scan_attachments:
                try:
                    from ost_explorer.engine.attachment_content import extract_text
                    content = extract_text(att)
                    if content:
                        att_findings = self._scan_text(content, message, folder_path, min_severity)
                        # Tag findings with the attachment filename in folder path
                        for f in att_findings:
                            f.folder_path = f"{folder_path} → {att.filename}"
                        findings.extend(att_findings)
                except Exception as e:
                    logger.warning("Failed to scan attachment %s: %s", att.filename, e)
        return findings

    def scan_messages(self, messages: list[Message], folder_path: str,
                      min_severity: Severity = Severity.LOW,
                      dedupe: bool = True) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        for msg in messages:
            findings.extend(self.scan_message(msg, folder_path, min_severity))
        if dedupe:
            findings = dedupe_findings(findings)
        return findings

    def _scan_text(self, text: str, message: Message, folder_path: str,
                   min_severity: Severity) -> list[ScanFinding]:
        if not text:
            return []
        findings: list[ScanFinding] = []
        seen_in_this_text: set[tuple[str, str]] = set()
        for rule in self._rules:
            severity = _SEVERITY_MAP.get(rule.severity, Severity.MEDIUM)
            if severity < min_severity:
                continue
            matches = rule.find_all(text)
            for match in matches:
                matched_text = match.group()
                # Dedupe within the same text block — avoids N hits when
                # one email has the same password repeated or embedded multiple times
                key = (rule.name, matched_text)
                if key in seen_in_this_text:
                    continue
                seen_in_this_text.add(key)
                context = self._build_context(text, match.start(), match.end())
                findings.append(ScanFinding(
                    rule_name=rule.name, severity=severity,
                    matched_text=matched_text, context=context,
                    message_subject=message.subject, message_sender=message.sender,
                    message_date=message.date, folder_path=folder_path,
                ))
        return findings

    def _build_context(self, text: str, match_start: int, match_end: int) -> str:
        """Return the context surrounding a match.

        If full_context is on, return the whole text. Otherwise return a
        window of context_chars centered on the match — big enough to see
        the username/recipient/paragraph that goes with a password.
        """
        if self._full_context:
            return text
        half = self._context_chars // 2
        start = max(0, match_start - half)
        end = min(len(text), match_end + half)
        context = text[start:end]
        prefix = "... " if start > 0 else ""
        suffix = " ..." if end < len(text) else ""
        return f"{prefix}{context}{suffix}"


def dedupe_findings(findings: list[ScanFinding]) -> list[ScanFinding]:
    """Collapse findings that share the same (rule, matched_text).

    Reply chains forward the same password through many messages — without
    dedup you see the same hit dozens of times. This keeps the first
    occurrence and appends a duplicate count to its context so you know how
    widely the credential was shared.
    """
    seen: dict[tuple[str, str], ScanFinding] = {}
    counts: dict[tuple[str, str], int] = {}
    for f in findings:
        key = (f.rule_name, f.matched_text)
        if key not in seen:
            seen[key] = f
            counts[key] = 1
        else:
            counts[key] += 1
    result: list[ScanFinding] = []
    for key, finding in seen.items():
        n = counts[key]
        if n > 1:
            finding.context = f"{finding.context}\n\n[seen in {n} messages / attachments]"
        result.append(finding)
    return result
