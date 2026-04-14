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
_CONTEXT_LINES = 2

class Scanner:
    def __init__(self, custom_rule_paths: list[Path] | None = None,
                 use_defaults: bool = True) -> None:
        self._rules: list[Rule] = []
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
            findings.extend(self._scan_text(att.filename, message, folder_path, min_severity))
        return findings

    def scan_messages(self, messages: list[Message], folder_path: str,
                      min_severity: Severity = Severity.LOW) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        for msg in messages:
            findings.extend(self.scan_message(msg, folder_path, min_severity))
        return findings

    def _scan_text(self, text: str, message: Message, folder_path: str,
                   min_severity: Severity) -> list[ScanFinding]:
        if not text:
            return []
        findings: list[ScanFinding] = []
        lines = text.split("\n")
        for rule in self._rules:
            severity = _SEVERITY_MAP.get(rule.severity, Severity.MEDIUM)
            if severity < min_severity:
                continue
            matches = rule.find_all(text)
            for match in matches:
                match_start = match.start()
                char_count = 0
                match_line_idx = 0
                for idx, line in enumerate(lines):
                    char_count += len(line) + 1
                    if char_count > match_start:
                        match_line_idx = idx
                        break
                context_start = max(0, match_line_idx - _CONTEXT_LINES)
                context_end = min(len(lines), match_line_idx + _CONTEXT_LINES + 1)
                context = "\n".join(lines[context_start:context_end])
                findings.append(ScanFinding(
                    rule_name=rule.name, severity=severity,
                    matched_text=match.group(), context=context,
                    message_subject=message.subject, message_sender=message.sender,
                    message_date=message.date, folder_path=folder_path,
                ))
        return findings
