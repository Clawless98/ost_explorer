from __future__ import annotations
import re
from dataclasses import dataclass, field
from pathlib import Path
import yaml
from yaml.reader import Reader
from yaml.scanner import Scanner, ScannerError
from yaml.parser import Parser
from yaml.composer import Composer
from yaml.constructor import SafeConstructor
from yaml.resolver import Resolver

VALID_SEVERITIES = {"low", "medium", "high", "critical"}


class _LenientScanner(Scanner):
    """YAML scanner that treats unknown backslash escapes as literals.

    Standard YAML rejects ``\\d``, ``\\w`` etc. inside double-quoted strings,
    but regex patterns stored in YAML frequently contain them.  This scanner
    passes them through unchanged so that ``"EMP-\\d{6}"`` is read as the
    string ``EMP-\\d{6}`` (which is what the rule author intended).
    """

    def scan_flow_scalar_non_spaces(self, double, start_mark):
        # Identical to the parent implementation except the final `else` branch:
        # instead of raising ScannerError for unknown escapes, we emit the
        # backslash and the following character literally.
        chunks = []
        while True:
            length = 0
            while self.peek(length) not in '\'"\\' + '\0 \t\r\n\x85\u2028\u2029':
                length += 1
            if length:
                chunks.append(self.prefix(length))
                self.forward(length)
            ch = self.peek()
            if not double and ch == "'" and self.peek(1) == "'":
                chunks.append("'")
                self.forward(2)
            elif (double and ch == "'") or (not double and ch in '"\\'):
                chunks.append(ch)
                self.forward()
            elif double and ch == '\\':
                self.forward()
                ch = self.peek()
                if ch in self.ESCAPE_REPLACEMENTS:
                    chunks.append(self.ESCAPE_REPLACEMENTS[ch])
                    self.forward()
                elif ch in self.ESCAPE_CODES:
                    length = self.ESCAPE_CODES[ch]
                    self.forward()
                    for k in range(length):
                        if self.peek(k) not in '0123456789ABCDEFabcdef':
                            raise ScannerError(
                                "while scanning a double-quoted scalar",
                                start_mark,
                                "expected escape sequence of %d hexadecimal "
                                "numbers, but found %r" % (length, self.peek(k)),
                                self.get_mark(),
                            )
                    code = int(self.prefix(length), 16)
                    chunks.append(chr(code))
                    self.forward(length)
                elif ch in '\r\n\x85\u2028\u2029':
                    self.scan_line_break()
                    chunks.extend(self.scan_flow_scalar_breaks(double, start_mark))
                else:
                    # Unknown escape: preserve backslash + character literally
                    chunks.append('\\')
                    chunks.append(ch)
                    self.forward()
            else:
                break
        return chunks


class _LenientLoader(Reader, _LenientScanner, Parser, Composer, SafeConstructor, Resolver):
    """Full YAML loader using the lenient scanner."""

    def __init__(self, stream: str) -> None:
        Reader.__init__(self, stream)
        _LenientScanner.__init__(self)
        Parser.__init__(self)
        Composer.__init__(self)
        SafeConstructor.__init__(self)
        Resolver.__init__(self)


def _lenient_load(text: str):
    return yaml.load(text, Loader=_LenientLoader)  # noqa: S506 — we use SafeConstructor


class RuleValidationError(Exception):
    pass


@dataclass
class Rule:
    name: str
    severity: str
    note: str
    _compiled_patterns: list[re.Pattern] = field(repr=False, default_factory=list)

    def matches(self, text: str) -> bool:
        return any(p.search(text) for p in self._compiled_patterns)

    def find_all(self, text: str) -> list[re.Match]:
        results: list[re.Match] = []
        for p in self._compiled_patterns:
            results.extend(p.finditer(text))
        return results


def load_rules_from_string(yaml_str: str) -> list[Rule]:
    data = _lenient_load(yaml_str)
    if not isinstance(data, list):
        raise RuleValidationError("Rules file must be a YAML list")
    return [_parse_rule(entry, idx) for idx, entry in enumerate(data)]


def load_rules_from_yaml(path: Path) -> list[Rule]:
    text = path.read_text()
    return load_rules_from_string(text)


def _parse_rule(entry: dict, index: int) -> Rule:
    if not isinstance(entry, dict):
        raise RuleValidationError(
            f"Rule at index {index}: expected a mapping, got {type(entry).__name__}"
        )
    name = entry.get("name")
    if not name:
        raise RuleValidationError(f"Rule at index {index}: missing 'name' field")
    severity = entry.get("severity", "medium")
    if severity not in VALID_SEVERITIES:
        raise RuleValidationError(
            f"Rule '{name}': invalid severity '{severity}' "
            f"(must be one of: {', '.join(sorted(VALID_SEVERITIES))})"
        )
    note = entry.get("note", "")
    patterns: list[re.Pattern] = []
    if "find" in entry:
        escaped = re.escape(entry["find"])
        patterns.append(re.compile(escaped, re.IGNORECASE))
    elif "find_any" in entry:
        keywords = entry["find_any"]
        if not isinstance(keywords, list) or len(keywords) == 0:
            raise RuleValidationError(f"Rule '{name}': 'find_any' must be a non-empty list")
        for kw in keywords:
            escaped = re.escape(str(kw))
            patterns.append(re.compile(escaped, re.IGNORECASE))
    elif "pattern" in entry:
        raw = entry["pattern"]
        try:
            patterns.append(re.compile(raw, re.IGNORECASE))
        except re.error as e:
            raise RuleValidationError(f"Rule '{name}': invalid regex pattern: {e}")
    else:
        raise RuleValidationError(
            f"Rule '{name}': missing 'find', 'find_any', or 'pattern' field"
        )
    return Rule(name=name, severity=severity, note=note, _compiled_patterns=patterns)
