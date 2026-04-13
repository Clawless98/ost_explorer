from __future__ import annotations
import csv
import datetime
import json
from importlib.resources import files
from pathlib import Path
from jinja2 import Template
from ost_explorer import __version__
from ost_explorer.models import Message, ScanFinding, Severity

_SEVERITY_NAMES = {
    Severity.LOW: "low", Severity.MEDIUM: "medium",
    Severity.HIGH: "high", Severity.CRITICAL: "critical",
}

def export_json(messages: list[Message], findings: list[ScanFinding], output_path: Path) -> None:
    data = {
        "generated_at": datetime.datetime.now().isoformat(),
        "messages": [_message_to_dict(m) for m in messages],
        "findings": [_finding_to_dict(f) for f in findings],
    }
    output_path.write_text(json.dumps(data, indent=2, default=str))

def export_csv(messages: list[Message], findings: list[ScanFinding], output_path: Path) -> None:
    with open(output_path, "w", newline="") as f:
        if messages:
            writer = csv.DictWriter(f, fieldnames=["date", "sender", "recipients_to", "subject", "has_attachments", "body_preview"])
            writer.writeheader()
            for msg in messages:
                writer.writerow({
                    "date": msg.date.isoformat(), "sender": msg.sender,
                    "recipients_to": "; ".join(msg.recipients_to),
                    "subject": msg.subject, "has_attachments": msg.has_attachments,
                    "body_preview": (msg.body_plain or "")[:200],
                })
        if findings:
            if messages:
                f.write("\n")
            writer = csv.DictWriter(f, fieldnames=["severity", "rule_name", "matched_text", "message_subject", "message_sender", "message_date", "folder_path"])
            writer.writeheader()
            for finding in findings:
                writer.writerow({
                    "severity": _SEVERITY_NAMES.get(finding.severity, "medium"),
                    "rule_name": finding.rule_name, "matched_text": finding.matched_text,
                    "message_subject": finding.message_subject, "message_sender": finding.message_sender,
                    "message_date": finding.message_date.isoformat(), "folder_path": finding.folder_path,
                })

def export_html(messages: list[Message], findings: list[ScanFinding], output_path: Path, mailbox_name: str = "unknown") -> None:
    template_path = Path(str(files("ost_explorer.templates").joinpath("report.html")))
    template = Template(template_path.read_text())
    enriched_findings = []
    for f in findings:
        enriched_findings.append(type("Finding", (), {
            "severity_name": _SEVERITY_NAMES.get(f.severity, "medium"),
            "rule_name": f.rule_name, "matched_text": f.matched_text,
            "context": f.context, "message_subject": f.message_subject,
            "message_sender": f.message_sender,
            "message_date": f.message_date.strftime("%Y-%m-%d"),
        })())
    html = template.render(
        mailbox_name=mailbox_name,
        generated_at=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total_messages=len(messages), total_findings=len(findings),
        critical_count=sum(1 for f in findings if f.severity == Severity.CRITICAL),
        high_count=sum(1 for f in findings if f.severity == Severity.HIGH),
        findings=enriched_findings, messages=messages, version=__version__,
    )
    output_path.write_text(html)

def export_attachments(messages: list[Message], output_dir: Path, folder_name: str = "attachments") -> int:
    count = 0
    for msg in messages:
        for att in msg.attachments:
            safe_subject = "".join(c if c.isalnum() or c in " -_" else "_" for c in msg.subject)[:50]
            msg_dir = output_dir / folder_name / f"{safe_subject}_{msg.date.strftime('%Y%m%d')}"
            msg_dir.mkdir(parents=True, exist_ok=True)
            (msg_dir / att.filename).write_bytes(att.extract_bytes())
            count += 1
    return count

def _message_to_dict(msg: Message) -> dict:
    return {
        "subject": msg.subject, "sender": msg.sender,
        "recipients_to": msg.recipients_to, "recipients_cc": msg.recipients_cc,
        "recipients_bcc": msg.recipients_bcc, "date": msg.date.isoformat(),
        "body_plain": msg.body_plain, "has_attachments": msg.has_attachments,
        "attachment_names": [a.filename for a in msg.attachments],
        "is_read": msg.is_read, "is_flagged": msg.is_flagged,
    }

def _finding_to_dict(f: ScanFinding) -> dict:
    return {
        "rule_name": f.rule_name, "severity": _SEVERITY_NAMES.get(f.severity, "medium"),
        "matched_text": f.matched_text, "context": f.context,
        "message_subject": f.message_subject, "message_sender": f.message_sender,
        "message_date": f.message_date.isoformat(), "folder_path": f.folder_path,
    }
