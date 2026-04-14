from __future__ import annotations
import logging
import sys
from pathlib import Path
import click
from ost_explorer import __version__

@click.group()
@click.version_option(__version__, prog_name="ost_explorer")
@click.option("--quiet", "-q", is_flag=True, help="Suppress banner and progress output")
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging")
@click.pass_context
def cli(ctx: click.Context, quiet: bool, verbose: bool) -> None:
    """ost_explorer — PST/OST email archive triage tool for penetration testing."""
    ctx.ensure_object(dict)
    ctx.obj["quiet"] = quiet
    level = logging.DEBUG if verbose else (logging.WARNING if quiet else logging.INFO)
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")
    if not quiet:
        click.echo(f"ost_explorer v{__version__}")

@cli.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.pass_context
def info(ctx: click.Context, file: Path) -> None:
    """Show summary information about a PST/OST file."""
    from ost_explorer.parser import open_mailbox
    from ost_explorer.parser.detect import detect_format
    fmt = detect_format(file)
    click.echo(f"File:     {file}")
    click.echo(f"Format:   {fmt}")
    click.echo(f"Size:     {file.stat().st_size:,} bytes")
    try:
        mailbox, parser = open_mailbox(file)
        click.echo(f"Folders:  {len(mailbox.folders)}")
        click.echo(f"Messages: {mailbox.total_messages}")
        def _print_tree(folders, indent=0):
            for f in folders:
                click.echo(f"{'  ' * indent}  {f.name} ({f.message_count})")
                _print_tree(f.children, indent + 1)
        click.echo("Folder tree:")
        _print_tree(mailbox.folders)
        parser.close()
    except Exception as e:
        click.echo(f"Warning: Could not fully parse file: {e}", err=True)

@cli.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.option("--rules", "-r", multiple=True, type=click.Path(exists=True, path_type=Path), help="Custom rule YAML files")
@click.option("--output", "-o", type=click.Path(path_type=Path), help="Output file path")
@click.option("--format", "-f", "fmt", type=click.Choice(["json", "csv", "text"]), default="text", help="Output format")
@click.option("--severity", type=click.Choice(["low", "medium", "high", "critical"]), default="low", help="Minimum severity")
@click.option("--folder", type=str, default=None, help="Scope to specific folder")
@click.option("--include-deleted/--no-deleted", default=True, help="Include recovered/deleted items")
@click.option("--no-cache", is_flag=True, help="Skip SQLite cache")
@click.option("--only-custom", is_flag=True, help="Use only custom rules, skip built-in defaults")
@click.option("--scan-attachments/--no-scan-attachments", default=True,
              help="Scan content of text/office/zip attachments (default: on)")
@click.option("--dedupe/--no-dedupe", default=True,
              help="Collapse duplicate hits (same rule + matched text). Default: on")
@click.option("--full-context", is_flag=True,
              help="Include entire message body in context instead of a window")
@click.option("--context-chars", type=int, default=2000,
              help="Chars of context around each match (default: 2000)")
@click.pass_context
def scan(ctx: click.Context, file: Path, rules: tuple[Path, ...], output: Path | None,
         fmt: str, severity: str, folder: str | None, include_deleted: bool, no_cache: bool,
         only_custom: bool, scan_attachments: bool, dedupe: bool,
         full_context: bool, context_chars: int) -> None:
    """Scan a PST/OST file for credentials, secrets, and sensitive data."""
    from ost_explorer.engine.scanner import Scanner
    from ost_explorer.engine.export import export_json, export_csv
    from ost_explorer.models import Severity
    from ost_explorer.parser import open_mailbox
    severity_map = {"low": Severity.LOW, "medium": Severity.MEDIUM, "high": Severity.HIGH, "critical": Severity.CRITICAL}
    min_severity = severity_map[severity]
    if only_custom and not rules:
        click.echo("Error: --only-custom requires at least one --rules file", err=True)
        sys.exit(2)
    scanner = Scanner(
        custom_rule_paths=list(rules) if rules else None,
        use_defaults=not only_custom,
        scan_attachments=scan_attachments,
        context_chars=context_chars,
        full_context=full_context,
    )
    mailbox, parser = open_mailbox(file)
    all_findings = []
    def _scan_folders(folders):
        for f in folders:
            if folder and f.name.lower() != folder.lower():
                _scan_folders(f.children)
                continue
            if not ctx.obj.get("quiet"):
                click.echo(f"Scanning: {f.name} ({f.message_count} messages)")
            offset = 0
            while True:
                messages = parser.get_messages(f, offset=offset, limit=50)
                if not messages:
                    break
                # Don't dedupe per-batch — we'll dedupe globally at the end
                all_findings.extend(scanner.scan_messages(
                    messages, folder_path=f.name,
                    min_severity=min_severity, dedupe=False,
                ))
                offset += 50
            _scan_folders(f.children)
    _scan_folders(mailbox.folders)
    if include_deleted:
        if not ctx.obj.get("quiet"):
            click.echo("Scanning recovered/deleted items...")
        recovered = parser.get_recovered_messages()
        if recovered:
            all_findings.extend(scanner.scan_messages(
                recovered, folder_path="Recovered",
                min_severity=min_severity, dedupe=False,
            ))
    parser.close()
    # Global dedupe across all folders
    if dedupe:
        from ost_explorer.engine.scanner import dedupe_findings
        all_findings = dedupe_findings(all_findings)
    if output and fmt == "json":
        export_json([], all_findings, output)
        click.echo(f"Findings exported to {output}")
    elif output and fmt == "csv":
        export_csv([], all_findings, output)
        click.echo(f"Findings exported to {output}")
    else:
        for f in all_findings:
            click.echo("=" * 78)
            click.echo(f"[{f.severity.name}] {f.rule_name}: {f.matched_text}")
            click.echo(f"  Message: {f.message_subject}")
            click.echo(f"  From:    {f.message_sender}")
            click.echo(f"  Date:    {f.message_date}")
            click.echo(f"  Folder:  {f.folder_path}")
            if f.context:
                click.echo(f"  Context:")
                for line in f.context.splitlines():
                    click.echo(f"    {line}")
            click.echo()
    click.echo(f"\nTotal findings: {len(all_findings)}")
    sys.exit(1 if all_findings else 0)

@cli.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.option("--format", "-f", "fmt", type=click.Choice(["json", "csv", "html"]), required=True, help="Export format")
@click.option("--output", "-o", type=click.Path(path_type=Path), required=True, help="Output file path")
@click.option("--output-dir", type=click.Path(path_type=Path), help="Output directory for attachments")
@click.option("--attachments", is_flag=True, help="Extract attachments")
@click.option("--folder", type=str, default=None, help="Scope to specific folder")
@click.pass_context
def export(ctx: click.Context, file: Path, fmt: str, output: Path,
           output_dir: Path | None, attachments: bool, folder: str | None) -> None:
    """Export messages, findings, and attachments from a PST/OST file."""
    from ost_explorer.engine.export import export_json, export_csv, export_html, export_attachments
    from ost_explorer.engine.scanner import Scanner
    from ost_explorer.parser import open_mailbox
    mailbox, parser = open_mailbox(file)
    scanner = Scanner()
    all_messages, all_findings = [], []
    def _collect(folders):
        for f in folders:
            if folder and f.name.lower() != folder.lower():
                _collect(f.children)
                continue
            offset = 0
            while True:
                messages = parser.get_messages(f, offset=offset, limit=50)
                if not messages:
                    break
                all_messages.extend(messages)
                all_findings.extend(scanner.scan_messages(messages, folder_path=f.name))
                offset += 50
            _collect(f.children)
    _collect(mailbox.folders)
    parser.close()
    if fmt == "json":
        export_json(all_messages, all_findings, output)
    elif fmt == "csv":
        export_csv(all_messages, all_findings, output)
    elif fmt == "html":
        export_html(all_messages, all_findings, output, mailbox_name=file.name)
    click.echo(f"Exported {len(all_messages)} messages and {len(all_findings)} findings to {output}")
    if attachments and output_dir:
        count = export_attachments(all_messages, output_dir)
        click.echo(f"Extracted {count} attachments to {output_dir}")

@cli.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.pass_context
def browse(ctx: click.Context, file: Path) -> None:
    """Open interactive TUI browser for a PST/OST file."""
    from ost_explorer.tui.app import OstExplorerApp
    app = OstExplorerApp(file)
    app.run()

@cli.command()
@click.argument("rules_file", type=click.Path(exists=True, path_type=Path))
def validate(rules_file: Path) -> None:
    """Validate a custom rules YAML file."""
    from ost_explorer.rules.loader import load_rules_from_yaml, RuleValidationError
    try:
        rules = load_rules_from_yaml(rules_file)
        click.echo(f"Valid: {len(rules)} rule(s) loaded successfully from {rules_file}")
    except RuleValidationError as e:
        click.echo(f"Validation error: {e}", err=True)
        sys.exit(1)

if __name__ == "__main__":
    cli()
