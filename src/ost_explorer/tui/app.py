from __future__ import annotations
import logging
from pathlib import Path
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Footer, Header, RichLog, Static, Input
from ost_explorer.models import Folder, Message, Severity
from ost_explorer.parser import open_mailbox
from ost_explorer.parser.base import MailboxParser
from ost_explorer.tui.folder_tree import FolderTree

logger = logging.getLogger(__name__)

class OstExplorerApp(App):
    """Interactive PST/OST browser TUI."""

    CSS = """
    #main { height: 1fr; }
    #folder-pane { width: 25; border-right: solid $primary; }
    #message-pane { width: 1fr; }
    #message-list { height: 40%; border-bottom: solid $primary; }
    #message-view { height: 60%; padding: 1; }
    #search-bar { dock: top; display: none; padding: 0 1; }
    #search-bar.visible { display: block; }
    #status-bar { dock: bottom; height: 1; background: $primary-background; color: $text; padding: 0 1; }
    """

    BINDINGS = [
        Binding("slash", "toggle_search", "Search", show=True),
        Binding("s", "run_scan", "Scan", show=True),
        Binding("e", "show_export", "Export", show=True),
        Binding("a", "extract_attachment", "Save Att", show=True),
        Binding("shift+a", "extract_all_attachments", "Save All"),
        Binding("f", "flag_message", "Flag", show=True),
        Binding("t", "toggle_html", "HTML", show=True),
        Binding("n", "next_message", "Next"),
        Binding("p", "prev_message", "Prev"),
        Binding("f1", "focus_folders", "Folders"),
        Binding("f2", "focus_messages", "Messages"),
        Binding("f3", "focus_viewer", "Viewer"),
        Binding("question_mark", "show_help", "Help", show=True),
        Binding("q", "quit", "Quit", show=True),
    ]

    def __init__(self, file_path: Path, **kwargs) -> None:
        super().__init__(**kwargs)
        self._file_path = file_path
        self._parser: MailboxParser | None = None
        self._current_folder: Folder | None = None
        self._current_messages: list[Message] = []
        self._current_message: Message | None = None
        self._show_html = False
        self._recovered_messages: list[Message] = []

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="main"):
            yield FolderTree(id="folder-pane")
            with Vertical(id="message-pane"):
                yield DataTable(id="message-list")
                yield RichLog(id="message-view", wrap=True, markup=True)
        yield Input(placeholder="Search: type query and press Enter (e.g. from:ceo has:attachment)", id="search-bar")
        yield Static("", id="status-bar")
        yield Footer()

    def on_mount(self) -> None:
        self.title = f"ost_explorer — {self._file_path.name}"
        table = self.query_one("#message-list", DataTable)
        table.add_columns("*", "From", "Subject", "Date", "Att")
        table.cursor_type = "row"
        try:
            mailbox, self._parser = open_mailbox(self._file_path)
            tree = self.query_one("#folder-pane", FolderTree)
            recovered = self._parser.get_recovered_messages()
            self._recovered_messages = recovered
            tree.load_folders(mailbox.folders, recovered_count=len(recovered))
            self._update_status(f"{self._file_path.name} | {mailbox.format_type} | {mailbox.total_messages} messages")
        except Exception as e:
            self._update_status(f"Error: {e}")

    def on_tree_node_selected(self, event: FolderTree.NodeSelected) -> None:
        node = event.node
        if node.data is None:
            return
        if node.data == "__recovered__":
            self._current_folder = None
            self._current_messages = self._recovered_messages
            self._populate_message_list(self._current_messages)
            self._update_status(f"Recovered items | {len(self._recovered_messages)} messages")
            return
        if isinstance(node.data, Folder) and self._parser:
            folder = node.data
            self._current_folder = folder
            messages = self._parser.get_messages(folder, offset=0, limit=50)
            self._current_messages = messages
            self._populate_message_list(messages)
            self._update_status(f"{self._file_path.name} | {folder.name} | {folder.message_count} messages")

    def _populate_message_list(self, messages: list[Message]) -> None:
        table = self.query_one("#message-list", DataTable)
        table.clear()
        for msg in messages:
            flag = "*" if msg.is_flagged else " "
            date_str = msg.date.strftime("%Y-%m-%d") if msg.date else ""
            att_str = str(len(msg.attachments)) if msg.attachments else ""
            sender = (msg.sender or "")[:25]
            subject = (msg.subject or "")[:40]
            table.add_row(flag, sender, subject, date_str, att_str)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        idx = event.cursor_row
        if 0 <= idx < len(self._current_messages):
            self._current_message = self._current_messages[idx]
            self._display_message(self._current_message)

    def _display_message(self, msg: Message) -> None:
        viewer = self.query_one("#message-view", RichLog)
        viewer.clear()
        viewer.write(f"[bold]From:[/bold] {msg.sender}")
        viewer.write(f"[bold]To:[/bold] {', '.join(msg.recipients_to)}")
        if msg.recipients_cc:
            viewer.write(f"[bold]Cc:[/bold] {', '.join(msg.recipients_cc)}")
        viewer.write(f"[bold]Subject:[/bold] {msg.subject}")
        viewer.write(f"[bold]Date:[/bold] {msg.date}")
        if msg.attachments:
            att_names = [f"[{a.filename}]" for a in msg.attachments]
            viewer.write(f"[bold]Attachments:[/bold] {' '.join(att_names)}")
        viewer.write("─" * 60)
        if self._show_html and msg.body_html:
            viewer.write(msg.body_html)
        else:
            body = msg.body_plain or msg.body_html or "(no body)"
            viewer.write(self._highlight_findings(body))

    def _highlight_findings(self, text: str) -> str:
        from ost_explorer.engine.scanner import Scanner
        if not self._current_message:
            return text
        scanner = Scanner()
        findings = scanner.scan_message(
            self._current_message,
            folder_path=self._current_folder.name if self._current_folder else ""
        )
        for finding in sorted(findings, key=lambda f: len(f.matched_text), reverse=True):
            if finding.matched_text in text:
                color = {
                    Severity.CRITICAL: "red", Severity.HIGH: "yellow",
                    Severity.MEDIUM: "cyan", Severity.LOW: "dim",
                }.get(finding.severity, "white")
                text = text.replace(
                    finding.matched_text,
                    f"[bold {color}]{finding.matched_text}[/bold {color}]", 1,
                )
        return text

    def _update_status(self, text: str) -> None:
        self.query_one("#status-bar", Static).update(text)

    def action_toggle_search(self) -> None:
        search = self.query_one("#search-bar", Input)
        if search.has_class("visible"):
            search.remove_class("visible")
        else:
            search.add_class("visible")
            search.focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "search-bar":
            query_str = event.value
            event.input.remove_class("visible")
            if not query_str.strip():
                return
            from ost_explorer.engine.search import parse_query, search_messages
            query = parse_query(query_str)
            results = search_messages(self._current_messages, query)
            self._current_messages = results
            self._populate_message_list(results)
            self._update_status(f"Search: '{query_str}' | {len(results)} results")

    def action_run_scan(self) -> None:
        if not self._current_messages:
            return
        from ost_explorer.engine.scanner import Scanner
        scanner = Scanner()
        folder_name = self._current_folder.name if self._current_folder else "Recovered"
        findings = scanner.scan_messages(self._current_messages, folder_path=folder_name)
        viewer = self.query_one("#message-view", RichLog)
        viewer.clear()
        viewer.write(f"[bold]Scan Results — {len(findings)} findings[/bold]\n")
        for f in findings:
            color = {"critical": "red", "high": "yellow", "medium": "cyan", "low": "dim"}.get(f.severity.name.lower(), "white")
            viewer.write(f"[{color}][{f.severity.name}][/{color}] {f.rule_name}: {f.matched_text}\n  Message: {f.message_subject} ({f.message_sender})\n")

    def action_show_export(self) -> None:
        from ost_explorer.tui.export_dialog import ExportDialog
        self.push_screen(ExportDialog(self._current_messages, self._file_path))

    def action_extract_attachment(self) -> None:
        if not self._current_message or not self._current_message.attachments:
            return
        att = self._current_message.attachments[0]
        out_path = Path.cwd() / att.filename
        out_path.write_bytes(att.extract_bytes())
        self._update_status(f"Saved: {out_path}")

    def action_extract_all_attachments(self) -> None:
        if not self._current_message:
            return
        count = 0
        for att in self._current_message.attachments:
            (Path.cwd() / att.filename).write_bytes(att.extract_bytes())
            count += 1
        self._update_status(f"Saved {count} attachments to {Path.cwd()}")

    def action_flag_message(self) -> None:
        if self._current_message:
            self._current_message.is_flagged = not self._current_message.is_flagged
            self._populate_message_list(self._current_messages)

    def action_toggle_html(self) -> None:
        self._show_html = not self._show_html
        if self._current_message:
            self._display_message(self._current_message)

    def action_next_message(self) -> None:
        if not self._current_messages or not self._current_message:
            return
        try:
            idx = self._current_messages.index(self._current_message)
            if idx + 1 < len(self._current_messages):
                self._current_message = self._current_messages[idx + 1]
                self._display_message(self._current_message)
                self.query_one("#message-list", DataTable).move_cursor(row=idx + 1)
        except ValueError:
            pass

    def action_prev_message(self) -> None:
        if not self._current_messages or not self._current_message:
            return
        try:
            idx = self._current_messages.index(self._current_message)
            if idx > 0:
                self._current_message = self._current_messages[idx - 1]
                self._display_message(self._current_message)
                self.query_one("#message-list", DataTable).move_cursor(row=idx - 1)
        except ValueError:
            pass

    def action_focus_folders(self) -> None:
        self.query_one("#folder-pane").focus()

    def action_focus_messages(self) -> None:
        self.query_one("#message-list").focus()

    def action_focus_viewer(self) -> None:
        self.query_one("#message-view").focus()

    def action_show_help(self) -> None:
        viewer = self.query_one("#message-view", RichLog)
        viewer.clear()
        viewer.write("[bold]Keybindings[/bold]\n")
        viewer.write("F1/F2/F3  — Focus folder tree / message list / viewer")
        viewer.write("/         — Search (filter syntax: from: to: has:attachment filename: date: folder:)")
        viewer.write("s         — Run scanner on current folder")
        viewer.write("e         — Export dialog")
        viewer.write("a         — Extract selected attachment")
        viewer.write("A         — Extract all attachments from current message")
        viewer.write("f         — Flag/unflag message")
        viewer.write("t         — Toggle HTML/plain text view")
        viewer.write("n/p       — Next/previous message")
        viewer.write("?         — This help")
        viewer.write("q         — Quit")

    def on_unmount(self) -> None:
        if self._parser:
            self._parser.close()
