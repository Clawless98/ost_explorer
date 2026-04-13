from __future__ import annotations
from pathlib import Path
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, RadioButton, RadioSet
from ost_explorer.models import Message

class ExportDialog(ModalScreen):
    """Modal dialog for export options."""
    CSS = """
    ExportDialog { align: center middle; }
    #export-container { width: 60; height: auto; max-height: 80%; border: solid $primary; background: $surface; padding: 1 2; }
    #export-container Label { margin: 1 0 0 0; }
    #export-path { margin: 1 0; }
    """

    def __init__(self, messages: list[Message], file_path: Path, **kwargs) -> None:
        super().__init__(**kwargs)
        self._messages = messages
        self._file_path = file_path

    def compose(self) -> ComposeResult:
        with Vertical(id="export-container"):
            yield Label("Export Format:")
            with RadioSet(id="format-select"):
                yield RadioButton("JSON", value=True)
                yield RadioButton("CSV")
                yield RadioButton("HTML Report")
            yield Label("Output path:")
            yield Input(value=str(Path.cwd() / f"{self._file_path.stem}_export"), id="export-path")
            yield Button("Export", variant="primary", id="export-btn")
            yield Button("Cancel", id="cancel-btn")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel-btn":
            self.dismiss()
            return
        if event.button.id == "export-btn":
            radio_set = self.query_one("#format-select", RadioSet)
            path_input = self.query_one("#export-path", Input)
            output_base = Path(path_input.value)
            idx = radio_set.pressed_index
            formats = {0: "json", 1: "csv", 2: "html"}
            fmt = formats.get(idx, "json")
            output_path = output_base.with_suffix(f".{fmt}")
            from ost_explorer.engine.export import export_json, export_csv, export_html
            from ost_explorer.engine.scanner import Scanner
            scanner = Scanner()
            findings = scanner.scan_messages(self._messages, folder_path="export")
            if fmt == "json":
                export_json(self._messages, findings, output_path)
            elif fmt == "csv":
                export_csv(self._messages, findings, output_path)
            elif fmt == "html":
                export_html(self._messages, findings, output_path, mailbox_name=self._file_path.name)
            self.dismiss()
            self.app.query_one("#status-bar").update(f"Exported to {output_path}")
