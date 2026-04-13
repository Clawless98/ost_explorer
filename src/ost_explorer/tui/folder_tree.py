from __future__ import annotations
from textual.widgets import Tree
from textual.widgets._tree import TreeNode
from ost_explorer.models import Folder

class FolderTree(Tree):
    """Folder navigation tree pane."""
    def __init__(self, **kwargs) -> None:
        super().__init__("Mailbox", **kwargs)
        self.guide_depth = 3

    def load_folders(self, folders: list[Folder], recovered_count: int = 0) -> None:
        self.clear()
        self.root.expand()
        for folder in folders:
            self._add_folder(self.root, folder)
        if recovered_count > 0:
            node = self.root.add(f"Recovered ({recovered_count})")
            node.data = "__recovered__"
        self.root.expand()

    def _add_folder(self, parent: TreeNode, folder: Folder) -> None:
        label = f"{folder.name} ({folder.message_count})"
        node = parent.add(label)
        node.data = folder
        for child in folder.children:
            self._add_folder(node, child)
