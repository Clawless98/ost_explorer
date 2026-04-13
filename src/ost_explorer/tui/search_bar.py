from __future__ import annotations
from textual.widgets import Input

class SearchBar(Input):
    """Search input with filter syntax support."""
    def __init__(self, **kwargs) -> None:
        super().__init__(
            placeholder="Search: from:user has:attachment keyword date:2025-01..2025-03",
            **kwargs,
        )
