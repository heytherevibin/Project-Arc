"""
Attention Filter

Manages focus priorities for the working memory, filtering irrelevant
observations and tracking what the agent should pay attention to.
In-memory module (no persistence) similar to WorkingMemory.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class AttentionItem:
    """An item the agent should pay attention to."""
    item_id: str
    category: str          # e.g. "host", "vuln", "credential", "technique"
    description: str
    priority: float = 1.0  # higher = more important
    created_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)
    decay_rate: float = 0.05  # priority decay per minute
    metadata: dict[str, Any] = field(default_factory=dict)


class AttentionFilter:
    """
    In-memory attention management for the agent's working memory.

    Features:
    - Focus priorities: what to pay attention to
    - Relevance filtering: should_attend() to gate observations
    - Priority decay: older items gradually lose priority
    - Category-based filtering
    """

    def __init__(self, default_decay_rate: float = 0.05) -> None:
        self._items: dict[str, AttentionItem] = {}
        self._focus_categories: set[str] = set()
        self._default_decay = default_decay_rate

    # ------------------------------------------------------------------
    # Focus management
    # ------------------------------------------------------------------

    def set_focus(
        self,
        item_id: str,
        category: str,
        description: str,
        priority: float = 1.0,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Add or update an attention focus item."""
        if item_id in self._items:
            item = self._items[item_id]
            item.priority = priority
            item.description = description
            item.last_accessed = time.time()
            if metadata:
                item.metadata.update(metadata)
        else:
            self._items[item_id] = AttentionItem(
                item_id=item_id,
                category=category,
                description=description,
                priority=priority,
                decay_rate=self._default_decay,
                metadata=metadata or {},
            )

        self._focus_categories.add(category)
        logger.debug("Focus set", item_id=item_id, category=category, priority=priority)

    def remove_focus(self, item_id: str) -> None:
        """Remove an attention item."""
        self._items.pop(item_id, None)

    def set_category_focus(self, *categories: str) -> None:
        """Set which categories the agent should focus on."""
        self._focus_categories = set(categories)

    def clear_category_focus(self) -> None:
        """Clear category focus (attend to everything)."""
        self._focus_categories.clear()

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def should_attend(
        self,
        category: str,
        priority_threshold: float = 0.2,
    ) -> bool:
        """
        Check if the agent should attend to items in a given category.

        Returns True if:
        - No focus categories are set (attend to all), OR
        - The category is in the focus set, OR
        - There are high-priority items in that category
        """
        if not self._focus_categories:
            return True

        if category in self._focus_categories:
            return True

        # Check if any high-priority items exist in this category
        for item in self._items.values():
            if item.category == category:
                effective = self._effective_priority(item)
                if effective >= priority_threshold:
                    return True

        return False

    def get_priority_items(
        self,
        category: str | None = None,
        min_priority: float = 0.1,
        limit: int = 20,
    ) -> list[AttentionItem]:
        """
        Get attention items sorted by effective priority (descending).

        Optionally filter by category and minimum priority.
        """
        self._apply_decay()

        items = list(self._items.values())
        if category:
            items = [i for i in items if i.category == category]

        items = [i for i in items if self._effective_priority(i) >= min_priority]
        items.sort(key=lambda i: self._effective_priority(i), reverse=True)

        return items[:limit]

    def get_all_categories(self) -> list[str]:
        """Return all categories with active attention items."""
        return list({item.category for item in self._items.values()})

    # ------------------------------------------------------------------
    # Decay
    # ------------------------------------------------------------------

    def decay_attention(self) -> int:
        """
        Apply time-based decay to all attention items.

        Removes items whose effective priority drops below 0.01.
        Returns the number of items removed.
        """
        self._apply_decay()

        to_remove = [
            item_id for item_id, item in self._items.items()
            if self._effective_priority(item) < 0.01
        ]

        for item_id in to_remove:
            del self._items[item_id]

        if to_remove:
            logger.debug("Attention decay removed items", count=len(to_remove))

        return len(to_remove)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _apply_decay(self) -> None:
        """Recompute priorities with time decay."""
        now = time.time()
        for item in self._items.values():
            minutes_elapsed = (now - item.last_accessed) / 60.0
            item.priority = max(0.0, item.priority - (item.decay_rate * minutes_elapsed))
            item.last_accessed = now

    @staticmethod
    def _effective_priority(item: AttentionItem) -> float:
        """Compute effective priority with time decay."""
        now = time.time()
        minutes_elapsed = (now - item.last_accessed) / 60.0
        return max(0.0, item.priority - (item.decay_rate * minutes_elapsed))

    @property
    def size(self) -> int:
        return len(self._items)
