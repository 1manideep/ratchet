"""ratchet_core.revocation — revocation store for capability tokens.

Revoking a root_id invalidates every token descended from it. Revoking an
individual token_id invalidates that token and every token descended from
it, because every descendant carries that token_id in its own `chain`.
Broker.authorize() checks both sets before evaluating any caveats.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable


class RevocationStore(ABC):
    """Pluggable revocation backend. v0.1 ships only the in-memory implementation."""

    @abstractmethod
    def revoke_root(self, root_id: str) -> None:
        """Revoke an entire delegation tree rooted at `root_id`."""

    @abstractmethod
    def revoke_token(self, token_id: str) -> None:
        """Revoke one token and, transitively, every token descended from it."""

    @abstractmethod
    def is_root_revoked(self, root_id: str) -> bool:
        """Return whether `root_id` itself has been revoked."""

    @abstractmethod
    def is_any_token_revoked(self, chain: Iterable[str]) -> bool:
        """Return whether any token_id in `chain` (root to self) has been revoked."""


class InMemoryRevocationStore(RevocationStore):
    """Set-backed revocation store. Not shared across processes; swap in a
    Redis/file-backed implementation of RevocationStore for multi-process use."""

    def __init__(self) -> None:
        self._revoked_roots: set[str] = set()
        self._revoked_tokens: set[str] = set()

    def revoke_root(self, root_id: str) -> None:
        self._revoked_roots.add(root_id)

    def revoke_token(self, token_id: str) -> None:
        self._revoked_tokens.add(token_id)

    def is_root_revoked(self, root_id: str) -> bool:
        return root_id in self._revoked_roots

    def is_any_token_revoked(self, chain: Iterable[str]) -> bool:
        return any(token_id in self._revoked_tokens for token_id in chain)
