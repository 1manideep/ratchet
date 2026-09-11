"""ratchet_core.audit — tamper-evident audit logging.

Every Decision from Broker.authorize() is appended to an AuditSink as a
hash-chained entry: entry_hash = sha256(canonical_json({...body, prev_hash})).
Tampering with, reordering, or dropping any entry breaks the chain from
that point forward — detectable by verify_audit_chain() without needing the
broker secret.

Args are hashed by default, not stored raw, to avoid leaking sensitive tool
arguments (file contents, API keys, ...) into the audit log. Pass
`store_raw_args=True` to `build_entry` if you need raw args for debugging
and accept that exposure.
"""

from __future__ import annotations

import hashlib
import json
import time
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64


def _canonical_json(obj: object) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _hash_args(args: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(dict(args)).encode("utf-8")).hexdigest()


def _entry_hash(prev_hash: str, body: Mapping[str, Any]) -> str:
    payload = {**body, "prev_hash": prev_hash}
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class AuditEntry:
    """One hash-chained audit log record."""

    timestamp: float
    delegation_chain: tuple[str, ...]
    tool_name: str
    args_digest: str
    resource: str | None
    decision: str
    reason_code: str
    token_id: str
    prev_hash: str
    entry_hash: str

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "delegation_chain": list(self.delegation_chain),
            "tool_name": self.tool_name,
            "args_digest": self.args_digest,
            "resource": self.resource,
            "decision": self.decision,
            "reason_code": self.reason_code,
            "token_id": self.token_id,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }


def build_entry(
    *,
    prev_hash: str,
    delegation_chain: Sequence[str],
    tool_name: str,
    args: Mapping[str, Any],
    resource: str | None,
    decision: str,
    reason_code: str,
    token_id: str,
    store_raw_args: bool = False,
) -> AuditEntry:
    """Construct the next hash-chained entry given the previous entry's hash."""
    args_digest = _canonical_json(dict(args)) if store_raw_args else _hash_args(args)
    body: dict[str, Any] = {
        "timestamp": time.time(),
        "delegation_chain": list(delegation_chain),
        "tool_name": tool_name,
        "args_digest": args_digest,
        "resource": resource,
        "decision": decision,
        "reason_code": reason_code,
        "token_id": token_id,
    }
    entry_hash = _entry_hash(prev_hash, body)
    return AuditEntry(
        timestamp=body["timestamp"],
        delegation_chain=tuple(delegation_chain),
        tool_name=tool_name,
        args_digest=args_digest,
        resource=resource,
        decision=decision,
        reason_code=reason_code,
        token_id=token_id,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
    )


class AuditSink(ABC):
    """Pluggable audit backend. v0.1 ships only the JSONL file implementation."""

    @abstractmethod
    def last_hash(self) -> str:
        """Return the entry_hash of the most recently appended entry, or the genesis hash."""

    @abstractmethod
    def append(self, entry: AuditEntry) -> None:
        """Append `entry` durably."""


class JsonlAuditSink(AuditSink):
    """Appends each AuditEntry as one JSON line to a file. Resumes the hash
    chain from the last line of an existing file, if present."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            self._path.touch()
        self._last_hash = self._read_last_hash()

    def _read_last_hash(self) -> str:
        last_line: str | None = None
        with self._path.open("r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped:
                    last_line = stripped
        if last_line is None:
            return GENESIS_HASH
        return json.loads(last_line)["entry_hash"]

    def last_hash(self) -> str:
        return self._last_hash

    def append(self, entry: AuditEntry) -> None:
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(_canonical_json(entry.to_canonical_dict()))
            fh.write("\n")
        self._last_hash = entry.entry_hash


def verify_audit_chain(path: str | Path) -> bool:
    """Replay a JSONL audit log and verify every entry_hash matches its recomputed value.

    Returns True if the chain is intact from genesis to the last entry
    (including an empty or missing file), False if any entry is missing,
    reordered, or tampered with.
    """
    prev_hash = GENESIS_HASH
    log_path = Path(path)
    if not log_path.exists():
        return True
    with log_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                record = json.loads(stripped)
            except json.JSONDecodeError:
                return False
            if record.get("prev_hash") != prev_hash:
                return False
            claimed_hash = record.get("entry_hash")
            body = {k: v for k, v in record.items() if k not in ("entry_hash", "prev_hash")}
            if _entry_hash(prev_hash, body) != claimed_hash:
                return False
            prev_hash = claimed_hash
    return True
