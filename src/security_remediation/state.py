"""Local durable ledger; one process per operation via flock (Unix-only)."""
from __future__ import annotations

import fcntl
import json
import os
from contextlib import contextmanager
from pathlib import Path

from .contracts import OperationState, Status


class Conflict(Exception):
    pass


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    with temp.open("wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)
    _fsync_dir(path.parent)


def atomic_json(path: Path, value: object) -> None:
    atomic_bytes(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())


class Store:
    def __init__(self, root: Path, operation_id: str):
        self.root = root / "operations" / operation_id
        self.file = self.root / "state.json"
        self.events = self.root / "events.jsonl"

    @contextmanager
    def lock(self):
        self.root.mkdir(parents=True, exist_ok=True)
        with (self.root / ".lock").open("a+b") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            try:
                yield self
            finally:
                fcntl.flock(stream, fcntl.LOCK_UN)

    def load(self) -> OperationState | None:
        if not self.file.exists():
            if any(p.name != ".lock" for p in self.root.iterdir()):
                raise Conflict("operation data exists without a valid state ledger")
            return None
        try:
            return OperationState.model_validate_json(self.file.read_bytes())
        except (ValueError, OSError) as exc:
            raise Conflict("corrupt operation state") from exc

    def save(self, state: OperationState, *, reason: str) -> OperationState:
        old = self.load()
        if old is not None and (old.revision != state.revision or state.attempts < old.attempts):
            raise Conflict("revision or attempt ledger conflict")
        if old is None and state.revision != 0:
            raise Conflict("missing initial ledger")
        updated = state.model_copy(update={"revision": state.revision + 1})
        atomic_json(self.file, updated.model_dump(mode="json"))
        with self.events.open("ab") as stream:
            stream.write((json.dumps({"revision": updated.revision, "status": updated.status, "attempts": updated.attempts, "reason": reason[:300]}) + "\n").encode())
            stream.flush()
            os.fsync(stream.fileno())
        return updated

    def reserve(self, state: OperationState, limit: int) -> OperationState:
        if state.attempts >= limit:
            return self.save(state.model_copy(update={"status": Status.EXHAUSTED}), reason="budget exhausted")
        return self.save(state.model_copy(update={"attempts": state.attempts + 1, "status": Status.AGENT_RUNNING}), reason="agent invocation reserved")
