"""Bounded output and process-group timeout for untrusted worker commands (Unix)."""
from __future__ import annotations

import os
import signal
import subprocess
import tempfile
from pathlib import Path


class CommandTimeout(Exception):
    pass


class OutputLimit(Exception):
    pass


def run(argv: list[str], *, cwd: Path, env: dict[str, str], timeout: int, max_output: int = 16_000) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        child = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=err, start_new_session=True)
        try:
            child.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
            raise CommandTimeout(f"timeout ({timeout}s): {Path(argv[0]).name}") from exc
        # A background child in the same process group cannot outlive this invocation.
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        def tail(stream):
            stream.seek(0, 2)
            length = stream.tell()
            if length > max_output:
                raise OutputLimit(f"command output exceeded {max_output} bytes: {Path(argv[0]).name}")
            stream.seek(0)
            return stream.read().decode("utf-8", errors="replace")
        return subprocess.CompletedProcess(argv, child.returncode, tail(out), tail(err))
