"""One concrete pi CLI subprocess. No model selection or provider credentials here."""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import tempfile
from pathlib import Path

from .contracts import Alert, Policy

EXPECTED_PI = "0.99.1"


class HarnessError(Exception):
    pass


def invoke(work: Path, alert: Alert, policy: Policy, skill: Path, failure: str, env: dict[str, str]) -> dict:
    pi = shutil.which("pi")
    if not pi:
        raise HarnessError("pi executable not installed")
    version = subprocess.run([pi, "--version"], text=True, capture_output=True, check=True).stdout.strip()
    if version != EXPECTED_PI:
        raise HarnessError(f"expected pi {EXPECTED_PI}, found {version}")
    prompt = (
        "/skill:vulnerability-remediation\n"
        f"Alert: {alert.model_dump_json()}\n"
        f"Edit ONLY permitted dependency fields or src files; do not edit tests, uv.lock, or settings. "
        f"A runner will regenerate uv.lock and independently verify your edits. "
        f"Previous failure: {failure[:300]}. "
        "Respond with a single JSON object with assessment and plan strings (each <=500 chars). "
        "If you cannot fix this safely, explain why and do not edit files."
    )
    args = [pi, "--mode", "json", "--no-session", "--no-context-files", "--no-extensions", "--no-skills", "--skill", str(skill), "--no-approve", "--tools", "read,bash,edit,write", "--", prompt]
    # Temporary logs are outside the worker. JSON is event telemetry, not a schema-constrained model result.
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(args, cwd=work, env=env, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True)
        try:
            process.wait(timeout=policy.agent_timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise HarnessError("pi timed out; process group killed") from exc
        # Pi may have started background shell children; do not leave them running.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout.seek(0, 2)
        if stdout.tell() > 12_000_000:
            raise HarnessError("pi event output exceeded limit")
        stdout.seek(0)
        settled = False
        last_text = ""
        error = ""
        for line in stdout:
            try:
                event = json.loads(line)
            except ValueError as exc:
                raise HarnessError("malformed pi JSONL event") from exc
            if event.get("type") == "agent_settled":
                settled = True
            if event.get("type") == "message_end" and event.get("message", {}).get("role") == "assistant":
                message = event["message"]
                if message.get("stopReason") in {"error", "aborted", "length"}:
                    error = message.get("errorMessage", message["stopReason"])[:300]
                text = "".join(block.get("text", "") for block in message.get("content", []) if block.get("type") == "text")
                if text:
                    last_text = text
        if process.returncode or not settled or error:
            raise HarnessError(f"pi failed: {error or 'incomplete/exit failure'}")
        try:
            result = json.loads(last_text)
        except ValueError as exc:
            raise HarnessError("pi returned no valid assessment/plan JSON") from exc
        if not isinstance(result, dict) or set(result) != {"assessment", "plan"} or any(not isinstance(result[k], str) or len(result[k]) > 500 for k in result):
            raise HarnessError("pi assessment/plan schema invalid")
        return result
