"""Untrusted input and durable fact schemas. No agent prose is verification evidence."""
from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import Version


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Alert(Strict):
    schema_version: Literal[1] = 1
    repository: str = Field(min_length=1, max_length=200)
    number: int = Field(gt=0)
    package: str = Field(min_length=1, max_length=150)
    advisory_ids: list[str] = Field(min_length=1, max_length=20)
    affected_range: str = Field(min_length=1, max_length=200)
    patched_versions: list[str] = Field(min_length=1, max_length=20)
    manifest: Literal["pyproject.toml"] = "pyproject.toml"

    @field_validator("package")
    @classmethod
    def normalize_package(cls, value: str) -> str:
        if not value.replace("-", "").replace("_", "").replace(".", "").isalnum():
            raise ValueError("invalid package name")
        return canonicalize_name(value)

    @field_validator("affected_range")
    @classmethod
    def valid_range(cls, value: str) -> str:
        SpecifierSet(value)
        return value

    @field_validator("patched_versions")
    @classmethod
    def valid_versions(cls, value: list[str]) -> list[str]:
        for version in value:
            Version(version)
        return value


class Check(Strict):
    id: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,39}$")
    argv: list[str] = Field(min_length=1, max_length=30)
    timeout_seconds: int = Field(ge=1, le=900)


class Policy(Strict):
    schema_version: Literal[1] = 1
    repository: str
    python_version: str
    package_index: Literal["https://pypi.org/simple"] = "https://pypi.org/simple"
    dependency_groups: list[str] = Field(default_factory=list)
    extras: list[str] = Field(default_factory=list)
    max_agent_attempts: int = Field(default=3, ge=1, le=3)
    agent_timeout_seconds: int = Field(default=300, ge=5, le=600)
    run_timeout_seconds: int = Field(default=1800, ge=10, le=3600)
    max_changed_files: int = Field(default=10, ge=1, le=50)
    max_changed_lines: int = Field(default=500, ge=1, le=5000)
    max_dependency_version_changes: int = Field(default=10, ge=1, le=50)
    allow_major_upgrades: Literal[False] = False
    allowed_edit_paths: list[str] = Field(default_factory=lambda: ["pyproject.toml", "uv.lock", "src/**"])
    publication_enabled: Literal[False] = False
    required_checks: list[Check] = Field(min_length=1, max_length=10)

    @field_validator("python_version")
    @classmethod
    def pin_python(cls, value: str) -> str:
        version = Version(value)
        if len(version.release) != 3 or version.is_prerelease:
            raise ValueError("pin exact Python patch version")
        return value

    @field_validator("dependency_groups", "extras")
    @classmethod
    def unique_selections(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)) or len(value) > 10:
            raise ValueError("selections must be unique and bounded")
        return value


class Status(StrEnum):
    BASELINE = "baseline"
    AGENT_RUNNING = "agent_running"
    CANDIDATE = "candidate"
    VERIFYING = "verifying"
    VERIFIED = "verified"
    BLOCKED = "blocked"
    EXHAUSTED = "exhausted"
    INTERRUPTED = "interrupted"
    INFRASTRUCTURE_ERROR = "infrastructure_error"
    CONFLICT = "conflict"


class OperationState(Strict):
    schema_version: Literal[1] = 1
    revision: int = Field(default=0, ge=0)
    operation_id: str
    base_sha: str
    alert_digest: str
    policy_digest: str
    skill_digest: str = ""
    attempts: int = Field(default=0, ge=0, le=3)
    status: Status = Status.BASELINE
    candidate_digest: str | None = None
    failure: str = Field(default="", max_length=500)
    new_operation_reason: str = Field(default="", max_length=300)


class CheckResult(Strict):
    id: str
    phase: Literal["baseline", "candidate"]
    status: Literal["passed", "failed", "error", "timed_out", "not_run"]
    command: list[str] = Field(default_factory=list)
    exit_code: int | None = None
    detail: str = Field(default="", max_length=1000)


class Verification(Strict):
    schema_version: Literal[1] = 1
    candidate_digest: str
    base_sha: str
    policy_digest: str
    python_version: str
    platform: str = ""
    uv_version: str
    scanner: str
    scanner_timestamp: str = ""
    runner_version: str = "0.1.0"
    skill_sha256: str = ""
    baseline_findings: list[str] = Field(default_factory=list)
    candidate_findings: list[str] = Field(default_factory=list)
    checks: list[CheckResult]
    target_resolved: bool
    verified: bool


class RunResult(Strict):
    schema_version: Literal[1] = 1
    operation_id: str
    outcome: Status
    reason: str
    attempts: int
    candidate_digest: str | None = None
    verification: str | None = None
    patch: str | None = None
