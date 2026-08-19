"""Strict, JSON-only task contract for the offline T2 producer.

Filesystem roots, repository paths, model files, and credentials deliberately
do not belong to this object.  They are trusted process configuration.  Every
value in ``hints`` is an untrusted search hint and must be re-established by a
deterministic tool before it can enter a formal Entry.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Mapping

from vulngym_agent.evidence import PackageSpec
from vulngym_agent.orchestrator.contracts import RunTask
from vulngym_agent.tools.git import validate_commit_sha, validate_repo_relative_path


_REPO_URL_RE = re.compile(
    r"^https://github\.com/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/"
    r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$"
)
_SYMBOL_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_.$:/-]{0,127}$")
_MAX_FIX_COMMITS = 16
_MAX_SOURCE_PATHS = 64
_MAX_ENTRY_SYMBOLS = 64
_MAX_PACKAGE_FILES = 256
_MAX_PACKAGE_PATH_CHARS = 1024
_MAX_SOURCE_PATH_CHARS = 4096


def _strict_keys(
    value: Mapping[str, Any], *, expected: frozenset[str], name: str
) -> None:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be a JSON object")
    actual = set(value)
    if actual != expected:
        raise ValueError(
            f"{name} keys differ; missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )


def _string_array(
    value: Any,
    *,
    name: str,
    maximum: int,
    allow_empty: bool,
) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"{name} must be an ordered array")
    items = tuple(value)
    if (not allow_empty and not items) or len(items) > maximum:
        qualifier = "one or more" if not allow_empty else "zero or more"
        raise ValueError(
            f"{name} must contain {qualifier} values and at most {maximum}"
        )
    if any(not isinstance(item, str) or not item for item in items):
        raise ValueError(f"{name} must contain non-empty strings")
    if len(items) != len(set(items)):
        raise ValueError(f"{name} must not contain duplicates")
    return items


@dataclass(frozen=True, slots=True)
class T2Hints:
    """Untrusted, bounded discovery hints supplied by the task builder."""

    project: str | None
    fix_commits: tuple[str, ...]
    source_paths: tuple[str, ...]
    entry_symbols: tuple[str, ...]
    critical_mode: str

    def __post_init__(self) -> None:
        if self.project is not None and (
            not isinstance(self.project, str)
            or not self.project
            or self.project != self.project.strip()
            or len(self.project) > 256
            or any(ord(character) < 32 or ord(character) == 127 for character in self.project)
        ):
            raise ValueError(
                "hints.project must be a canonical, bounded string or null"
            )
        fixes = _string_array(
            self.fix_commits,
            name="hints.fix_commits",
            maximum=_MAX_FIX_COMMITS,
            allow_empty=True,
        )
        paths = _string_array(
            self.source_paths,
            name="hints.source_paths",
            maximum=_MAX_SOURCE_PATHS,
            allow_empty=False,
        )
        if any(len(value) > _MAX_SOURCE_PATH_CHARS for value in paths):
            raise ValueError(
                f"hints.source_paths entries must not exceed "
                f"{_MAX_SOURCE_PATH_CHARS} characters"
            )
        symbols = _string_array(
            self.entry_symbols,
            name="hints.entry_symbols",
            maximum=_MAX_ENTRY_SYMBOLS,
            allow_empty=True,
        )
        object.__setattr__(
            self,
            "fix_commits",
            tuple(validate_commit_sha(value) for value in fixes),
        )
        object.__setattr__(
            self,
            "source_paths",
            tuple(validate_repo_relative_path(value) for value in paths),
        )
        if any(_SYMBOL_RE.fullmatch(value) is None for value in symbols):
            raise ValueError("hints.entry_symbols contains an unsafe symbol")
        object.__setattr__(self, "entry_symbols", symbols)
        if self.critical_mode not in {"auto", "sink", "guard"}:
            raise ValueError("hints.critical_mode must be auto, sink, or guard")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "T2Hints":
        _strict_keys(
            value,
            expected=frozenset(
                {
                    "project",
                    "fix_commits",
                    "source_paths",
                    "entry_symbols",
                    "critical_mode",
                }
            ),
            name="T2 hints",
        )
        return cls(
            project=value["project"],
            fix_commits=value["fix_commits"],
            source_paths=value["source_paths"],
            entry_symbols=value["entry_symbols"],
            critical_mode=value["critical_mode"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "project": self.project,
            "fix_commits": list(self.fix_commits),
            "source_paths": list(self.source_paths),
            "entry_symbols": list(self.entry_symbols),
            "critical_mode": self.critical_mode,
        }


@dataclass(frozen=True, slots=True)
class T2TaskInputV1:
    """One fully correlated, path-free input for a real T2 attempt."""

    input_line: int
    repo_url: str
    package: PackageSpec
    hints: T2Hints
    contract_version: int = 1

    def __post_init__(self) -> None:
        if type(self.contract_version) is not int or self.contract_version != 1:
            raise ValueError("contract_version must be integer 1")
        if (
            isinstance(self.input_line, bool)
            or not isinstance(self.input_line, int)
            or self.input_line < 1
        ):
            raise ValueError("input_line must be a positive integer")
        if (
            not isinstance(self.repo_url, str)
            or _REPO_URL_RE.fullmatch(self.repo_url) is None
            or self.repo_url.endswith(".git")
        ):
            raise ValueError(
                "repo_url must be a canonical https://github.com/owner/repo URL"
            )
        if not isinstance(self.package, PackageSpec):
            raise ValueError("package must be a PackageSpec")
        if (
            1 + len(self.package.references) + len(self.package.patches)
            > _MAX_PACKAGE_FILES
        ):
            raise ValueError(
                f"package must declare at most {_MAX_PACKAGE_FILES} files"
            )
        package_paths = (
            self.package.advisory,
            *self.package.references,
            *self.package.patches,
        )
        if any(len(value) > _MAX_PACKAGE_PATH_CHARS for value in package_paths):
            raise ValueError(
                f"package paths must not exceed {_MAX_PACKAGE_PATH_CHARS} characters"
            )
        if not isinstance(self.hints, T2Hints):
            raise ValueError("hints must be T2Hints")

    @classmethod
    def from_task(cls, task: RunTask) -> "T2TaskInputV1":
        if not isinstance(task, RunTask):
            raise ValueError("task must be a RunTask")
        if task.report_id is None or task.entry_id is None:
            raise ValueError("real T2 tasks require report_id and entry_id anchors")
        value = task.inputs
        _strict_keys(
            value,
            expected=frozenset(
                {"contract_version", "input_line", "repo_url", "package", "hints"}
            ),
            name="T2 task inputs",
        )
        package_value = value["package"]
        hints_value = value["hints"]
        if not isinstance(package_value, Mapping):
            raise ValueError("package must be a JSON object")
        if not isinstance(hints_value, Mapping):
            raise ValueError("hints must be a JSON object")
        _strict_keys(
            package_value,
            expected=frozenset({"advisory", "references", "patches"}),
            name="T2 package",
        )
        return cls(
            contract_version=value["contract_version"],
            input_line=value["input_line"],
            repo_url=value["repo_url"],
            package=PackageSpec(
                advisory=package_value.get("advisory"),
                references=package_value.get("references", ()),
                patches=package_value.get("patches", ()),
            ),
            hints=T2Hints.from_dict(hints_value),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "input_line": self.input_line,
            "repo_url": self.repo_url,
            "package": self.package.to_dict(),
            "hints": self.hints.to_dict(),
        }


__all__ = ["T2Hints", "T2TaskInputV1"]
