"""Simple local T2 results, separate from the internal finalized-only replay.

These files contain candidate source snippets and actual T1 evidence. They are
for the operator, not a credential-free public metadata export. No raw prompts,
model responses, provider exceptions, or tool call payloads are copied here.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import json
from pathlib import Path
from typing import Any

from vulngym_agent.orchestrator import ClosedLoopOutcome


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


def _json(value: Any) -> str:
    return json.dumps(_plain(value), ensure_ascii=False, allow_nan=False,
                      sort_keys=True, separators=(",", ":")) + "\n"


class T2UserResults:
    """Incrementally retain accepted terminal candidates, even without T1.

    A running/interrupted summary is deliberately not an all-or-nothing
    publication claim. Existing result directories are never reused.
    """

    def __init__(self, directory: Path, *, protected_paths: Sequence[Path]) -> None:
        requested = Path(directory)
        if not requested.is_absolute():
            raise ValueError("results_dir must be absolute")
        if requested.exists() or requested.is_symlink():
            raise ValueError("results_dir already exists")
        self.directory = requested.parent.resolve(strict=True) / requested.name
        for item in protected_paths:
            other = Path(item).resolve()
            if (self.directory == other or self.directory in other.parents
                    or other in self.directory.parents):
                raise ValueError("results_dir overlaps an input or replay directory")
        self.directory.mkdir(exist_ok=False)
        self._streams: dict[str, Any] = {}
        self.failed = False
        self._summary: dict[str, Any] = {
            "status": "running", "candidate_count": 0, "validation_count": 0,
            "deferred_count": 0, "unreviewed_candidate_count": 0,
            "machine_verify": 0, "independent_human_review_completed": False,
            "tasks": [],
        }
        try:
            for name in ("entries", "validation", "deferred"):
                self._streams[name] = (self.directory / f"{name}.jsonl").open(
                    "x", encoding="utf-8", newline="\n")
            with (self.directory / "summary.json").open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(_json(self._summary))
        except BaseException:
            self.close()
            raise

    def check_writable(self) -> None:
        if self.failed or not self._streams:
            raise OSError("T2 result output is unavailable")

    def record(self, outcome: ClosedLoopOutcome) -> None:
        self.check_writable()
        task_id = outcome.state.task.task_id
        row: dict[str, Any] = {
            "task_id": task_id, "workflow_status": outcome.status,
            "stop_reason": outcome.state.stop_reason,
            "entry_line": None, "validation_line": None, "deferred_line": None,
            "review_status": "no_candidate",
        }
        try:
            # The terminal accepted candidate is authoritative; the final
            # production sidecar might instead be a rejected repair attempt.
            if outcome.entry is not None:
                if type(outcome.entry["verify"]) is not int or outcome.entry["verify"] != 0:
                    raise ValueError("machine candidate verify must be zero")
                self._streams["entries"].write(_json(outcome.entry))
                self._summary["candidate_count"] += 1
                row["entry_line"] = self._summary["candidate_count"]
                row["review_status"] = "unreviewed" if outcome.report is None else "t1_" + outcome.report.verdict
                self._summary["unreviewed_candidate_count"] += int(outcome.report is None)
            if outcome.report is not None:
                self._streams["validation"].write(_json(outcome.report.to_dict()))
                self._summary["validation_count"] += 1
                row["validation_line"] = self._summary["validation_count"]
            deferred = outcome.deferred_outcome
            if deferred is not None:
                missing: list[str] = []
                model_reason: dict[str, Any] | None = None
                for message in deferred.missing_information:
                    if message.startswith("model_defer_details:"):
                        # Keep the bounded reason/field labels, not the raw
                        # structured model explanation or evidence payloads.
                        details = json.loads(message.split(":", 1)[1])
                        model_reason = {key: details[key] for key in
                                        ("reason_code", "missing_fields") if key in details}
                    else:
                        missing.append(message)
                self._streams["deferred"].write(_json({
                    "task_id": task_id, "stage": deferred.stage,
                    "reason_code": deferred.reason_code,
                    "missing_information": missing, "model_reason": model_reason,
                }))
                self._summary["deferred_count"] += 1
                row["deferred_line"] = self._summary["deferred_count"]
            for stream in self._streams.values():
                stream.flush()
            self._summary["tasks"].append(row)
            self._save_summary()
        except BaseException:
            self.failed = True
            raise

    def _save_summary(self) -> None:
        with (self.directory / "summary.json").open("w", encoding="utf-8", newline="\n") as stream:
            stream.write(_json(self._summary))

    def finish(self, batch: Mapping[str, Any]) -> None:
        self.check_writable()
        self._summary.update(status="completed", batch_exit_code=batch["exit_code"],
            execution_status=batch["execution_status"],
            input_failures=batch["input_failures"], failed_tasks=batch["failed"],
            backend_id=batch["backend_id"], model_id=batch["model_id"])
        self._save_summary()
        self.close()

    def abort(self) -> None:
        self._summary["status"] = "interrupted"
        try:
            self._save_summary()
        except OSError:
            pass
        finally:
            self.close()

    def close(self) -> None:
        for stream in self._streams.values():
            stream.close()
        self._streams.clear()
