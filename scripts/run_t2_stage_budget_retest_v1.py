"""One authorized, bounded stage-budget diagnostic on two already-seen inputs.

Prepare/check are offline. All historical runs and runners stay immutable.
The provider-side CNY 20 hard cap requires current operator confirmation.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import redirect_stdout
from datetime import datetime, timezone
import getpass
from hashlib import sha256
import io
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import warnings

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import run_t2_context_retest_v2 as previous
from scripts.prepare_t2_quality_review import parse, read_bytes
from vulngym_agent.agents import deepseek_backend as adapter
from vulngym_agent.agents.model_runtime import ModelBlocked

RUN = Path(r"D:\VulnGym-bv2-runtime\t2-stage-budget-retest-20260909-v1")
BASE = Path(r"D:\VulnGym-bv2-runtime\t2-context-retest-20260909-v3-context")
BASE_MANIFEST = "f6d82a48d6cc375a5419755b15c5e3a381aeb3a22be6704b4cd1a2cd7f01ee1c"
RUNTIME_TREE = "8945df9255bbc3f330a48f85e0afc2dd8f7a15bf"
RUNTIME_BASE = "778aa1bc7a8b0c86ac31d023d0c904685874a198"
PROMPT_SHA = "36e7c74a989f5869ae015cee7a01d506181510a11375910a574949585ea3eb12"
DEPENDENCIES = ("scripts/run_t2_stage_budget_retest_v1.py", "scripts/run_t2_context_retest_v2.py",
                "scripts/run_t2_new_input_batch_v1.py", "scripts/prepare_t2_quality_review.py")
SETTINGS = adapter.DeepSeekSettings(timeout_seconds=300, token_budget_profile="t2-balanced-v1")
STAGES = ("plan", "semantic_judge", "reflection")
STAGE_LIMITS = {stage: SETTINGS.max_tokens_for_stage(stage) for stage in STAGES}
TASKS = previous.TASKS
wire, emit, put_new, git = previous.wire, previous.emit, previous.put_new, previous.git
_backend = None


def build_plan():
    raw = read_bytes(BASE / "input-manifest.json")
    if sha256(raw).hexdigest() != BASE_MANIFEST:
        raise ValueError("baseline_manifest_changed")
    if adapter.PROMPT_VERSION != "t2-json-v5" or adapter.PROMPT_SHA256 != PROMPT_SHA:
        raise ValueError("prompt_identity_changed")
    old = parse(raw)
    return {"schema": "t2.stage-budget-diagnostic-plan.v1",
        "sample_group": "seen_input_diagnostic_retest_not_new_input_evaluation",
        "authorization_status": "requires_this_run_confirmation_and_current_key",
        "budget_cny": 20, "max_total_http_requests": 6, "max_llm_calls_per_task": 3,
        "automatic_retries": 0, "max_repair_iterations": 0,
        "required_stage_sequence": list(STAGES), "stage_max_tokens": STAGE_LIMITS,
        "maximum_configured_completion_tokens": 45056, "currency_cost_measured": False,
        "runtime_tree": RUNTIME_TREE, "runtime_base_commit": RUNTIME_BASE,
        "model": SETTINGS.profile(), "baseline_manifest_sha256": BASE_MANIFEST,
        "runner_dependencies_sha256": {n: sha256(read_bytes(ROOT / n)).hexdigest() for n in DEPENDENCIES},
        "input_files": old["input_files"], "cases": old["cases"]}


def prepare():
    if RUN.exists():
        raise ValueError("existing_preparation_preserve")
    plan = build_plan()
    files = {name: previous.checked_input(BASE, name, expected)
             for name, expected in plan["input_files"].items()}
    RUN.mkdir()
    for name, data in files.items():
        path = RUN / "input" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        put_new(path, data)
    put_new(RUN / "input-manifest.json", wire(plan))
    return preflight()


def preflight(*, for_run=False, expected_digest=None):
    raw = read_bytes(RUN / "input-manifest.json")
    digest = sha256(raw).hexdigest()
    if expected_digest is not None and expected_digest != digest:
        raise ValueError("operator_manifest_digest_mismatch")
    plan = parse(raw)
    if wire(plan) != wire(build_plan()):
        raise ValueError("frozen_diagnostic_profile_changed")
    if git("branch", "--show-current").decode().strip() != "codex/b-v2-source-discovery":
        raise ValueError("wrong_branch")
    if git("rev-parse", "HEAD:vulngym_agent").decode().strip() != RUNTIME_TREE:
        raise ValueError("runtime_tree_changed")
    git("diff", "--quiet", "HEAD", "--", "vulngym_agent")
    git("merge-base", "--is-ancestor", RUNTIME_BASE, "HEAD")
    if for_run:
        for name in DEPENDENCIES:
            if git("show", "HEAD:" + name) != read_bytes(ROOT / name):
                raise ValueError("runner_dependency_not_committed")
        if any((RUN / name).exists() for name in (
                "run-start.json", "transport-events.jsonl", "output", "run-exit.json", "cli-stdout.json")):
            raise ValueError("existing_run_preserve_do_not_restart")
    for name, expected in plan["input_files"].items():
        previous.checked_input(RUN, name, expected)
        previous.checked_input(BASE, name, expected)
    from vulngym_agent.closed_loop_cli import iter_task_jsonl, load_trusted_repo_map
    rows = list(iter_task_jsonl(RUN / "input/tasks.jsonl"))
    if len(rows) != 2 or any(r.task is None for r in rows) or tuple(r.task.task_id for r in rows) != TASKS:
        raise ValueError("task_identity_changed")
    repos = load_trusted_repo_map(RUN / "input/repos.json")
    if set(repos) != {case["repo_url"] for case in plan["cases"]}:
        raise ValueError("repository_set_changed")
    for case in plan["cases"]:
        def source(*args):
            result = subprocess.run(["git", "--git-dir=" + str(repos[case["repo_url"]]), *args],
                cwd=ROOT, capture_output=True, timeout=30)
            if result.returncode:
                raise ValueError("fixed_source_read_failed")
            return result.stdout
        if source("show", "-s", "--format=%P", case["fix_commit"]).decode().strip().split() != [case["working_pre_fix_snapshot"]]:
            raise ValueError("source_parent_changed")
        for name, versions in case["source_files"].items():
            for side, revision in (("before", case["working_pre_fix_snapshot"]), ("after", case["fix_commit"])):
                if previous.pin(source("show", revision + ":" + name)) != versions[side]:
                    raise ValueError("fixed_source_changed")
    return {"status": "offline_preflight_passed", "provider_calls": 0,
        "input_manifest_sha256": digest, "runtime_tree": RUNTIME_TREE,
        "prompt_version": adapter.PROMPT_VERSION, "tasks": 2, "max_total_http_requests": 6,
        "budget_cny": 20, "timeout_seconds": 300, "current_run_confirmation_required": True,
        "stage_max_tokens": STAGE_LIMITS, "maximum_configured_completion_tokens": 45056}


class StageBudgetTransport:
    """Actual-wire caps, unique ordered stages, durable intent, no retry."""

    def __init__(self, send, record):
        self.send, self.record = send, record
        self.attempts, self.per_task, self.identities, self.halt = 0, Counter(), set(), None
        self.configured_completion_tokens = 0

    def __call__(self, body, api_key, timeout):
        if self.halt is not None:
            raise ModelBlocked(self.halt)
        try:
            if type(body) is not bytes or len(body) > adapter.MAX_REQUEST_BYTES:
                raise ValueError("invalid_body")
            envelope = parse(body)
            request = parse(envelope["messages"][1]["content"])
            task, stage, call = request["task_id"], request["stage"], request["model_call_id"]
            valid = (envelope["model"] == adapter.MODEL_ID
                and stage in STAGES and task in TASKS
                and type(envelope["max_tokens"]) is int
                and envelope["max_tokens"] == STAGE_LIMITS[stage]
                and envelope["stream"] is False and envelope["reasoning_effort"] == "high"
                and isinstance(call, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", call)
                and type(timeout) in (int, float) and timeout == 300)
        except (ValueError, TypeError, KeyError, IndexError, UnicodeError):
            valid = False
        if not valid:
            raise ModelBlocked("diagnostic_transport_contract_invalid")
        if self.attempts >= 6 or self.per_task[task] >= 3:
            raise ModelBlocked("diagnostic_transport_budget_exceeded")
        if (task, call) in self.identities:
            raise ModelBlocked("diagnostic_duplicate_request_rejected")
        if stage != STAGES[self.per_task[task]]:
            raise ModelBlocked("diagnostic_stage_sequence_invalid")
        requested_cap = envelope["max_tokens"]
        if self.configured_completion_tokens + requested_cap > 45056:
            raise ModelBlocked("diagnostic_transport_budget_exceeded")
        row = {"attempt": self.attempts + 1, "task_id": task, "stage": stage,
            "model_call_id": call, "configured_max_tokens": requested_cap,
            "request_bytes": len(body), "request_body_sha256": sha256(body).hexdigest(),
            "timeout_seconds": timeout, "started_at": datetime.now(timezone.utc).isoformat()}
        try:
            self.record(dict(row, event="started"))
        except Exception:
            self.halt = "diagnostic_telemetry_failed"
            raise ModelBlocked(self.halt) from None
        self.attempts += 1
        self.per_task[task] += 1
        self.identities.add((task, call))
        self.configured_completion_tokens += requested_cap
        started = time.monotonic()
        try:
            response = self.send(body, api_key, timeout)
            row.update(status="http_200", response_bytes=len(response))
            row["usage"] = {}
            try:
                value = parse(response)
                usage = value.get("usage", {})
                row["usage"] = {key: usage[key] for key in
                    ("prompt_tokens", "completion_tokens", "total_tokens",
                     "prompt_cache_hit_tokens", "prompt_cache_miss_tokens")
                    if type(usage.get(key)) is int and 0 <= usage[key] <= 1_000_000_000}
                row["response_model_matches"] = value.get("model") == adapter.MODEL_ID
                choice = value["choices"][0]
                finish = choice.get("finish_reason")
                row["finish_reason"] = finish if finish in ("stop", "length", "content_filter") else "unknown"
                message = choice.get("message", {})
                row["answer_characters"] = len(message["content"]) if isinstance(message.get("content"), str) else None
                row["provider_reasoning_characters"] = len(message["reasoning_content"]) if isinstance(message.get("reasoning_content"), str) else None
            except (ValueError, TypeError, AttributeError, KeyError, IndexError):
                pass
            return response
        except ModelBlocked as error:
            code = error.error_code
            self.halt = code if re.fullmatch(r"deepseek_[a-z_]{1,70}", code) else "diagnostic_transport_failed"
            row.update(status="blocked", error_code=self.halt)
            if isinstance(error, adapter._TransportBlocked):
                info = error.diagnostic
                phase = info.get("phase")
                row["transport_failure"] = {
                    "phase": phase if phase in ("connect", "send", "wait_headers", "response_checks", "read_body") else "unknown",
                    "request_started": info.get("request_started") is True,
                    "usage_and_billing_known": False}
            raise ModelBlocked(self.halt) from None
        except Exception:
            self.halt = "diagnostic_transport_failed"
            row.update(status="error", error_code=self.halt)
            raise ModelBlocked(self.halt) from None
        finally:
            row["elapsed_seconds"] = round(time.monotonic() - started, 3)
            try:
                self.record(dict(row, event="finished"))
            except Exception:
                self.halt = "diagnostic_telemetry_failed"
                raise ModelBlocked(self.halt) from None


def backend_factory():
    if _backend is None:
        raise RuntimeError("backend_not_initialized")
    return _backend


def run(expected_digest):
    global _backend
    checked = preflight(for_run=True, expected_digest=expected_digest)
    put_new(RUN / "run-start.json", wire({"started_at": datetime.now(timezone.utc).isoformat(),
        "execution_head": git("rev-parse", "HEAD").decode().strip(),
        "input_manifest_sha256": checked["input_manifest_sha256"], "budget_cny": 20,
        "platform_hard_cap": "operator_confirmed_not_programmatically_verified"}))
    transport = adapter._post_official
    stdout = io.StringIO()
    key, code, error = None, 2, None
    with (RUN / "transport-events.jsonl").open("xb") as telemetry:
        def record(event):
            telemetry.write(wire(event))
            telemetry.flush()
            os.fsync(telemetry.fileno())
            emit({"event": event["event"], "attempt": event["attempt"], "stage": event["stage"]})
        guard = StageBudgetTransport(transport, record)
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                key = getpass.getpass("Current authorized temporary key (hidden; not stored): ")
            if re.fullmatch(r"sk-[A-Za-z0-9_-]{16,128}", key) is None:
                raise ValueError("credential_format_invalid")
            _backend = adapter.DeepSeekV4ProBackend(api_key=key, settings=SETTINGS)
            key = None
            adapter._post_official = guard
            from vulngym_agent import t2_production_cli
            with redirect_stdout(stdout):
                code = t2_production_cli.main(["--tasks", str(RUN / "input/tasks.jsonl"),
                    "--repo-map", str(RUN / "input/repos.json"), "--package-root", str(RUN / "input/package"),
                    "--backend-factory", "__main__:backend_factory", "--output-dir", str(RUN / "output"),
                    "--max-records", "2", "--max-llm-calls", "3", "--max-tool-calls", "80",
                    "--max-repair-iterations", "0", "--progress"])
        except (Exception, KeyboardInterrupt):
            code, error = 2, "diagnostic_setup_or_run_failed"
        finally:
            key = None
            if _backend is not None:
                _backend._api_key = ""
            _backend = None
            adapter._post_official = transport
    put_new(RUN / "cli-stdout.json", stdout.getvalue().encode("utf-8"))
    result = {"status": "run_finished", "exit_code": code, "transport_attempts": guard.attempts,
        "configured_completion_tokens_attempted": guard.configured_completion_tokens,
        "credential_use_ended": True, "finished_at": datetime.now(timezone.utc).isoformat(),
        "error_code": error, "transport_halt_code": guard.halt,
        "not_new_input_evaluation": True, "currency_cost_measured": False}
    put_new(RUN / "run-exit.json", wire(result))
    emit(result)
    return code


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "check", "run"))
    parser.add_argument("--confirm-paid-retest", action="store_true")
    parser.add_argument("--confirm-platform-cap", action="store_true")
    parser.add_argument("--expected-manifest-sha256")
    args = parser.parse_args(argv)
    if args.action == "run" and (not args.confirm_paid_retest or not args.confirm_platform_cap
            or re.fullmatch(r"[0-9a-f]{64}", args.expected_manifest_sha256 or "") is None):
        emit({"status": "blocked", "code": "fresh_paid_retest_confirmation_required", "provider_calls": 0})
        return 2
    os.environ.update(TEMP=r"D:\VulnGym-bv2-runtime\tmp", TMP=r"D:\VulnGym-bv2-runtime\tmp",
        GIT_NO_LAZY_FETCH="1", GIT_OPTIONAL_LOCKS="0")
    try:
        if args.action == "run":
            return run(args.expected_manifest_sha256)
        emit(prepare() if args.action == "prepare" else preflight())
        return 0
    except (Exception, KeyboardInterrupt):
        emit({"status": "invalid", "code": "diagnostic_preflight_or_io_failed_preserve",
            "provider_calls": 0 if args.action != "run" else "unknown_preserve_telemetry",
            "preserve_existing_files": True})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
