"""Prepare/check offline; run a separately authorized two-case diagnostic once.

The original two inputs are already seen, not a new-input evaluation. This
version selects the existing 300-second transport deadline explicitly, without
changing production defaults, prompts or historical runners. No automatic retry.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import redirect_stdout
from datetime import datetime, timezone
import getpass
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import warnings

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import run_t2_new_input_batch_v1 as original
from scripts.prepare_t2_quality_review import parse, read_bytes
from vulngym_agent.agents import deepseek_backend as adapter
from vulngym_agent.agents.model_runtime import ModelBlocked

RUN = Path(r"D:\VulnGym-bv2-runtime\t2-context-retest-20260909-v2-longwait")
BASE = Path(r"D:\VulnGym-bv2-runtime\t2-context-retest-20260909-v1")
BASE_MANIFEST = "7332b4ef71d6c5a96f5f0252d626f0c623a05d106515a5d3333d6e0757f1b54f"
RUNTIME_TREE = "5d8cfbc7f0bc0c50190310a25d56f6524375251e"
RUNTIME_BASE = "1f48e5ed937596dc5ad1995a30eaf50f8f58f7ac"
TASKS = original.TASKS
SETTINGS = adapter.DeepSeekSettings(timeout_seconds=300)
wire, emit, put_new, git = original.wire, original.emit, original.put_new, original.git
_backend = None


def pin(raw):
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}


def checked_input(base, name, expected):
    if name not in {"tasks.jsonl", "repos.json"} and not re.fullmatch(
            r"package/(?:advisory|patch)-GHSA-[A-Z0-9-]+\.(?:json|diff)", name):
        raise ValueError("unexpected_input_name")
    raw = read_bytes(base / "input" / name)
    if len(raw) > adapter.MAX_REQUEST_BYTES or pin(raw) != expected:
        raise ValueError("input_file_changed")
    return raw


def prepare():
    if RUN.exists():
        raise ValueError("existing_preparation_preserve")
    raw = read_bytes(BASE / "input-manifest.json")
    if sha256(raw).hexdigest() != BASE_MANIFEST:
        raise ValueError("baseline_manifest_changed")
    old = parse(raw)
    files = {name: checked_input(BASE, name, expected) for name, expected in old["input_files"].items()}
    # Local inputs may include approved repository paths; this file is not public evidence.
    plan = {"schema": "t2.longwait-diagnostic-plan.v2",
        "sample_group": "seen_input_diagnostic_retest_not_new_input_evaluation",
        "authorization_status": "pending_fresh_key_and_explicit_operator_confirmation",
        "proposed_budget_cny": 20, "max_total_http_requests": 6,
        "max_llm_calls_per_task": 3, "automatic_retries": 0, "max_repair_iterations": 0,
        "runtime_tree": RUNTIME_TREE, "runtime_base_commit": RUNTIME_BASE,
        "model": SETTINGS.profile(), "baseline_manifest_sha256": BASE_MANIFEST,
        "runner_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
        "shared_runner_sha256": sha256(Path(original.__file__).read_bytes()).hexdigest(),
        "input_files": old["input_files"], "cases": old["cases"]}
    RUN.mkdir()
    for name, data in files.items():
        path = RUN / "input" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        put_new(path, data)
    put_new(RUN / "input-manifest.json", wire(plan))
    return preflight()


def preflight(*, for_run=False, expected_digest=None):
    raw = read_bytes(RUN / "input-manifest.json")
    plan = parse(raw)
    digest = sha256(raw).hexdigest()
    if expected_digest is not None and digest != expected_digest:
        raise ValueError("operator_manifest_digest_mismatch")
    fixed = {"schema": "t2.longwait-diagnostic-plan.v2",
        "sample_group": "seen_input_diagnostic_retest_not_new_input_evaluation",
        "authorization_status": "pending_fresh_key_and_explicit_operator_confirmation",
        "proposed_budget_cny": 20, "max_total_http_requests": 6,
        "max_llm_calls_per_task": 3, "automatic_retries": 0, "max_repair_iterations": 0,
        "runtime_tree": RUNTIME_TREE, "runtime_base_commit": RUNTIME_BASE,
        "model": SETTINGS.profile(), "baseline_manifest_sha256": BASE_MANIFEST,
        "runner_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
        "shared_runner_sha256": sha256(Path(original.__file__).read_bytes()).hexdigest()}
    if any(type(plan.get(k)) is not type(v) or plan[k] != v for k, v in fixed.items()):
        raise ValueError("frozen_diagnostic_profile_changed")
    baseline = read_bytes(BASE / "input-manifest.json")
    if sha256(baseline).hexdigest() != BASE_MANIFEST:
        raise ValueError("baseline_manifest_changed")
    old = parse(baseline)
    if plan["input_files"] != old["input_files"] or plan["cases"] != old["cases"]:
        raise ValueError("diagnostic_input_selection_changed")
    if git("branch", "--show-current").decode().strip() != "codex/b-v2-source-discovery":
        raise ValueError("wrong_branch")
    if git("rev-parse", "HEAD:vulngym_agent").decode().strip() != RUNTIME_TREE:
        raise ValueError("runtime_tree_changed")
    git("diff", "--quiet", "HEAD", "--", "vulngym_agent")
    git("merge-base", "--is-ancestor", RUNTIME_BASE, "HEAD")
    if for_run:
        for name in ("scripts/run_t2_context_retest_v2.py", "scripts/run_t2_new_input_batch_v1.py",
                     "scripts/prepare_t2_quality_review.py"):
            if git("show", "HEAD:" + name) != (ROOT / name).read_bytes():
                raise ValueError("runner_dependency_not_committed")
    for name, expected in plan["input_files"].items():
        checked_input(RUN, name, expected)
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
                if pin(source("show", revision + ":" + name)) != versions[side]:
                    raise ValueError("fixed_source_changed")
    if for_run and any((RUN / name).exists() for name in (
            "run-start.json", "transport-events.jsonl", "output", "run-exit.json", "cli-stdout.json")):
        raise ValueError("existing_run_preserve_do_not_restart")
    return {"status": "offline_preflight_passed", "provider_calls": 0,
        "input_manifest_sha256": digest, "tasks": 2, "timeout_seconds": 300,
        "max_total_http_requests": 6, "proposed_budget_cny": 20,
        "authorization_status": "pending_fresh_key_and_explicit_operator_confirmation"}


class BoundedTransport:
    """Six attempted sends, three per task, durable intent, no automatic retry."""
    def __init__(self, send, record):
        self.send, self.record = send, record
        self.attempts, self.per_task, self.identities, self.halt = 0, Counter(), set(), None

    def __call__(self, body, api_key, timeout):
        if self.halt is not None:
            raise ModelBlocked(self.halt)
        try:
            envelope = parse(body)
            request = parse(envelope["messages"][1]["content"])
            task, stage, call = request["task_id"], request["stage"], request["model_call_id"]
            valid = (type(body) is bytes and len(body) <= adapter.MAX_REQUEST_BYTES
                and envelope["model"] == adapter.MODEL_ID and type(envelope["max_tokens"]) is int
                and envelope["max_tokens"] == 8192 and envelope["stream"] is False
                and task in TASKS and stage in {"plan", "semantic_judge", "reflection"}
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
        row = {"attempt": self.attempts + 1, "task_id": task, "stage": stage,
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
        start = time.monotonic()
        try:
            response = self.send(body, api_key, timeout)
            row.update(status="http_200", response_bytes=len(response))
            try:
                value = parse(response)
                usage = value.get("usage", {})
                row["usage"] = {key: usage[key] for key in ("prompt_tokens", "completion_tokens", "total_tokens",
                    "prompt_cache_hit_tokens", "prompt_cache_miss_tokens") if type(usage.get(key)) is int and usage[key] >= 0}
            except (ValueError, TypeError, AttributeError):
                row["usage"] = {}
            return response
        except ModelBlocked as error:
            code = error.error_code
            self.halt = code if re.fullmatch(r"deepseek_[a-z_]{1,70}", code) else "diagnostic_transport_failed"
            row.update(status="blocked", error_code=self.halt)
            # Carry only the adapter's bounded metadata, never raw error text.
            if isinstance(error, adapter._TransportBlocked):
                info = error.diagnostic
                phase = info.get("phase")
                row["transport_failure"] = {
                    "phase": phase if phase in {"connect", "send", "wait_headers", "response_checks", "read_body"} else "unknown",
                    "request_started": info.get("request_started") is True,
                    "usage_and_billing_known": False}
            raise ModelBlocked(self.halt) from None
        except Exception:
            self.halt = "diagnostic_transport_failed"
            row.update(status="error", error_code=self.halt)
            raise ModelBlocked(self.halt) from None
        finally:
            row["elapsed_seconds"] = round(time.monotonic() - start, 3)
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
        guard = BoundedTransport(transport, record)
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                key = getpass.getpass("Fresh temporary key (hidden; not stored): ")
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
        emit({"status": "blocked", "code": "fresh_paid_retest_confirmation_required",
            "provider_calls": 0, "run_started": False})
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
