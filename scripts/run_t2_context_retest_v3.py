"""One separately authorized v5 diagnostic on the same two frozen inputs.

Prepare/check are offline. The v2 runner and every historical run stay intact;
only its tested six-request transport guard and serialization helpers are reused.
"""
from __future__ import annotations

import argparse
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
import warnings

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import run_t2_context_retest_v2 as previous
from scripts.prepare_t2_quality_review import parse, read_bytes
from vulngym_agent.agents import deepseek_backend as adapter

RUN = Path(r"D:\VulnGym-bv2-runtime\t2-context-retest-20260909-v3-context")
BASE = previous.RUN
BASE_MANIFEST = "ca37cb9bb7661c5ad000e381665bd374fb9c6a6ed3b6f81a4265d2152be93533"
RUNTIME_TREE = "8266b1a6ef6e13d2fd5e0ce133e2d2d816945775"
RUNTIME_BASE = "8fb67ef25508fd7edf3a3cdc1ffa29ad72110cfb"
PROMPT_SHA = "36e7c74a989f5869ae015cee7a01d506181510a11375910a574949585ea3eb12"
DEPENDENCIES = ("scripts/run_t2_context_retest_v3.py", "scripts/run_t2_context_retest_v2.py",
                "scripts/run_t2_new_input_batch_v1.py", "scripts/prepare_t2_quality_review.py")
SETTINGS = adapter.DeepSeekSettings(timeout_seconds=300)
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
    return {"schema": "t2.context-diagnostic-plan.v3",
        "sample_group": "seen_input_diagnostic_retest_not_new_input_evaluation",
        "authorization_status": "requires_this_run_confirmation_and_current_key",
        "budget_cny": 20, "max_total_http_requests": 6, "max_llm_calls_per_task": 3,
        "automatic_retries": 0, "max_repair_iterations": 0,
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
        "budget_cny": 20, "timeout_seconds": 300, "current_run_confirmation_required": True}


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
        guard = previous.BoundedTransport(transport, record)
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
