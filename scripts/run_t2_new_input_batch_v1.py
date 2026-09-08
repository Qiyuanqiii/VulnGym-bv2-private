"""One explicitly authorized, frozen two-input T2 run. Check mode is offline.

RMB enforcement is the user-confirmed provider-side CNY 20 key limit, not a
token-price estimate. Local controls cap requests and forbid automatic reruns.
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

WORKSPACE = Path(__file__).resolve().parents[1]
RUN = Path(r"D:\VulnGym-bv2-runtime\t2-new-input-live-20260908-v3")
MANIFEST_SHA256 = "1f85f4cad6ee17aa722bec985938ba76cea93bc6c0fe7bec52f050cca20c6a3f"
TASKS = ("VG-NEW-20260908-001", "VG-NEW-20260908-002")
sys.path.insert(0, str(WORKSPACE))
from vulngym_agent.agents import deepseek_backend as adapter
from vulngym_agent.agents.model_runtime import ModelBlocked

_backend = None


def wire(value):
    return (json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def emit(value):
    print(wire(value).decode().rstrip(), file=sys.__stdout__, flush=True)


def put_new(path, data):
    with path.open("xb") as stream:
        stream.write(data)


def git(*args):
    result = subprocess.run(["git", *args], cwd=WORKSPACE, capture_output=True, timeout=30)
    if result.returncode:
        raise ValueError("git_pin_check_failed")
    return result.stdout


def preflight(*, for_run=False):
    raw = (RUN / "input-manifest.json").read_bytes()
    if sha256(raw).hexdigest() != MANIFEST_SHA256:
        raise ValueError("input_manifest_changed")
    manifest = json.loads(raw)
    if git("branch", "--show-current").decode().strip() != "codex/b-v2-source-discovery":
        raise ValueError("wrong_branch")
    # New documentation/evidence commits are allowed, runtime edits are not.
    if git("rev-parse", "HEAD:vulngym_agent").decode().strip() != manifest["runtime_tree"]:
        raise ValueError("runtime_commit_tree_changed")
    git("diff", "--quiet", "HEAD", "--", "vulngym_agent")
    git("merge-base", "--is-ancestor", manifest["runtime_base_commit"], "HEAD")
    if adapter.DeepSeekSettings().profile() != manifest["model"]:
        raise ValueError("provider_profile_changed")
    if for_run and git("show", "HEAD:scripts/run_t2_new_input_batch_v1.py") != Path(__file__).read_bytes():
        raise ValueError("runner_not_committed_or_changed")
    for name, expected in manifest["input_files"].items():
        if name not in {"tasks.jsonl", "repos.json"} and not re.fullmatch(r"package/(?:advisory|patch)-GHSA-[A-Z0-9-]+\.(?:json|diff)", name):
            raise ValueError("unexpected_input_name")
        path = RUN / "input" / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
            raise ValueError("invalid_input_file")
        data = path.read_bytes()
        if len(data) != expected["bytes"] or sha256(data).hexdigest() != expected["sha256"]:
            raise ValueError("input_file_changed")
    from vulngym_agent.closed_loop_cli import iter_task_jsonl, load_trusted_repo_map
    rows = list(iter_task_jsonl(RUN / "input/tasks.jsonl"))
    if len(rows) != 2 or any(row.task is None for row in rows) or tuple(row.task.task_id for row in rows) != TASKS:
        raise ValueError("task_identity_changed")
    repos = load_trusted_repo_map(RUN / "input/repos.json")
    if set(repos) != {case["repo_url"] for case in manifest["cases"]}:
        raise ValueError("repository_set_changed")
    for case in manifest["cases"]:
        repo = repos[case["repo_url"]]
        result = subprocess.run(["git", "--git-dir=" + str(repo), "show", "-s", "--format=%P", case["fix_commit"]],
                                cwd=WORKSPACE, capture_output=True, timeout=30)
        if result.returncode or result.stdout.decode().strip().split() != [case["working_pre_fix_snapshot"]]:
            raise ValueError("source_parent_changed")
        for name, versions in case["source_files"].items():
            for side, revision in [("before", case["working_pre_fix_snapshot"]), ("after", case["fix_commit"])]:
                result = subprocess.run(["git", "--git-dir=" + str(repo), "show", revision + ":" + name],
                                        cwd=WORKSPACE, capture_output=True, timeout=30)
                if result.returncode or {"bytes": len(result.stdout), "sha256": sha256(result.stdout).hexdigest()} != versions[side]:
                    raise ValueError("fixed_source_changed")
    if for_run and any((RUN / name).exists() for name in ["run-start.json", "transport-events.jsonl", "output", "run-exit.json", "cli-stdout.json"]):
        raise ValueError("existing_run_preserve_do_not_restart")
    return manifest


class BoundedTransport:
    """Process-local allowance, with persist-before-send and terminal failures."""
    def __init__(self, send, record):
        self.send = send
        self.record = record
        self.attempts = 0
        self.per_task = Counter()
        self.identities = set()
        self.halt = None

    def __call__(self, body, api_key, timeout):
        if self.halt is not None:
            raise ModelBlocked(self.halt)
        try:
            envelope = json.loads(body)
            request = json.loads(envelope["messages"][1]["content"])
            task, stage, call = request["task_id"], request["stage"], request["model_call_id"]
            valid = (type(body) is bytes and len(body) <= adapter.MAX_REQUEST_BYTES
                and envelope["model"] == adapter.MODEL_ID and type(envelope["max_tokens"]) is int
                and envelope["max_tokens"] == 8192 and envelope["stream"] is False
                and task in TASKS and stage in {"plan", "semantic_judge", "reflection"}
                and isinstance(call, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", call)
                and type(timeout) in (int, float) and 0 < timeout <= 120)
        except (ValueError, TypeError, KeyError, IndexError, UnicodeError):
            valid = False
        if not valid:
            raise ModelBlocked("new_input_transport_contract_invalid")
        if self.attempts >= 6 or self.per_task[task] >= 3:
            raise ModelBlocked("new_input_transport_budget_exceeded")
        if (task, call) in self.identities:
            raise ModelBlocked("new_input_duplicate_request_rejected")
        self.attempts += 1
        self.per_task[task] += 1
        self.identities.add((task, call))
        start = time.monotonic()
        row = {"attempt": self.attempts, "task_id": task, "stage": stage,
               "request_bytes": len(body), "request_body_sha256": sha256(body).hexdigest(),
               "started_at": datetime.now(timezone.utc).isoformat()}
        # A failed write must not turn into an unrecorded paid request.
        try:
            self.record(dict(row, event="started"))
        except Exception:
            self.halt = "new_input_telemetry_failed"
            raise ModelBlocked(self.halt) from None
        try:
            response = self.send(body, api_key, timeout)
            row.update(status="http_200", response_bytes=len(response))
            try:
                value = json.loads(response)
                usage = value.get("usage", {})
                row["usage"] = {name: usage[name] for name in ("prompt_tokens", "completion_tokens", "total_tokens", "prompt_cache_hit_tokens", "prompt_cache_miss_tokens")
                                if type(usage.get(name)) is int and usage[name] >= 0}
                row["reported_model_matches"] = value.get("model") == adapter.MODEL_ID
            except (ValueError, AttributeError, TypeError, UnicodeError):
                row["usage"] = {}
            return response
        except ModelBlocked as error:
            code = error.error_code
            self.halt = code if re.fullmatch(r"deepseek_[a-z_]{1,70}", code) else "new_input_transport_failed"
            row.update(status="blocked", error_code=self.halt)
            raise ModelBlocked(self.halt) from None
        except Exception:
            self.halt = "new_input_transport_failed"
            row.update(status="error", error_code=self.halt)
            raise ModelBlocked(self.halt) from None
        finally:
            row["elapsed_seconds"] = round(time.monotonic() - start, 3)
            try:
                self.record(dict(row, event="finished"))
            except Exception:
                self.halt = "new_input_telemetry_failed"
                raise ModelBlocked(self.halt) from None


def backend_factory():
    if _backend is None:
        raise RuntimeError("backend_not_initialized")
    return _backend


def run():
    global _backend
    manifest = preflight(for_run=True)
    # An exclusive marker blocks a second process and every unattended rerun.
    put_new(RUN / "run-start.json", wire({"started_at": datetime.now(timezone.utc).isoformat(),
        "execution_head": git("rev-parse", "HEAD").decode().strip(), "manifest_sha256": MANIFEST_SHA256,
        "runner_sha256": sha256(Path(__file__).read_bytes()).hexdigest(), "budget_cny": 20,
        "platform_hard_limit": manifest["platform_hard_limit"]}))
    original = adapter._post_official
    telemetry = (RUN / "transport-events.jsonl").open("xb")
    def record(event):
        telemetry.write(wire(event))
        telemetry.flush()
        os.fsync(telemetry.fileno())
        emit({"event": event["event"], "attempt": event["attempt"], "stage": event["stage"]})
    guard = BoundedTransport(original, record)
    stdout = io.StringIO()
    key, code, error = None, 2, None
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            key = getpass.getpass("Temporary key (hidden): ")
        if re.fullmatch(r"sk-[A-Za-z0-9_-]{16,128}", key) is None:
            raise ValueError("credential_format_invalid")
        _backend = adapter.DeepSeekV4ProBackend(api_key=key, settings=adapter.DeepSeekSettings())
        key = None
        adapter._post_official = guard
        from vulngym_agent import t2_production_cli
        with redirect_stdout(stdout):
            code = t2_production_cli.main(["--tasks", str(RUN / "input/tasks.jsonl"),
                "--repo-map", str(RUN / "input/repos.json"), "--package-root", str(RUN / "input/package"),
                "--backend-factory", "__main__:backend_factory", "--output-dir", str(RUN / "output"),
                "--max-records", "2", "--max-llm-calls", "3", "--max-tool-calls", "80", "--max-repair-iterations", "0"])
    except (Exception, KeyboardInterrupt):
        error = "new_input_setup_or_run_failed"
        code = 2
    finally:
        key = None
        if _backend is not None:
            _backend._api_key = ""
        _backend = None
        adapter._post_official = original
        telemetry.close()
    put_new(RUN / "cli-stdout.json", stdout.getvalue().encode("utf-8"))
    result = {"status": "run_finished", "exit_code": code, "transport_attempts": guard.attempts,
        "credential_use_ended": True, "finished_at": datetime.now(timezone.utc).isoformat(),
        "error_code": error, "transport_halt_code": guard.halt}
    put_new(RUN / "run-exit.json", wire(result))
    emit(result)
    return code


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["check", "run"])
    args = parser.parse_args(argv)
    os.environ.update(TEMP=r"D:\VulnGym-bv2-runtime\tmp", TMP=r"D:\VulnGym-bv2-runtime\tmp",
                      GIT_NO_LAZY_FETCH="1", GIT_OPTIONAL_LOCKS="0")
    try:
        if args.action == "run":
            return run()
        manifest = preflight()
        emit({"status": "inputs_verified_no_provider_call", "tasks": 2, "budget_cny": 20,
              "platform_hard_limit": manifest["platform_hard_limit"], "max_total_http_requests": 6,
              "prompt_version": manifest["model"]["prompt_version"], "provider_calls": 0,
              "input_manifest_sha256": MANIFEST_SHA256})
        return 0
    except (Exception, KeyboardInterrupt):
        emit({"status": "invalid", "code": "new_input_preflight_or_io_failed", "preserve_existing_files": True})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
