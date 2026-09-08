"""One seen-input diagnostic retest, reusing the existing bounded transport.

Check is offline. Run requires a fresh key and an explicit confirmation of the
provider-side CNY 20 hard cap; this program cannot infer RMB from token counts.
Old run files are immutable. This is not another unseen-input evaluation.
"""
from contextlib import contextmanager
from hashlib import sha256
import argparse
import json
from pathlib import Path
import sys

W = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(W))
from scripts import run_t2_new_input_batch_v1 as engine

RUN = Path(r"D:\VulnGym-bv2-runtime\t2-context-retest-20260909-v1")
OLD = Path(r"D:\VulnGym-bv2-runtime\t2-new-input-live-20260908-v3")
MANIFEST_SHA256 = "7332b4ef71d6c5a96f5f0252d626f0c623a05d106515a5d3333d6e0757f1b54f"


def backend_factory():
    # The shared CLI resolves __main__:backend_factory in this wrapper.
    return engine.backend_factory()


@contextmanager
def configured_engine():
    original = engine.RUN, engine.MANIFEST_SHA256
    engine.RUN, engine.MANIFEST_SHA256 = RUN, MANIFEST_SHA256
    try:
        yield
    finally:
        engine.RUN, engine.MANIFEST_SHA256 = original


def verify_frozen_profile(*, for_run):
    raw = (RUN / "input-manifest.json").read_bytes()
    if sha256(raw).hexdigest() != MANIFEST_SHA256:
        raise ValueError("retest_manifest_changed")
    value = json.loads(raw)
    if (value["sample_group"] != "seen_input_diagnostic_retest_not_new_input_evaluation"
            or value["authorized_budget_cny"] != 20 or value["max_total_http_requests"] != 6
            or value["max_llm_calls_per_task"] != 3 or value["automatic_retries"] != 0
            or value["max_repair_iterations"] != 0):
        raise ValueError("retest_scope_changed")
    if sha256(Path(engine.__file__).read_bytes()).hexdigest() != value["shared_runner_sha256"]:
        raise ValueError("shared_runner_changed")
    for expected in value["baseline_runtime_file_pins"]:
        data = (OLD / expected["path"]).read_bytes()
        if len(data) != expected["bytes"] or sha256(data).hexdigest() != expected["sha256"]:
            raise ValueError("baseline_changed_preserve")
    if for_run and engine.git("show", "HEAD:scripts/run_t2_context_retest_v1.py") != Path(__file__).read_bytes():
        raise ValueError("retest_wrapper_not_committed")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "run"))
    parser.add_argument("--confirm-platform-cap", action="store_true",
                        help="Operator confirms this NEW key has a CNY 20 provider-side hard cap.")
    args = parser.parse_args(argv)
    if args.action == "run" and not args.confirm_platform_cap:
        engine.emit({"status": "blocked", "code": "fresh_key_platform_cap_confirmation_required",
                     "provider_calls": 0, "run_started": False})
        return 2
    try:
        verify_frozen_profile(for_run=args.action == "run")
        with configured_engine():
            return engine.main([args.action])
    except (Exception, KeyboardInterrupt):
        engine.emit({"status": "invalid", "code": "retest_preflight_failed_preserve",
                     "preserve_existing_files": True})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
