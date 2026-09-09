"""Export one pinned, honest T2 delivery; preserve every prior package/run.

Input is tracked public material, one reviewed PDF and one explicitly archival
video. Output is new-only. Runtime tree equality binds the source to the latest
real diagnostic without claiming it is a fresh run or a quality pass.
"""
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.verify_t2_submission_v3 import E, REVIEW, EXECUTION, RUNTIME, VIDEO, pin, wire, validate_members

TESTS = ["tests.test_deepseek_backend", "tests.test_deepseek_stage_budget",
         "tests.test_real_t2_producer", "tests.test_t2_production_cli",
         "tests.test_t2_semantic_context", "tests.test_t2_context_allocation",
         "tests.test_t2_reflection_defer", "tests.test_t2_submission_v3"]
SCRIPTS = ["scripts/build_t2_submission_v3.py", "scripts/verify_t2_submission_v3.py",
           "scripts/demo_t2_submission_v3.py", "scripts/build_t2_delivery_pdf_v3.py"]
DOCS = ["START_HERE_T2.md", "SCHEMA.md", "LICENSE", "requirements-dev.txt",
        "docs/current_task_reference.md", "docs/submission/acceptance_report.md",
        "docs/submission/T2_DELIVERY_BRIEF.md", "docs/submission/t2_submission_v3_readme.md",
        "docs/submission/design.md", "docs/submission/ai_coding_history.md",
        "docs/submission/self_assessment.md", "docs/submission/t2_quality_protocol_v1.md",
        "docs/t2_production_runbook.md", "docs/deepseek_t2_setup.md",
        "docs/submission_prediction_runbook.md", "docs/t2_current_review_20260910.md",
        "docs/t2_stage_budget_retest_receipt.md", "docs/t2_stage_budget_receipt.md",
        "docs/t2_context_delivery_v2.md", "docs/t2_results_video_receipt.md"]
PUBLIC_DIRS = ["evidence/t2-stage-budget-retest-20260909-v1",
               "evidence/t2-current-review-20260910-v1",
               "evidence/t2-quality-self-review-dev12-20260908",
               "evidence/t2-submission-disposition-20260909-v1"]


def environment():
    env = os.environ.copy()
    for name in ("DEEPSEEK_API_KEY", "OPENAI_API_KEY", "PYTHONPATH", "PYTHONHOME"):
        env.pop(name, None)
    env.update(TEMP=r"D:\VulnGym-bv2-runtime\tmp", TMP=r"D:\VulnGym-bv2-runtime\tmp",
               PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1", PYTHONIOENCODING="utf-8",
               GIT_NO_LAZY_FETCH="1", GIT_OPTIONAL_LOCKS="0")
    return env


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, env=environment(), timeout=30)


def blobs_at(commit, names):
    names = sorted(set(names))
    raw = subprocess.check_output(["git", "cat-file", "--batch"], cwd=ROOT, env=environment(),
           input="".join(commit + ":" + name + "\n" for name in names).encode(), timeout=30)
    stream, result = io.BytesIO(raw), {}
    for name in names:
        header = stream.readline().decode().split()
        if len(header) != 3 or header[1] != "blob":
            raise ValueError("source_blob_missing:" + name)
        result[name] = stream.read(int(header[2]))
        if stream.read(1) != b"\n":
            raise ValueError("invalid_git_batch")
    if stream.read():
        raise ValueError("unexpected_git_output")
    return result


def archive_bytes(members):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for name, raw in sorted(members.items()):
            info = zipfile.ZipInfo(name, (2026, 9, 10, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            z.writestr(info, raw)
    return out.getvalue()


def exclusive(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as f:
        f.write(raw)


def main():
    import argparse
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source-commit", required=True)
    p.add_argument("--pdf", required=True, type=Path)
    p.add_argument("--python", required=True, type=Path)
    p.add_argument("--old-package", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--preflight", action="store_true", help="validate pinned inputs without creating output")
    args = p.parse_args()
    commit = args.source_commit
    assert re.fullmatch("[0-9a-f]{40}", commit)
    assert git("branch", "--show-current").decode().strip() == "codex/b-v2-source-discovery"
    assert git("rev-parse", "HEAD").decode().strip() == commit and not git("status", "--porcelain")
    assert git("rev-parse", commit + ":vulngym_agent").decode().strip() == RUNTIME
    assert git("ls-tree", "-r", commit, "--", "vulngym_agent").decode().splitlines()
    assert all(line.startswith("100644 ") for line in git("ls-tree", "-r", commit, "--", "vulngym_agent").decode().splitlines())
    out, check = args.output, args.output.with_name(args.output.name + "-checks")
    archive = out.with_suffix(".zip")
    receipt = out.with_suffix(".receipt.json")
    assert not any(path.exists() for path in (out, check, archive, receipt)), "preserve_existing_outputs"
    assert out.resolve().is_relative_to(Path(r"D:\VulnGym-bv2-runtime\delivery").resolve())
    scoped = git("ls-tree", "-r", "--name-only", commit, "--", "vulngym_agent", "schemas", *PUBLIC_DIRS).decode().splitlines()
    names = set(scoped) | set(DOCS) | set(SCRIPTS) | {t.replace(".", "/") + ".py" for t in TESTS}
    blobs = blobs_at(commit, names)
    # Compare the authored PDF's source pin to the committed brief, not a later worktree.
    pdf_receipt = json.loads(args.pdf.with_suffix(".json").read_bytes())
    pdf = args.pdf.read_bytes()
    assert pin(pdf) == pdf_receipt["pdf"] and pdf_receipt["pages"] == 3
    assert pdf_receipt["source_sha256"] == sha256(blobs["docs/submission/T2_DELIVERY_BRIEF.md"]).hexdigest()
    assert pdf_receipt["visual_check"] == "passed_three_pages", "pdf_visual_review_required"
    assert sha256(args.old_package.read_bytes()).hexdigest() == "4e6216c80ed47aed8fdffd50bde4a152a920d6cc05da2fc3f6f4316f6259b4bd"
    with zipfile.ZipFile(args.old_package) as z:
        videos = [n for n in z.namelist() if n.endswith("T2-existing-results-demo.mp4")]
        assert len(videos) == 1
        video = z.read(videos[0])
    assert sha256(video).hexdigest() == VIDEO
    members = {"source/" + n: raw for n, raw in blobs.items()}
    for n, raw in blobs.items():
        if n.startswith(PUBLIC_DIRS[0] + "/"):
            members[E + n.split("/")[-1]] = raw
    members[REVIEW] = blobs[PUBLIC_DIRS[1] + "/review.json"]
    members["verify_delivery.py"] = blobs[SCRIPTS[1]]
    members["demo.py"] = blobs[SCRIPTS[2]]
    members["README.md"] = blobs["docs/submission/t2_submission_v3_readme.md"]
    members["output/pdf/T2-design.pdf"] = pdf
    members["output/pdf/provenance.json"] = wire(pdf_receipt)
    members["media/archival/T2-existing-results-demo.mp4"] = video
    h = json.loads(members[E + "handoff.json"])
    for field in ("entries", "validation"):
        members["data/latest/" + field + ".jsonl"] = b"".join(wire(v) for v in h[field])
    members["data/latest/deferred.jsonl"] = b"".join(wire({"task_id": t["task_id"], **d}) for t in h["tasks"] for d in t["deferred"])
    members["MANIFEST.json"] = wire({"schema": "t2.submission-candidate.v3",
        "scope": "engineering_delivery_with_unresolved_quality", "source_commit": commit,
        "runtime_tree": RUNTIME, "execution_commit": EXECUTION, "source_files": len(blobs),
        "new_model_calls": 0, "complete_T2_quality_acceptance": False,
        "video_scope": "archival_existing_results_not_current_live_run",
        "source_hashes": {n: pin(raw) for n, raw in sorted(blobs.items())},
        "files": {n: pin(raw) for n, raw in sorted(members.items())}})
    validate_members(members)
    if args.preflight:
        print(json.dumps({"preflight": "passed", "files": len(members), "source_files": len(blobs),
                          "source_commit": commit, "runtime_tree": RUNTIME, "new_model_calls": 0}, sort_keys=True))
        return
    out.mkdir()
    check.mkdir()
    for name, raw in members.items():
        exclusive(out / name, raw)
    print("Pinned source and latest result bundle exported; offline checks running.", flush=True)

    def run(label, argv, cwd=out, timeout=240):
        result = subprocess.run([str(args.python), "-B", *argv], cwd=cwd, env=environment(),
                                capture_output=True, timeout=timeout)
        exclusive(check / (label + ".stdout"), result.stdout)
        exclusive(check / (label + ".stderr"), result.stderr)
        assert result.returncode == 0, label + "_failed"
        return result

    verifies = [run("verify-" + str(i), ["-I", "verify_delivery.py"]) for i in (1, 2)]
    assert verifies[0].stdout == verifies[1].stdout and not any(v.stderr for v in verifies)
    demos = [run("demo-" + str(i), ["demo.py", "--json"]) for i in (1, 2)]
    assert demos[0].stdout == demos[1].stdout and not any(d.stderr for d in demos)
    for module in ("t2_production_cli", "submission_prediction_cli"):
        run(module + "-help", ["-m", "vulngym_agent." + module, "--help"], out / "source")
    clean = run("clean-environment", ["-I", "-c", "import importlib.util,json,sys; names=('pip','jsonschema','cryptography'); missing={n:importlib.util.find_spec(n) is None for n in names}; assert all(missing.values()); print(json.dumps({'python':sys.version.split()[0],'missing':missing},sort_keys=True))"])
    tests = run("exported-tests", ["-m", "unittest", *TESTS, "-q"], out / "source", timeout=600)
    match = re.search(rb"Ran (\d+) tests in ([0-9.]+)s", tests.stderr)
    assert match and tests.stderr.rstrip().endswith(b"OK")
    final_verify = run("verify-after-tests", ["-I", "verify_delivery.py"])
    assert final_verify.stdout == verifies[0].stdout
    raw = archive_bytes(members)
    assert raw == archive_bytes(members), "zip_not_reproducible"
    exclusive(archive, raw)
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None and len(z.namelist()) == len(members)
        assert {n: z.read(n) for n in z.namelist()} == members
    run("zip-verification", ["-I", "verify_delivery.py", "--zip", str(archive)])
    result = {"schema": "t2.submission-v3-receipt.v1", "file_name": archive.name, **pin(raw),
        "files": len(members), "source_files": len(blobs), "source_commit": commit,
        "runtime_tree": RUNTIME, "execution_commit": EXECUTION,
        "uncompressed_bytes": sum(map(len, members.values())), "manifest_sha256": sha256(members["MANIFEST.json"]).hexdigest(),
        "exported_tests": {"modules": TESTS, "count": int(match[1]), "seconds": float(match[2]), "exit_code": 0},
        "clean_environment": json.loads(clean.stdout), "verify_two_processes_byte_equal": True,
        "demo_two_processes_byte_equal": True, "runtime_matches_actual_run": True,
        "zip_reproducible_byte_equal": True, "zip_readback_byte_equal": True,
        "files_unchanged_after_tests": True, "pdf_pages": 3, "pdf_visual_check": "passed_three_pages",
        "video_scope": "archival_existing_results_not_current_live_run", "new_model_calls": 0,
        "complete_T2_quality_acceptance": False,
        "checks": {p.name: pin(p.read_bytes()) for p in sorted(check.iterdir())}}
    exclusive(receipt, wire(result))
    print(wire(result).decode(), end="", flush=True)


if __name__ == "__main__":
    main()
