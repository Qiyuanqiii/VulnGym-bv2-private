"""Build a new offline preview without changing the original archive or runs."""
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import zipfile

W = Path(__file__).resolve().parents[1]
R = Path(r"D:\VulnGym-bv2-runtime")
OLD_ZIP = R / "delivery/t2-review-preview-20260908-v1.zip"
OUT = R / "delivery/t2-review-preview-20260908-v2"
ZIP = OUT.with_suffix(".zip")
PUBLIC = W / "evidence/t2-updated-preview-20260908-v1"
LIVE = "evidence/t2-new-input-live-20260908-v1/"
ALLOCATION = "evidence/t2-context-allocation-20260908-v1/"


def wire(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def pin(data):
    return {"bytes": len(data), "sha256": sha256(data).hexdigest()}


def rehash(members):
    members["MANIFEST.json"] = wire({"kind": "t2.updated-offline-review-preview-files.v1",
        "files": {n: pin(b) for n, b in sorted(members.items()) if n != "MANIFEST.json"}})


def main():
    assert not OUT.exists() and not ZIP.exists() and not PUBLIC.exists(), "existing_delivery_preserve"
    assert sha256(OLD_ZIP.read_bytes()).hexdigest() == "7310b3026f2d9bf1012e12653b1359bc896cb5b308a9ad46f2726957d6a0ae08"
    with zipfile.ZipFile(OLD_ZIP) as old:
        assert old.testzip() is None and len(old.namelist()) == len(set(old.namelist())) == 22
        members = {n: old.read(n) for n in old.namelist()}
    sys.path.insert(0, str(W))
    from scripts.verify_t2_review_preview import validate_members as verify_old
    verify_old(members)
    for name in ["docs/current_task_reference.md", "docs/submission/acceptance_report.md",
                 "docs/t2_new_input_live_receipt.md", "docs/t2_context_allocation_receipt.md",
                 "docs/t2_new_input_selection_v1.md", "docs/t2_next_run_budget.md"]:
        members[name] = (W / name).read_bytes()
    members["README.md"] = (W / "docs/submission/updated_preview_readme.md").read_bytes()
    members["verify_bundle.py"] = (W / "scripts/verify_t2_updated_preview.py").read_bytes()
    for folder in (LIVE, ALLOCATION):
        manifest = json.loads((W / folder / "manifest.json").read_bytes())
        for name, expected in manifest["files"].items():
            data = (W / folder / name).read_bytes()
            assert pin(data) == expected
            members[folder + name] = data
        members[folder + "manifest.json"] = (W / folder / "manifest.json").read_bytes()
    members["new_input/handoff.json"] = (R / "t2-new-input-live-20260908-v3/verification/handoff.json").read_bytes()
    assert all(re.search(rb"\bsk-[A-Za-z0-9_-]{16,}", b) is None for b in members.values())
    rehash(members)
    spec = importlib.util.spec_from_file_location("updated_preview", W / "scripts/verify_t2_updated_preview.py")
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    expected_result = verifier.validate_members(members)
    negatives = []

    def edit(data, transform):
        value = json.loads(data)
        transform(value)
        return wire(value)

    def fails(label, filename, transform, expected_code, *, repin=True, handoff_repin=False):
        changed = dict(members)
        changed[filename] = transform(changed[filename])
        if handoff_repin:
            summary = json.loads(changed[LIVE + "summary.json"])
            summary["handoff_file_sha256"] = sha256(changed["new_input/handoff.json"]).hexdigest()
            changed[LIVE + "summary.json"] = wire(summary)
        if repin:
            rehash(changed)
        try:
            verifier.validate_members(changed)
        except ValueError as error:
            assert str(error) == expected_code, (label, str(error))
        else:
            raise AssertionError("invalid_updated_preview_accepted:" + label)
        negatives.append({"case": label, "rejected": True, "code": expected_code})

    fails("changed_bytes", "new_input/handoff.json", lambda b: b + b" ", "file_digest_mismatch", repin=False)
    fails("false_new_accuracy", LIVE + "summary.json", lambda b: edit(b, lambda j: j.update(semantic_accuracy=1)), "new_quality_claim_changed")
    fails("false_new_candidate", LIVE + "summary.json", lambda b: edit(b, lambda j: j.update(complete_candidates=1)), "new_run_counts_changed")
    fails("false_human_review", LIVE + "summary.json", lambda b: edit(b, lambda j: j.update(independent_human_review_completed=True)), "new_quality_claim_changed")
    fails("false_calls", LIVE + "summary.json", lambda b: edit(b, lambda j: j.update(actual_http_requests=7)), "new_run_counts_changed")
    fails("false_formal_export", "new_input/handoff.json", lambda b: edit(b, lambda j: j.update(formal_submission_export=True)), "new_handoff_claim_changed", handoff_repin=True)
    fails("invented_pair", "new_input/handoff.json", lambda b: edit(b, lambda j: j["tasks"][0].update(pair_ordinal=1)), "new_task_outcome_changed", handoff_repin=True)
    fails("wrong_replay_digest", "new_input/handoff.json", lambda b: edit(b, lambda j: j.update(source_replay_dataset_sha256="0" * 64)), "new_handoff_binding_mismatch", handoff_repin=True)
    fails("changed_defer", LIVE + "summary.json", lambda b: edit(b, lambda j: j["results"][0]["model_self_report"].update(explanation="changed")), "new_defer_content_mismatch")
    fails("false_post_patch_inference", ALLOCATION + "summary.json", lambda b: edit(b, lambda j: j.update(new_real_provider_calls_after_patch=1)), "offline_change_claim_changed")
    fails("old_verify_promotion", "data/handoff.json", lambda b: edit(b, lambda j: j["entries"][0].update(verify=1)), "machine_verify_changed")
    fails("duplicate_json_key", LIVE + "summary.json", lambda b: b'{"task_count":2,' + b[1:], "duplicate_json_key")
    OUT.mkdir()
    for name, data in members.items():
        path = OUT / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(data)
    command = [sys.executable, "-I", "-B", str(OUT / "verify_bundle.py")]
    runs = [subprocess.run(command, cwd=OUT, capture_output=True, timeout=30) for _ in range(2)]
    assert all(r.returncode == 0 and not r.stderr for r in runs)
    assert runs[0].stdout == runs[1].stdout and json.loads(runs[0].stdout) == expected_result
    with zipfile.ZipFile(ZIP, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(members.items()):
            info = zipfile.ZipInfo(name, (2026, 9, 8, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    with zipfile.ZipFile(ZIP) as archive:
        assert archive.testzip() is None and len(archive.namelist()) == len(members)
        readback = {n: archive.read(n) for n in archive.namelist()}
        assert readback == members and verifier.validate_members(readback) == expected_result
    assert sha256(OLD_ZIP.read_bytes()).hexdigest() == "7310b3026f2d9bf1012e12653b1359bc896cb5b308a9ad46f2726957d6a0ae08"
    receipt = {"schema": "t2.updated-preview-package-receipt.v1", "file_name": ZIP.name,
        "zip": pin(ZIP.read_bytes()), "files": len(members), "uncompressed_bytes": sum(len(b) for b in members.values()),
        "member_manifest_sha256": sha256(members["MANIFEST.json"]).hexdigest(),
        "standalone_processes": 2, "standalone_exit_codes": [0, 0], "standalone_stdout_byte_equal": True,
        "zip_readback_byte_equal": True, "prior_zip_unchanged": True, "negative_checks": len(negatives),
        "source_code_not_bundled": True, "new_real_model_calls": 0,
        "scope": "authorized_review_preview_not_final_acceptance_or_independent_semantic_verification"}
    artifacts = {"package_receipt.json": wire(receipt), "verification.json": wire({"result": expected_result, "negative_checks": negatives})}
    artifacts["manifest.json"] = wire({"files": {n: pin(b) for n, b in artifacts.items()}})
    PUBLIC.mkdir()
    for name, data in artifacts.items():
        with (PUBLIC / name).open("xb") as stream:
            stream.write(data)
    print(json.dumps(receipt), flush=True)


if __name__ == "__main__":
    main()
