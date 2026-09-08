"""Verify a delivery directory without network access or file writes.

Copied to the delivery root as verify_delivery.py. File hashes provide byte
integrity, not authorship, model quality or an independent human review.
"""
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath
import sys
import zipfile


def require(condition, code):
    if not condition:
        raise ValueError(code)


def verify(root):
    manifest = json.loads((root / "MANIFEST.json").read_bytes())
    require(manifest["schema"] == "t2.deadline-candidate.v1", "manifest_schema")
    actual = set()
    for path in root.rglob("*"):
        require(not path.is_symlink() and not path.is_junction(), "unexpected_link")
        if path.is_file():
            actual.add(path.relative_to(root).as_posix())
    require(actual == set(manifest["files"]) | {"MANIFEST.json"}, "file_set_changed")
    for name, expected in manifest["files"].items():
        path = PurePosixPath(name)
        require(not path.is_absolute() and ".." not in path.parts
                and ":" not in name and "\\" not in name, "invalid_member_path")
        raw = (root / name).read_bytes()
        require({"bytes": len(raw), "sha256": sha256(raw).hexdigest()} == expected,
                "file_bytes_changed")
    preview = root / "evidence/prior-results.zip"
    require(sha256(preview.read_bytes()).hexdigest()
            == "452a0cf3e869573f7aaf18f36c92e2c9f9a7319a968c195422948835292f1a09",
            "prior_results_changed")
    with zipfile.ZipFile(preview) as archive:
        require(len(archive.namelist()) == len(set(archive.namelist())) == 38,
                "prior_results_file_set_changed")
        handoff = json.loads(archive.read("data/handoff.json"))
    for field in ("entries", "validation"):
        actual_rows = [json.loads(line) for line in
                       (root / "data/development" / (field + ".jsonl")).read_bytes().splitlines()]
        require(actual_rows == handoff[field], "historical_data_changed")
    require(len(handoff["entries"]) == len(handoff["validation"]) == 1,
            "historical_count_changed")
    require(handoff["entries"][0]["verify"] == 0, "machine_verify_changed")
    current = json.loads((root / "evidence/diagnostic/summary.json").read_bytes())
    require(current["complete_candidates"] == 0, "diagnostic_count_changed")
    require(current["run_status"] == "diagnostic_inconclusive_transport_timeout",
            "diagnostic_status_changed")
    require(manifest["complete_T2_quality_acceptance"] is False, "acceptance_claim_changed")
    return {"verified": True, "files": len(actual), "source_commit": manifest["source_commit"],
            "new_provider_calls": 0, "scope": "byte_integrity_and_grouped_counts_not_quality"}


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    try:
        result = verify(Path(__file__).resolve().parent)
    except (ValueError, OSError, KeyError, TypeError, zipfile.BadZipFile):
        raise SystemExit("delivery_verification_failed") from None
    print(json.dumps(result, sort_keys=True))
