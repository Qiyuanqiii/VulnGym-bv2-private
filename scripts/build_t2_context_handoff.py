"""Package committed diagnostic evidence only; no API, input or source repo reads."""
from hashlib import sha256
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.verify_t2_context_handoff import E, REVIEW, validate_members, read_directory

OUT = Path(r"D:\VulnGym-bv2-runtime\delivery\t2-context-diagnostic-20260909-v3")
ZIP = OUT.with_suffix(".zip")
PUBLIC = ROOT / "evidence/t2-context-handoff-20260909-v1/package_receipt.json"


def wire(value):
    return (json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def pin(data):
    return {"bytes": len(data), "sha256": sha256(data).hexdigest()}


def build_members(commit):
    names = {E + n: E + n for n in ("summary.json", "runtime_files.json", "readback.json", "review.json",
             "handoff.json", "handoff_verification.json", "transport_events.jsonl", "manifest.json")}
    names.update({REVIEW: REVIEW, "docs/t2_context_retest_v3_receipt.md": "docs/t2_context_retest_v3_receipt.md",
        "README.md": "docs/submission/context_diagnostic_handoff_readme.md",
        "verify_bundle.py": "scripts/verify_t2_context_handoff.py"})
    members = {}
    for target, source in names.items():
        raw = (ROOT / source).read_bytes()
        result = subprocess.run(["git", "show", commit + ":" + source], cwd=ROOT, capture_output=True, timeout=30)
        if result.returncode or result.stdout != raw:
            raise ValueError("package_source_not_committed")
        members[target] = raw
    if any(re.search(rb"\bsk-[A-Za-z0-9_-]{16,}", b) for b in members.values()):
        raise ValueError("credential_marker_preserve")
    members["MANIFEST.json"] = wire({"schema": "t2.context-diagnostic-handoff.v1",
        "scope": "diagnostic_increment_not_final_delivery", "source_commit": commit,
        "source_code_bundled": False, "files": {n: pin(b) for n, b in sorted(members.items())}})
    validate_members(members)
    return members


def archive_bytes(members):
    target = io.BytesIO()
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(members.items()):
            info = zipfile.ZipInfo(name, (2026, 9, 9, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    return target.getvalue()


def main():
    if OUT.exists() or ZIP.exists() or PUBLIC.exists():
        raise ValueError("existing_handoff_preserve")
    branch = subprocess.check_output(["git", "branch", "--show-current"], cwd=ROOT).decode().strip()
    if branch != "codex/b-v2-source-discovery":
        raise ValueError("wrong_branch")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT).decode().strip()
    members = build_members(commit)
    expected = validate_members(members)
    raw = archive_bytes(members)
    if raw != archive_bytes(members):
        raise ValueError("archive_not_reproducible")
    OUT.mkdir()
    for name, data in members.items():
        path = OUT / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(data)
    command = [sys.executable, "-I", "-B", str(OUT / "verify_bundle.py")]
    checks = [subprocess.run(command, cwd=OUT, capture_output=True, timeout=30) for _ in range(2)]
    if not all(c.returncode == 0 and not c.stderr for c in checks) or checks[0].stdout != checks[1].stdout:
        raise ValueError("standalone_verification_failed_preserve")
    if json.loads(checks[0].stdout) != expected or read_directory(OUT) != members:
        raise ValueError("package_readback_mismatch_preserve")
    with ZIP.open("xb") as stream:
        stream.write(raw)
    with zipfile.ZipFile(ZIP) as archive:
        if archive.testzip() is not None or len(archive.namelist()) != len(members):
            raise ValueError("archive_verification_failed_preserve")
        if {n: archive.read(n) for n in archive.namelist()} != members:
            raise ValueError("archive_bytes_changed_preserve")
    receipt = dict(expected, zip_name=ZIP.name, zip=pin(raw),
        uncompressed_bytes=sum(map(len, members.values())),
        deterministic_archive_twice_equal=True, standalone_processes=2,
        standalone_stdout_byte_equal=True, zip_readback_byte_equal=True,
        source_code_bundled=False, old_archives_modified=False)
    PUBLIC.parent.mkdir()
    with PUBLIC.open("xb") as stream:
        stream.write(wire(receipt))
    print(wire(receipt).decode(), end="")


if __name__ == "__main__":
    main()
