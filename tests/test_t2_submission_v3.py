"""Synthetic negative cases and public-record bindings; not model quality tests."""
from copy import deepcopy
from hashlib import sha256
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from scripts import verify_t2_submission_v3 as v
from scripts.build_t2_submission_v3 import archive_bytes, with_local_dependencies
from scripts.demo_t2_submission_v3 import explain

ROOT = Path(__file__).resolve().parents[1]


def seal(members):
    members["MANIFEST.json"] = v.wire({"schema": "t2.submission-candidate.v3",
        "scope": "engineering_delivery_with_unresolved_quality", "source_commit": "a" * 40,
        "execution_commit": v.EXECUTION, "runtime_tree": v.runtime_tree(members),
        "new_model_calls": 0, "complete_T2_quality_acceptance": False,
        "video_scope": "archival_existing_results_not_current_live_run",
        "source_files": sum(n.startswith("source/") for n in members),
        "source_hashes": {n[len("source/"):]: v.pin(raw) for n, raw in members.items() if n.startswith("source/")},
        "files": {n: v.pin(raw) for n, raw in members.items() if n != "MANIFEST.json"}})


class SubmissionV3Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        e = ROOT / "evidence/t2-stage-budget-retest-20260909-v1"
        cls.base = {v.E + p.name: p.read_bytes() for p in e.iterdir() if p.is_file()}
        cls.base[v.REVIEW] = (ROOT / "evidence/t2-current-review-20260910-v1/review.json").read_bytes()
        h = v.parse(cls.base[v.E + "handoff.json"])
        for field in ("entries", "validation"):
            cls.base["data/latest/" + field + ".jsonl"] = b"".join(v.wire(x) for x in h[field])
        cls.base["data/latest/deferred.jsonl"] = b"".join(v.wire({"task_id": t["task_id"], **d}) for t in h["tasks"] for d in t["deferred"])
        cls.base["source/vulngym_agent/__init__.py"] = b"# Synthetic runtime, no provider.\n"
        cls.base["media/archival/T2-existing-results-demo.mp4"] = b"synthetic video bytes"
        cls.base["source/docs/submission/T2_DELIVERY_BRIEF.md"] = b"synthetic brief"
        cls.base["output/pdf/T2-design.pdf"] = b"synthetic pdf"
        cls.base["output/pdf/provenance.json"] = v.wire({"pages": 3, "visual_check": "passed_three_pages",
            "pdf": v.pin(b"synthetic pdf"), "source_sha256": sha256(b"synthetic brief").hexdigest()})

    def setUp(self):
        self.members = self.base.copy()
        self.runtime = patch.object(v, "RUNTIME", v.runtime_tree(self.members))
        self.video = patch.object(v, "VIDEO", sha256(self.members["media/archival/T2-existing-results-demo.mp4"]).hexdigest())
        self.runtime.start()
        self.video.start()
        self.addCleanup(self.runtime.stop)
        self.addCleanup(self.video.stop)
        seal(self.members)

    def rejected(self, code):
        with self.assertRaisesRegex(ValueError, "^" + code + "$"):
            v.validate_members(self.members)

    def review_change(self, update):
        r = v.parse(self.members[v.REVIEW])
        update(r)
        self.members[v.REVIEW] = v.wire(r)
        seal(self.members)

    def test_real_public_bindings_with_synthetic_runtime_and_media(self):
        result = v.validate_members(self.members)
        self.assertTrue(result["verified"])
        self.assertEqual(result["complete_candidates"], 1)
        self.assertEqual(result["deferred_tasks"], 1)

    def test_offline_demo_reports_limits(self):
        result = explain(self.members)
        self.assertEqual(result["new_model_calls"], 0)
        self.assertFalse(result["complete_T2_quality_acceptance"])
        self.assertIsNone(result["semantic_accuracy"])

    def test_dependency_closure_includes_function_local_and_transitive_imports(self):
        available = {"tests/a.py": b"def check():\n from scripts.b import value\n",
                     "scripts/b.py": b"from scripts import c\nvalue=1\n",
                     "scripts/c.py": b"import os\n"}
        result = with_local_dependencies({"tests/a.py": available["tests/a.py"]}, set(available),
                                         lambda names: {n: available[n] for n in names})
        self.assertEqual(result, available)

    def test_dependency_closure_does_not_execute_source(self):
        source = {"scripts/a.py": b"raise RuntimeError('must not execute')\nimport subprocess\n"}
        self.assertEqual(with_local_dependencies(source, set(source), lambda names: {}), source)

    def test_dependency_fetch_cannot_silently_omit_module(self):
        with self.assertRaisesRegex(ValueError, "local_dependency_missing"):
            with_local_dependencies({"tests/a.py": b"import scripts.b\n"}, {"scripts/b.py"}, lambda names: {})

    def test_zip_reproducible_and_readback(self):
        raw = archive_bytes(self.members)
        self.assertEqual(raw, archive_bytes(self.members))
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "bundle.zip"
            path.write_bytes(raw)
            self.assertEqual(v.read_archive(path), self.members)

    def test_unlisted_member(self):
        self.members["extra.txt"] = b"extra"
        self.rejected("file_set_mismatch")

    def test_changed_bytes(self):
        self.members[v.REVIEW] += b" "
        self.rejected("file_digest_mismatch")

    def test_source_inventory_must_match_actual_files(self):
        m = v.parse(self.members["MANIFEST.json"])
        m["source_files"] += 1
        self.members["MANIFEST.json"] = v.wire(m)
        self.rejected("source_inventory_mismatch")

    def test_pdf_must_match_reviewed_markdown(self):
        self.members["source/docs/submission/T2_DELIVERY_BRIEF.md"] += b"changed"
        seal(self.members)
        self.rejected("pdf_binding_changed")

    def test_resealed_runtime_cannot_change_pinned_identity(self):
        self.members["source/vulngym_agent/__init__.py"] += b"changed"
        seal(self.members)
        self.rejected("runtime_tree_mismatch")

    def test_resealed_evidence_cannot_replace_actual_run(self):
        self.members[v.E + "manifest.json"] += b" "
        seal(self.members)
        self.rejected("historical_evidence_changed")

    def test_resealed_evidence_child_cannot_change(self):
        self.members[v.E + "handoff.json"] += b" "
        seal(self.members)
        self.rejected("evidence_digest_mismatch")

    def test_candidate_projection_cannot_promote_verify(self):
        rows = [v.parse(line) for line in self.members["data/latest/entries.jsonl"].splitlines()]
        rows[0]["verify"] = 1
        self.members["data/latest/entries.jsonl"] = b"".join(v.wire(x) for x in rows)
        seal(self.members)
        self.rejected("projection_changed")

    def test_defer_projection_cannot_be_omitted(self):
        self.members["data/latest/deferred.jsonl"] = b""
        seal(self.members)
        self.rejected("projection_changed")

    def test_self_review_cannot_become_human(self):
        self.review_change(lambda r: r.update(independent_human_review_completed=True))
        self.rejected("review_claim_changed")

    def test_new_review_cannot_bind_old_candidate(self):
        self.review_change(lambda r: r["candidate_review"].update(candidate_sha256="0" * 64))
        self.rejected("review_binding")

    def test_review_counts_must_match_fields(self):
        self.review_change(lambda r: r["candidate_review"]["counts"].update(supported=5))
        self.rejected("review_counts_changed")

    def test_uncertain_field_needs_action(self):
        self.review_change(lambda r: r["candidate_review"]["fields"]["trace"].update(next_action=""))
        self.rejected("missing_action")

    def test_review_references_must_resolve(self):
        self.review_change(lambda r: r["candidate_review"]["fields"]["trace"].update(evidence_refs=["missing:1"]))
        self.rejected("unresolved_reference")

    def test_video_cannot_be_relabelled_live(self):
        m = v.parse(self.members["MANIFEST.json"])
        m["video_scope"] = "current_live_run"
        self.members["MANIFEST.json"] = v.wire(m)
        self.rejected("video_scope_changed")

    def test_no_overall_quality_promotion(self):
        m = v.parse(self.members["MANIFEST.json"])
        m["complete_T2_quality_acceptance"] = True
        self.members["MANIFEST.json"] = v.wire(m)
        self.rejected("quality_claim_changed")

    def test_no_credential_shape(self):
        self.members["README.md"] = b"sk-" + b"x" * 24
        seal(self.members)
        self.rejected("credential_shape")

    def test_no_machine_path_in_evidence(self):
        self.members["evidence/extra.txt"] = b"D:" + b"/local/example"
        seal(self.members)
        self.rejected("evidence_local_path")

    def test_duplicate_json_and_nonfinite_rejected(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}'):
            with self.assertRaises(ValueError):
                v.parse(raw)

    def test_noncanonical_and_reserved_paths_rejected(self):
        for name in ("../a", "/a", "a\\b", "a//b", "a/./b", "a/CON.txt", "a/name.", "a:stream"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                v.safe_name(name)

    def test_private_member_rejected(self):
        self.members["data/private/a.json"] = b"{}"
        self.rejected("prohibited_member")

    def test_case_collision_rejected(self):
        self.members["DATA/latest/entries.jsonl"] = b""
        self.rejected("case_collision")

    def test_duplicate_archive_names_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "bad.zip"
            with zipfile.ZipFile(p, "w") as z:
                z.writestr("A.txt", b"a")
                z.writestr("a.txt", b"b")
            with self.assertRaisesRegex(ValueError, "duplicate_zip_member"):
                v.read_archive(p)

    def test_symlink_archive_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "bad.zip"
            item = zipfile.ZipInfo("link")
            item.external_attr = 0o120777 << 16
            with zipfile.ZipFile(p, "w") as z:
                z.writestr(item, b"destination")
            with self.assertRaisesRegex(ValueError, "unexpected_link"):
                v.read_archive(p)


if __name__ == "__main__":
    unittest.main()
