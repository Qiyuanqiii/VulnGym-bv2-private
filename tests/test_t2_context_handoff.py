"""Offline package checks against public evidence, with in-memory negative cases."""
from hashlib import sha256
import json
from pathlib import Path
import unittest

from scripts.build_t2_context_handoff import archive_bytes, wire, pin
from scripts.verify_t2_context_handoff import E, REVIEW, validate_members, digest

ROOT = Path(__file__).resolve().parents[1]


def seal(members):
    evidence = json.loads(members[E + "manifest.json"])
    evidence["files"] = {name: pin(members[E + name]) for name in evidence["files"]}
    members[E + "manifest.json"] = wire(evidence)
    members["MANIFEST.json"] = wire({"schema": "t2.context-diagnostic-handoff.v1",
        "scope": "diagnostic_increment_not_final_delivery", "source_commit": "fixture",
        "files": {name: pin(raw) for name, raw in members.items() if name != "MANIFEST.json"}})


class ContextHandoffTests(unittest.TestCase):
    def setUp(self):
        manifest = json.loads((ROOT / E / "manifest.json").read_bytes())
        self.members = {E + name: (ROOT / E / name).read_bytes() for name in [*manifest["files"], "manifest.json"]}
        self.members[REVIEW] = (ROOT / REVIEW).read_bytes()
        seal(self.members)

    def change(self, name, transform):
        value = json.loads(self.members[name])
        transform(value)
        self.members[name] = wire(value)
        seal(self.members)

    def rebind_handoff(self):
        h = json.loads(self.members[E + "handoff.json"])
        h["handoff_sha256"] = digest({k: v for k, v in h.items() if k != "handoff_sha256"})
        self.members[E + "handoff.json"] = wire(h)
        self.change(E + "summary.json", lambda s: s.update(handoff_sha256=h["handoff_sha256"],
            handoff_file_sha256=sha256(self.members[E + "handoff.json"]).hexdigest()))

    def rejected(self, code):
        with self.assertRaisesRegex(ValueError, "^" + code + "$"):
            validate_members(self.members)

    def test_actual_public_bindings_and_nine_fields(self):
        result = validate_members(self.members)
        self.assertTrue(result["verified"])
        self.assertEqual(result["production_exit_code"], 1)
        self.assertEqual(result["new_model_calls"], 0)

    def test_archive_is_deterministic(self):
        self.assertEqual(archive_bytes(self.members), archive_bytes(self.members))

    def test_modified_bytes_without_new_manifest(self):
        self.members[REVIEW] += b" "
        self.rejected("file_digest_mismatch")

    def test_extra_file_not_hidden(self):
        self.members["extra"] = b"x"
        self.rejected("file_set_mismatch")

    def test_zero_exit_not_forged(self):
        self.change(E + "summary.json", lambda s: s.update(cli_exit_code=0))
        self.rejected("production_status_changed")

    def test_false_accuracy_not_accepted(self):
        self.change(E + "summary.json", lambda s: s.update(semantic_accuracy=0.5))
        self.rejected("quality_claim_changed")

    def test_human_claim_not_accepted(self):
        self.change(REVIEW, lambda r: r.update(independent_human_review_completed=True))
        self.rejected("review_claim_changed")

    def test_candidate_review_binding_not_swapped(self):
        self.change(REVIEW, lambda r: r.update(candidate_sha256="f" * 64))
        self.rejected("candidate_binding")

    def test_missing_uncertain_action_not_accepted(self):
        self.change(REVIEW, lambda r: r["fields"]["trace"].update(next_action=""))
        self.rejected("missing_action")

    def test_invented_evidence_reference_not_accepted(self):
        self.change(REVIEW, lambda r: r["fields"]["entry_role"].update(evidence_refs=["UNKNOWN:1"]))
        self.rejected("unresolved_reference")

    def test_missing_dimension_not_accepted(self):
        self.change(REVIEW, lambda r: r["fields"].pop("trace"))
        self.rejected("review_dimensions")

    def test_promoted_verify_not_accepted_even_with_rebound_handoff(self):
        self.change(E + "handoff.json", lambda h: h["entries"][0].update(verify=1))
        self.rebind_handoff()
        self.rejected("verify_promoted")

    def test_duplicate_key_not_accepted(self):
        self.members[REVIEW] = b'{"schema":"duplicate",' + self.members[REVIEW].lstrip()[1:]
        seal(self.members)
        self.rejected("duplicate_json_key")


if __name__ == "__main__":
    unittest.main()
