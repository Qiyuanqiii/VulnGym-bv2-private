"""Synthetic retrieval scheduling tests, not semantic truth or model outcomes."""
from copy import deepcopy
import unittest

from vulngym_agent.agents.t2_semantic_context import prioritize_context_candidates


def candidate(identifier, path="a.py", line=1, **clues):
    return {"candidate_id": identifier, "location": {"file": path, "line": line}, **clues}


class ContextAllocationTests(unittest.TestCase):
    def test_roles_and_paths_receive_early_turns(self):
        critical = [candidate("c-a1", line=100), candidate("c-a2", line=101),
                    candidate("c-b1", "b.py", 200)]
        entries = [candidate("e-a1", line=1), candidate("e-a2", line=95),
                   candidate("e-b1", "b.py", 190)]
        self.assertEqual(prioritize_context_candidates(critical, entries),
                         ["c-a1", "e-a2", "c-b1", "e-b1", "c-a2", "e-a1"])

    def test_late_nearby_declaration_precedes_early_unrelated_declarations(self):
        critical = [candidate("c", line=2352)]
        entries = [candidate(f"e-{n}", line=n * 150) for n in range(1, 10)]
        entries.append(candidate("e-late", line=2291))
        order = prioritize_context_candidates(critical, entries)
        self.assertEqual(order[:2], ["c", "e-late"])
        self.assertEqual(set(order), {c["candidate_id"] for c in critical + entries})

    def test_existing_binding_clues_only_change_retrieval_priority(self):
        critical = [candidate("c", line=100)]
        entries = [candidate("near", line=99), candidate("direct", line=1, direct_critical_reference=True),
                   candidate("bound", line=2, explicit_external_binding=True)]
        original = deepcopy((critical, entries))
        self.assertEqual(prioritize_context_candidates(critical, entries), ["c", "bound", "direct", "near"])
        self.assertEqual((critical, entries), original)
        self.assertTrue(all("semantic_verified" not in c for c in critical + entries))

    def test_equal_locations_keep_distinct_ids_and_stable_ties(self):
        critical = [candidate("c", line=10)]
        entries = [candidate("e1", line=10), candidate("e2", line=10)]
        self.assertEqual(prioritize_context_candidates(critical, entries), ["c", "e1", "e2"])

    def test_no_critical_same_path_uses_stable_round_robin(self):
        entries = [candidate("a1"), candidate("a2"), candidate("b1", "b.py")]
        self.assertEqual(prioritize_context_candidates([], entries), ["a1", "b1", "a2"])

    def test_empty_inputs_and_one_role(self):
        self.assertEqual(prioritize_context_candidates([], []), [])
        self.assertEqual(prioritize_context_candidates([candidate("c")], []), ["c"])

    def test_duplicate_ids_are_rejected(self):
        with self.assertRaises(ValueError):
            prioritize_context_candidates([candidate("same")], [candidate("same")])

    def test_invalid_location_or_identity_is_rejected(self):
        bad = [{}, candidate(""), candidate("c", line=0), candidate("c", line=True),
               candidate("c", path=""), {"candidate_id": "c", "location": None}]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(ValueError):
                prioritize_context_candidates([value], [])

    def test_repeated_scheduling_is_deterministic_and_preserves_inputs(self):
        critical = [candidate(f"c{n}", f"{n % 3}.py", n * 10 + 1) for n in range(12)]
        entries = [candidate(f"e{n}", f"{n % 3}.py", n * 15 + 1) for n in range(36)]
        before = deepcopy((critical, entries))
        self.assertEqual(prioritize_context_candidates(critical, entries),
                         prioritize_context_candidates(critical, entries))
        self.assertEqual((critical, entries), before)


if __name__ == "__main__":
    unittest.main()
