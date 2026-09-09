"""Synthetic retrieval scheduling tests, not semantic truth or model outcomes."""
from copy import deepcopy
import unittest

from vulngym_agent.agents.t2_semantic_context import (
    prioritize_context_candidates, remove_covered_lines, source_window,
)


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


class PairedWindowTests(unittest.TestCase):
    def test_long_function_keeps_both_nearby_anchors_and_intervening_lines(self):
        text = "def entry(request):\n" + "    value = request\n" * 150
        block = source_window(text, "a.py", 62, companion_lines=[1])
        self.assertLessEqual(block["line_start"], 1)
        self.assertGreaterEqual(block["line_end"], 62)
        self.assertEqual(block["companion_anchor_line"], 1)
        self.assertLessEqual(len(block["text"]), 3000)
        self.assertEqual(block["text"], "\n".join(text.splitlines()[block["line_start"] - 1:block["line_end"]]))
        self.assertFalse(block["complete_function"])
        self.assertFalse(block["call_relationship_verified"])
        self.assertEqual(block["relationship_assessment"], "not_assessed_by_context_collector")

    def test_nearby_non_python_anchors_do_not_claim_function_or_relationship(self):
        text = "\n".join(f"line {n}" for n in range(1, 200))
        block = source_window(text, "a.ts", 100, companion_lines=[130, 70, 170])
        self.assertEqual(block["companion_anchor_line"], 70)  # stable distance tie
        self.assertEqual(block["selection"], "paired_anchor_window")
        self.assertFalse(block["complete_function"])
        self.assertIn("not_a_verified_edge", block["companion_basis"])

    def test_pair_does_not_cross_known_function_boundary(self):
        text = "def first():\n    return 1\n\ndef second():\n    return 2\n"
        block = source_window(text, "a.py", 5, companion_lines=[1])
        self.assertIsNone(block["companion_anchor_line"])
        self.assertEqual((block["line_start"], block["line_end"]), (4, 5))

    def test_distant_same_or_over_budget_companions_cannot_expand_the_budget(self):
        text = "\n".join("x" * 50 for _ in range(250))
        for companions in ([70], [200], [75]):
            block = source_window(text, "a.ts", 75, companion_lines=companions, max_chars=120)
            self.assertIsNone(block["companion_anchor_line"])
            self.assertTrue(block["line_start"] <= 75 <= block["line_end"])
            self.assertLessEqual(len(block["text"]), 120)

    def test_companion_values_must_be_real_in_range_line_numbers(self):
        for companions in ([True], [0], [4], ["1"], "1", {"line": 1}, None):
            with self.subTest(companions=companions), self.assertRaises(ValueError):
                source_window("a\nb\nc", "a.ts", 2, companion_lines=companions)

    def test_overlong_primary_line_remains_explicitly_incomplete(self):
        block = source_window("short\n" + "x" * 900, "a.ts", 2, companion_lines=[1], max_chars=100)
        self.assertEqual(block["text"], "x" * 100)
        self.assertFalse(block["anchor_line_complete"])
        self.assertIsNone(block["companion_anchor_line"])

    def test_edge_overlap_is_removed_without_losing_anchor_or_line_identity(self):
        text = "\n".join(f"line {n}" for n in range(1, 180))
        left = source_window(text, "a.ts", 30)
        right = source_window(text, "a.ts", 110)
        middle = source_window(text, "a.ts", 70)
        before = deepcopy((middle, left, right))
        block = remove_covered_lines(middle, [left, right])
        self.assertEqual((block["line_start"], block["line_end"]), (55, 85))
        self.assertEqual(block["text"], "\n".join(text.splitlines()[54:85]))
        self.assertTrue(block["anchor_line_complete"])
        self.assertFalse(block["complete_function"])
        self.assertEqual((middle, left, right), before)

    def test_pair_companion_trimmed_from_window_stops_claiming_inclusion(self):
        text = "\n".join(f"line {n}" for n in range(1, 150))
        block = source_window(text, "a.ts", 100, companion_lines=[70])
        prior = source_window(text, "a.ts", 50)
        clipped = remove_covered_lines(block, [prior])
        self.assertIsNone(clipped["companion_anchor_line"])
        self.assertIsNone(clipped["companion_basis"])

    def test_other_file_or_incomplete_line_is_not_reusable_coverage(self):
        text = "\n".join(f"line {n}" for n in range(1, 150))
        block = source_window(text, "a.ts", 70)
        other = source_window(text, "b.ts", 70)
        partial = {**block, "anchor_line_complete": False}
        self.assertEqual(remove_covered_lines(block, [other, partial]), block)

    def test_already_covered_anchor_must_reuse_existing_evidence(self):
        block = source_window("a\nb\nc", "a.ts", 2)
        with self.assertRaisesRegex(ValueError, "already_covered"):
            remove_covered_lines(block, [block])

    def test_many_windows_preserve_all_new_anchors_without_duplicate_lines(self):
        for extension in ("ts", "py"):
            text = "\n".join(f"value = {n}" for n in range(1, 300))
            blocks = []
            for anchor in (50, 100, 75, 200, 145, 250, 295, 1):
                if any(b["line_start"] <= anchor <= b["line_end"] for b in blocks):
                    continue
                block = source_window(text, "a." + extension, anchor, companion_lines=[160])
                block = remove_covered_lines(block, blocks)
                self.assertTrue(block["line_start"] <= anchor <= block["line_end"])
                self.assertEqual(block["text"], "\n".join(text.splitlines()[block["line_start"] - 1:block["line_end"]]))
                blocks.append(block)
            covered = [n for b in blocks for n in range(b["line_start"], b["line_end"] + 1)]
            self.assertEqual(len(covered), len(set(covered)))


class ContextProbeTests(unittest.TestCase):
    def test_probe_only_replays_routing_and_stops_before_inference(self):
        from types import SimpleNamespace
        from scripts.probe_t2_context_delivery_v2 import CaptureOnlyBackend, PLAN
        from vulngym_agent.agents.model_runtime import ModelBlocked
        backend = CaptureOnlyBackend()
        self.assertEqual(backend.invoke(SimpleNamespace(stage="plan")), PLAN)
        with self.assertRaisesRegex(ModelBlocked, "offline_context_capture_no_provider"):
            backend.invoke(SimpleNamespace(stage="semantic_judge", payload={"context": (1, 2)}))
        self.assertEqual(backend.semantic, {"context": [1, 2]})
        with self.assertRaisesRegex(ValueError, "unexpected_stage"):
            backend.invoke(SimpleNamespace(stage="reflection"))

    def test_probe_does_not_accept_inference_without_recorded_plan(self):
        from types import SimpleNamespace
        from scripts.probe_t2_context_delivery_v2 import CaptureOnlyBackend
        with self.assertRaisesRegex(ValueError, "unexpected_stage"):
            CaptureOnlyBackend().invoke(SimpleNamespace(stage="semantic_judge", payload={}))

    def test_metrics_count_overlap_and_do_not_treat_partial_lines_as_complete(self):
        from scripts.probe_t2_context_delivery_v2 import metrics
        def block(first, last, complete=True):
            return dict(file="a.ts", line_start=first, line_end=last, candidate_ids=[],
                        complete_function=False, anchor_line_complete=complete)
        ctx = dict(source_contexts=[block(1, 3), block(3, 5), block(6, 6, False)],
                   source_chars=20, source_files_read=1, candidate_context_coverage=[])
        result = metrics(ctx)
        self.assertEqual(result["unique_complete_source_lines"], 5)
        self.assertEqual(result["repeated_complete_source_lines"], 1)
        self.assertNotIn("semantic_accuracy", result)


if __name__ == "__main__":
    unittest.main()
