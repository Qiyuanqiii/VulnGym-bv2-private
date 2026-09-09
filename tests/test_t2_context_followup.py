"""Pure follow-up collector tests using synthetic source strings only."""
from __future__ import annotations

import unittest
from types import MappingProxyType

from vulngym_agent.agents import t2_context_followup as context


def choice(path="src/a.py", line=100, symbol="helper"):
    return {"location": {"file": path, "line": line, "code": "helper(value)"}, "symbol": symbol}


def request(identifier="C-1", kind="window", reason="Need surrounding source"):
    return {"candidate_id": identifier, "kind": kind, "reason": reason}


def response(*requests):
    return {"action": "request_context", "requests": list(requests or (request(),))}


class FollowupContractTests(unittest.TestCase):
    def test_contract_advertises_exact_shape_and_remaining_round(self):
        contract = context.request_contract(["C-1", "E-1"])
        self.assertEqual(contract["candidate_ids"], ["C-1", "E-1"])
        self.assertEqual(contract["max_requests"], 2)
        self.assertEqual(contract["rounds_remaining"], 1)
        self.assertFalse(contract["extra_fields_allowed"])
        self.assertEqual(context.request_contract([], rounds_remaining=0)["rounds_remaining"], 0)
        for ids, rounds in ((["C-1", "C-1"], 1), ("C-1", 1), ([None], 1), ([], True), ([], 2)):
            with self.subTest(ids=ids, rounds=rounds), self.assertRaises(ValueError):
                context.request_contract(ids, rounds_remaining=rounds)

    def test_valid_requests_are_copied_without_semantic_endorsement(self):
        source = response(request(), request(kind="references", reason=" Find helper occurrences "))
        result = context.validate_requests(source, {"C-1": choice()})
        self.assertEqual(result, source["requests"])
        self.assertIsNot(result, source["requests"])
        self.assertIsNot(result[0], source["requests"][0])
        frozen = MappingProxyType({"action": "request_context", "requests": (MappingProxyType(request()),)})
        self.assertEqual(context.validate_requests(frozen, {"C-1": choice()}), [request()])

    def test_unknown_overlimit_duplicates_and_unadvertised_fields_rejected(self):
        values = [
            response(request("unknown")), response(request(), request(), request()),
            response(request(), request(reason="Different reason, same request")),
            {"action": "request_context", "requests": []},
            {"action": "request_context", "requests": "not requests"},
            {**response(), "path": "extra.py"}, response({**request(), "path": "extra.py"}),
            response(request(kind="calls")), response(request(reason=" ")),
            response(request(reason="x" * 201)), response(request(identifier=[])),
            response(request(kind=[])), response(request(reason=None)),
            {"action": "pick", "requests": [request()]}, None,
        ]
        for value in values:
            with self.subTest(value=value), self.assertRaises(ValueError):
                context.validate_requests(value, {"C-1": choice()})

    def test_bad_choice_location_is_rejected_without_scanning_other_choices(self):
        for location in (None, {}, {"file": "a.py", "line": True, "code": "x"},
                         {"file": "a.py", "line": 1, "code": None}):
            with self.subTest(location=location), self.assertRaises(ValueError):
                context.validate_requests(response(), {"C-1": {"location": location}})
        self.assertEqual(len(context.validate_requests(response(), {"C-1": choice(), "unused": None})), 1)


class FollowupCollectorTests(unittest.TestCase):
    def assert_complete_new_blocks(self, blocks, blobs, *, covered=None):
        seen = set(covered or ())
        self.assertLessEqual(len(blocks), context.MAX_BLOCKS)
        self.assertLessEqual(sum(len(block["text"]) for block in blocks), context.MAX_CHARS)
        for block in blocks:
            self.assertEqual(set(block), {"file", "line_start", "line_end", "text", "candidate_ids",
                                         "kind", "relationship_verified"})
            self.assertFalse(block["relationship_verified"])
            lines = blobs[block["file"]].splitlines()
            self.assertEqual(block["text"], "\n".join(lines[block["line_start"] - 1:block["line_end"]]))
            for number in range(block["line_start"], block["line_end"] + 1):
                identity = (block["file"], number)
                self.assertNotIn(identity, seen)
                seen.add(identity)

    def test_window_really_expands_around_existing_complete_context(self):
        lines = [f"line {number}" for number in range(1, 201)]
        blobs = {"src/a.py": "\n".join(lines)}
        prior = {"file": "src/a.py", "line_start": 76, "line_end": 124,
                 "text": "\n".join(lines[75:124]), "anchor_line_complete": True}
        blocks = context.collect_blocks([request()], {"C-1": choice()}, blobs, [prior])
        self.assertEqual([(block["line_start"], block["line_end"]) for block in blocks], [(40, 75), (125, 160)])
        self.assert_complete_new_blocks(blocks, blobs, covered={("src/a.py", n) for n in range(76, 125)})

    def test_no_new_context_returns_empty_and_out_of_prefix_anchor_is_safe(self):
        blobs = {"src/a.py": "first\nhelper(value)\nlast"}
        existing = [{"file": "src/a.py", "line_start": 1, "line_end": 3, "text": blobs["src/a.py"]}]
        self.assertEqual(context.collect_blocks([request()], {"C-1": choice(line=2)}, blobs, existing), [])
        self.assertEqual(context.collect_blocks([request()], {"C-1": choice(line=10**100)}, blobs, []), [])
        self.assertEqual(context.collect_blocks([request()], {"C-1": choice()}, {}, []), [])

    def test_partial_or_mismatched_prior_text_does_not_hide_source(self):
        blobs = {"src/a.py": "first\nhelper(value)\nlast"}
        for text, complete in (("truncated", True), (blobs["src/a.py"], False)):
            prior = {"file": "src/a.py", "line_start": 1, "line_end": 3,
                     "text": text, "anchor_line_complete": complete}
            blocks = context.collect_blocks([request()], {"C-1": choice(line=2)}, blobs, [prior])
            self.assertEqual(blocks[0]["text"], blobs["src/a.py"])

    def test_whitespace_only_new_gap_does_not_request_another_model_call(self):
        blobs = {"src/a.py": "def first(): pass\n \n\t\ndef second(): pass"}
        existing = [{"file": "src/a.py", "line_start": n, "line_end": n, "text": text}
                    for n, text in ((1, "def first(): pass"), (4, "def second(): pass"))]
        self.assertEqual(context.collect_blocks([request()], {"C-1": choice(line=1)}, blobs, existing), [])

    def test_references_are_literal_tokens_candidate_file_first(self):
        blobs = {"other.py": "helper(value)\n", "not-a-token.py": "myhelper()\nhelper2()\n$helper()\nhelper$()",
                 "src/a.py": "helper(value)\n"}
        blocks = context.collect_blocks([request(kind="references")], {"C-1": choice(line=1)}, blobs, [])
        self.assertEqual([block["file"] for block in blocks], ["src/a.py", "other.py"])
        self.assertTrue(all(block["kind"] == "references" for block in blocks))
        self.assert_complete_new_blocks(blocks, blobs)
        escaped = {"src/a.py": "aXb()", "other.py": "a.b()"}
        blocks = context.collect_blocks([request(kind="references")], {"C-1": choice(line=1, symbol="a.b")}, escaped, [])
        self.assertEqual([block["file"] for block in blocks], ["other.py"])

    def test_repeated_matches_and_overlapping_requests_do_not_duplicate_lines(self):
        lines = ["helper(value)" if n % 10 == 0 else f"line {n}" for n in range(1, 201)]
        blobs = {"src/a.py": "\n".join(lines)}
        blocks = context.collect_blocks([request(), request("E-1", "references")],
                                        {"C-1": choice(), "E-1": choice(line=10)}, blobs, [])
        self.assert_complete_new_blocks(blocks, blobs)

    def test_character_and_block_caps_preserve_whole_lines_and_skip_huge_lines(self):
        blobs = {"src/a.py": "\n".join(["A" * 9_000, "short", "B" * 7_900, "C" * 500, "tail"])}
        blocks = context.collect_blocks([request()], {"C-1": choice(line=1)}, blobs, [])
        self.assert_complete_new_blocks(blocks, blobs)
        self.assertEqual([(b["line_start"], b["line_end"]) for b in blocks], [(2, 3), (5, 5)])
        alternating = {"src/a.py": "\n".join(["small", "H" * 9_000] * 10)}
        blocks = context.collect_blocks([request()], {"C-1": choice(line=1)}, alternating, [])
        self.assertEqual(len(blocks), context.MAX_BLOCKS)
        self.assert_complete_new_blocks(blocks, alternating)

    def test_references_respect_file_and_scan_work_caps(self):
        blobs = {f"file-{n}.py": "no occurrence" for n in range(8)}
        blobs["last.py"] = "helper(value)"
        blocks = context.collect_blocks([request(kind="references")], {"C-1": choice(path="file-0.py", line=1)}, blobs, [])
        self.assertEqual(blocks, [])
        # A requested candidate file still wins over earlier supplied paths.
        blocks = context.collect_blocks([request(kind="references")], {"C-1": choice(path="last.py", line=1)}, blobs, [])
        self.assertEqual(blocks[0]["file"], "last.py")
        huge = {"src/a.py": "x" * (256 * 1_024 + 1) + "\nhelper(value)"}
        self.assertEqual(context.collect_blocks([request(kind="references")], {"C-1": choice(line=2)}, huge, []), [])

    def test_crlf_and_blank_lines_are_preserved_as_complete_lines(self):
        blobs = {"src/a.py": "first\r\n\r\nhelper(value)\r\n\r\n"}
        blocks = context.collect_blocks([request()], {"C-1": choice(line=3)}, blobs, [])
        self.assert_complete_new_blocks(blocks, blobs)
        self.assertEqual(blocks[0]["text"], "first\n\nhelper(value)\n")

    def test_invalid_collection_inputs_fail_boundedly(self):
        for requests, blobs, existing in (([], {}, []), ([request()], [], []),
                                          ([request()], {"src/a.py": b"source"}, []),
                                          ([request()], {}, [None]),
                                          ([request()], {}, [{}] * 257)):
            with self.subTest(requests=requests, blobs=blobs), self.assertRaises(ValueError):
                context.collect_blocks(requests, {"C-1": choice()}, blobs, existing)
        self.assertEqual(context.collect_blocks([request(kind="references")],
                                                {"C-1": choice(symbol=None)}, {"src/a.py": "helper()"}, []), [])


if __name__ == "__main__":
    unittest.main()
