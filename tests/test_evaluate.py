from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from examples.evaluate import (
    _endpoint_match,
    evaluate,
    line_span_distance,
    line_span_width,
    load_jsonl,
    normalize_line_span,
    normalize_repo,
)


REPO_ROOT = Path(__file__).resolve().parent.parent


class LineSpanTests(unittest.TestCase):
    def test_normalizes_integer_and_range_locations(self) -> None:
        self.assertEqual(normalize_line_span(12), (12, 12))
        self.assertEqual(normalize_line_span("12"), (12, 12))
        self.assertEqual(normalize_line_span("12-19"), (12, 19))

    def test_rejects_invalid_locations(self) -> None:
        for value in (
            None,
            True,
            0,
            -1,
            "0",
            "19-12",
            "12-",
            "a-b",
            "9" * 5_000,
            "1-" + "9" * 5_000,
        ):
            with self.subTest(value=value):
                self.assertIsNone(normalize_line_span(value))

    def test_span_distance_uses_nearest_endpoints(self) -> None:
        self.assertEqual(line_span_distance((10, 15), (12, 20)), 0)
        self.assertEqual(line_span_distance((10, 15), (18, 20)), 3)
        self.assertEqual(line_span_distance((18, 20), (10, 15)), 3)

    def test_span_width_is_inclusive(self) -> None:
        self.assertEqual(line_span_width((10, 10)), 1)
        self.assertEqual(line_span_width((10, 15)), 6)

    def test_repo_normalization_lowercases_only_url_authority(self) -> None:
        self.assertEqual(
            normalize_repo("HTTPS://GITHUB.COM/Owner/Repo.git/"),
            "https://github.com/Owner/Repo",
        )


class EndpointMatchTests(unittest.TestCase):
    def test_integer_finding_matches_ground_truth_range(self) -> None:
        ground_truth = {"file": "src/example.py", "line": "112-119"}
        self.assertTrue(
            _endpoint_match(
                {"file": "./src/example.py", "line": 119},
                ground_truth,
                tolerance=0,
            )
        )
        self.assertTrue(
            _endpoint_match(
                {"file": "src/example.py", "line": 124},
                ground_truth,
                tolerance=5,
            )
        )
        self.assertFalse(
            _endpoint_match(
                {"file": "src/example.py", "line": 125},
                ground_truth,
                tolerance=5,
            )
        )

    def test_range_finding_matches_overlapping_ground_truth_range(self) -> None:
        self.assertTrue(
            _endpoint_match(
                {"file": "src/example.py", "line": "108-113"},
                {"file": "src/example.py", "line": "112-119"},
                tolerance=0,
            )
        )

    def test_rejects_unbounded_finding_range(self) -> None:
        endpoint = {"file": "src/example.py", "line": 112}
        self.assertFalse(
            _endpoint_match(
                {"file": "src/example.py", "line": "1-999999"},
                endpoint,
                tolerance=5,
            )
        )

    def test_finding_span_may_use_only_the_tolerance_envelope(self) -> None:
        endpoint = {"file": "src/example.py", "line": 112}
        self.assertTrue(
            _endpoint_match(
                {"file": "src/example.py", "line": "107-117"},
                endpoint,
                tolerance=5,
            )
        )
        self.assertFalse(
            _endpoint_match(
                {"file": "src/example.py", "line": "106-117"},
                endpoint,
                tolerance=5,
            )
        )

    def test_unbounded_ranges_cannot_obtain_full_recall(self) -> None:
        entry = {
            "entry_id": "entry-range-cheat",
            "report_id": "GHSA-TEST-TEST-TEST",
            "repo_url": "https://github.com/example/project",
            "commit": "a" * 40,
            "entry_point": {"file": "src/source.py", "line": 10},
            "critical_operation": {"file": "src/sink.py", "line": 30},
        }
        finding = {
            "repo_url": entry["repo_url"],
            "commit": entry["commit"],
            "entry_point": {"file": "src/source.py", "line": "1-999999"},
            "critical_operation": {"file": "src/sink.py", "line": "1-999999"},
        }

        report = evaluate([entry], [finding], tolerance=5)

        self.assertEqual(report["recall"]["entry_level"]["numerator"], 0)
        self.assertEqual(report["findings"][0]["matched_entry_ids"], [])

    def test_non_object_endpoint_is_unmatched_instead_of_crashing(self) -> None:
        self.assertFalse(
            _endpoint_match(
                {"file": "src/example.py", "line": 10},
                ["not", "an", "object"],
                tolerance=5,
            )
        )


class EvaluationTests(unittest.TestCase):
    def test_loader_rejects_non_object_jsonl_with_line_number(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "findings.jsonl"
            path.write_text('{}\n42\n', encoding="utf-8")

            with self.assertRaisesRegex(
                SystemExit, r"findings\.jsonl:2: each JSONL line must contain one object"
            ):
                load_jsonl(path)

    def test_programmatic_non_object_finding_is_reported_unmatched(self) -> None:
        report = evaluate([], [42], tolerance=5)

        self.assertEqual(report["totals"]["findings"], 1)
        self.assertEqual(report["findings"][0]["matched_entry_ids"], [])
        self.assertEqual(
            report["findings"][0]["invalid_reason"],
            "finding is not a JSON object",
        )

    def test_range_endpoints_are_usable_and_matchable(self) -> None:
        entry = {
            "entry_id": "entry-test",
            "report_id": "GHSA-TEST-TEST-TEST",
            "repo_url": "https://github.com/example/project",
            "commit": "a" * 40,
            "entry_point": {"file": "src/source.py", "line": "10-12"},
            "critical_operation": {"file": "src/sink.py", "line": "30-35"},
        }
        finding = {
            "repo_url": entry["repo_url"],
            "commit": entry["commit"],
            "entry_point": {"file": "src/source.py", "line": 11},
            "critical_operation": {"file": "src/sink.py", "line": 35},
        }

        report = evaluate([entry], [finding], tolerance=0)

        self.assertEqual(report["totals"]["usable_entries"], 1)
        self.assertEqual(report["totals"]["skipped_entries_invalid_line"], 0)
        self.assertEqual(report["recall"]["entry_level"]["numerator"], 1)
        self.assertEqual(report["findings"][0]["matched_entry_ids"], ["entry-test"])

    def test_invalid_ground_truth_locations_are_skipped(self) -> None:
        entry = {
            "entry_id": "entry-invalid",
            "report_id": "GHSA-TEST-TEST-TEST",
            "repo_url": "https://github.com/example/project",
            "commit": "a" * 40,
            "entry_point": {"file": "src/source.py", "line": 0},
            "critical_operation": {"file": "src/sink.py", "line": 35},
        }

        report = evaluate([entry], [], tolerance=5)

        self.assertEqual(report["totals"]["usable_entries"], 0)
        self.assertEqual(report["totals"]["skipped_entries_invalid_line"], 1)
        self.assertEqual(report["totals"]["skipped_entries_line_zero"], 1)

    def test_current_dataset_self_matches_at_zero_tolerance(self) -> None:
        entries = load_jsonl(REPO_ROOT / "data" / "entries.jsonl")
        findings = [
            {
                "repo_url": entry["repo_url"],
                "commit": entry["commit"],
                "entry_point": {
                    "file": entry["entry_point"]["file"],
                    "line": entry["entry_point"]["line"],
                },
                "critical_operation": {
                    "file": entry["critical_operation"]["file"],
                    "line": entry["critical_operation"]["line"],
                },
            }
            for entry in entries
        ]

        report = evaluate(entries, findings, tolerance=0)

        self.assertEqual(report["totals"]["skipped_entries_invalid_line"], 0)
        self.assertEqual(report["recall"]["entry_level"]["numerator"], len(entries))
        self.assertEqual(report["recall"]["entry_level"]["denominator"], len(entries))


if __name__ == "__main__":
    unittest.main()
