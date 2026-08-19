from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import unittest

from vulngym_agent import (
    EvidenceItem,
    FieldValidation,
    SchemaAdapter,
    SchemaAdapterError,
    ValidationReport,
    adapt_t2_entry,
)
from vulngym_agent.adapters import ENTRY_FIELDS, MAX_TRACE_NODES


ROOT = Path(__file__).resolve().parents[1]


class SchemaAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        first_line = (ROOT / "data" / "entries.jsonl").read_text(
            encoding="utf-8"
        ).splitlines()[0]
        cls.real_entry = json.loads(first_line)

    def setUp(self) -> None:
        self.adapter = SchemaAdapter()
        self.entry = deepcopy(self.real_entry)

    def test_real_first_entry_satisfies_official_contract(self) -> None:
        result = self.adapter.validate(self.entry)

        self.assertTrue(result.valid, result.to_dict())
        normalized = self.adapter.normalize(self.entry)
        self.assertEqual(normalized["verify"], 1)
        self.assertEqual(tuple(normalized), ENTRY_FIELDS)

    def test_all_408_entries_satisfy_official_schema(self) -> None:
        failures = []
        lines = (ROOT / "data" / "entries.jsonl").read_text(
            encoding="utf-8"
        ).splitlines()

        for line_number, line in enumerate(lines, start=1):
            result = self.adapter.validate(json.loads(line))
            if not result.valid:
                failures.append(
                    {
                        "line": line_number,
                        "issues": [issue.to_dict() for issue in result.issues],
                    }
                )

        self.assertEqual(len(lines), 408)
        self.assertEqual(failures, [])

    def test_trace_node_count_has_a_fixed_schema_cap_and_configurable_lower_cap(
        self,
    ) -> None:
        node = deepcopy(self.entry["entry_point"])
        candidate = deepcopy(self.entry)
        candidate["trace"] = [deepcopy(node) for _ in range(MAX_TRACE_NODES + 1)]

        result = self.adapter.validate(candidate)

        issue = next(issue for issue in result.issues if issue.path == "$.trace")
        self.assertEqual(issue.code, "max_items")
        self.assertEqual(
            issue.context,
            {"maximum": MAX_TRACE_NODES, "actual": MAX_TRACE_NODES + 1},
        )

        candidate["trace"] = [deepcopy(node), deepcopy(node), deepcopy(node)]
        configured = SchemaAdapter(max_trace_nodes=2).validate(candidate)
        self.assertTrue(
            any(issue.code == "max_items" for issue in configured.issues)
        )

        for invalid in (0, -1, True, MAX_TRACE_NODES + 1):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                SchemaAdapter(max_trace_nodes=invalid)

    def test_reports_extra_and_missing_fields_individually(self) -> None:
        self.entry["confidence"] = 0.99
        del self.entry["critical_operation"]
        self.entry["entry_point"]["evidence_ids"] = ["EV-EXAMPLE"]

        with self.assertRaises(SchemaAdapterError) as raised:
            self.adapter.adapt(self.entry, formal_t2=False)

        issues = {(issue.path, issue.code) for issue in raised.exception.issues}
        self.assertIn(("$.confidence", "extra_field"), issues)
        self.assertIn(("$.critical_operation", "missing_required"), issues)
        self.assertIn(("$.entry_point.evidence_ids", "extra_field"), issues)

        dotted = dict(self.entry)
        dotted["commit.injected"] = "not a real field"
        dotted_paths = {issue.path for issue in self.adapter.validate(dotted).issues}
        self.assertIn('$["commit.injected"]', dotted_paths)

    def test_missing_critical_location_members_are_not_invented(self) -> None:
        del self.entry["entry_point"]["line"]
        del self.entry["critical_operation"]

        with self.assertRaises(SchemaAdapterError) as raised:
            adapt_t2_entry(self.entry)

        issue_paths = {issue.path for issue in raised.exception.issues}
        self.assertIn("$.entry_point.line", issue_paths)
        self.assertIn("$.critical_operation", issue_paths)

    def test_rejects_descending_line_range(self) -> None:
        self.entry["critical_operation"]["line"] = "352-348"

        with self.assertRaises(SchemaAdapterError) as raised:
            self.adapter.normalize(self.entry)

        issue = next(
            issue
            for issue in raised.exception.issues
            if issue.path == "$.critical_operation.line"
        )
        self.assertEqual(issue.code, "range_order")
        self.assertEqual(issue.context, {"start": 352, "end": 348})

    def test_extreme_line_numbers_report_errors_without_aborting(self) -> None:
        for line in ("9" * 5000, "1-" + "9" * 5000):
            with self.subTest(kind="range" if "-" in line else "numeric"):
                candidate = deepcopy(self.entry)
                candidate["entry_point"]["line"] = line

                result = self.adapter.validate(candidate)
                self.assertFalse(result.valid)
                self.assertTrue(
                    any(issue.path == "$.entry_point.line" for issue in result.issues)
                )
                with self.assertRaises(SchemaAdapterError):
                    self.adapter.normalize(candidate)

    def test_normalizes_numeric_line_ids_and_formal_t2_verify(self) -> None:
        report_id = self.entry["report_id"]
        cve_id = next(
            identifier
            for identifier in self.entry["vuln_ids"]
            if identifier.startswith("CVE-")
        )
        self.entry["report_id"] = report_id.lower()
        self.entry["vuln_ids"] = [
            report_id.lower(),
            cve_id.lower(),
            cve_id,
            report_id,
        ]
        self.entry["entry_point"]["line"] = "97"
        self.entry["verify"] = 1

        adapted = adapt_t2_entry(self.entry)

        self.assertEqual(adapted["report_id"], report_id)
        self.assertEqual(adapted["vuln_ids"], [cve_id, report_id])
        self.assertEqual(adapted["entry_point"]["line"], 97)
        self.assertIsInstance(adapted["entry_point"]["line"], int)
        self.assertEqual(adapted["verify"], 0)

    def test_formal_entry_has_no_sidecar_fields(self) -> None:
        adapted = adapt_t2_entry(self.entry)
        sidecar_names = {
            "confidence",
            "status",
            "evidence_ids",
            "alternatives",
            "assumptions",
            "tool_calls",
        }

        self.assertEqual(set(adapted), set(ENTRY_FIELDS))
        self.assertFalse(set(adapted) & sidecar_names)

        contaminated = deepcopy(self.entry)
        contaminated["evidence_ids"] = ["EV-NOT-ALLOWED"]
        with self.assertRaises(SchemaAdapterError):
            adapt_t2_entry(contaminated)

    def test_schema_documents_are_strict_json(self) -> None:
        loaded = {}
        for name in (
            "entry.schema.json",
            "validation.schema.json",
            "evidence.schema.json",
        ):
            schema = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
            self.assertFalse(schema["additionalProperties"], name)
            loaded[name] = schema

        self.assertEqual(
            loaded["validation.schema.json"]["properties"]["report_id"]["type"],
            ["string", "null"],
        )
        self.assertEqual(
            loaded["entry.schema.json"]["properties"]["trace"]["maxItems"],
            MAX_TRACE_NODES,
        )

    def test_sidecar_dataclasses_are_directly_json_serializable(self) -> None:
        evidence = EvidenceItem(
            evidence_id="EV-GHSA-001-SOURCE-04",
            report_id=self.entry["report_id"],
            source_type="source",
            snippet=self.entry["entry_point"]["code"],
            commit=self.entry["commit"],
            file=self.entry["entry_point"]["file"],
            line_start=97,
            line_end=97,
        )
        field = FieldValidation(
            status="correct",
            confidence=0.95,
            evidence="源码中的入口与候选记录一致。",
            evidence_refs=(evidence.evidence_id,),
        )
        report = ValidationReport(
            report_id=self.entry["report_id"],
            verdict="correct",
            fields={"entry_point": field},
            summary="入口字段验证通过。",
        )

        self.assertEqual(json.loads(evidence.to_json())["source_type"], "source")
        payload = json.loads(report.to_json())
        self.assertEqual(payload["fields"]["entry_point"]["status"], "correct")
        self.assertEqual(payload["missing_information"], [])

    def test_evidence_model_rejects_values_outside_its_schema(self) -> None:
        base = {
            "evidence_id": "EV-VALID-01",
            "report_id": self.entry["report_id"],
            "source_type": "source",
            "snippet": "real code",
        }
        invalid_overrides = (
            {"evidence_id": "bad id"},
            {"report_id": "not-a-ghsa"},
            {"entry_id": "entry-x"},
            {"source_type": "network"},
            {"snippet": " "},
            {"commit": "A" * 40},
            {"line_start": 4},
            {"line_start": 5, "line_end": 4},
        )
        for override in invalid_overrides:
            with self.subTest(override=override), self.assertRaises(ValueError):
                EvidenceItem(**(base | override))

    def test_uncertain_report_can_serialize_without_report_id(self) -> None:
        field = FieldValidation(
            status="uncertain",
            confidence=0.0,
            evidence="输入不是可解析的 JSON，无法提取 report_id。",
        )
        report = ValidationReport(
            report_id=None,
            verdict="uncertain",
            fields={"report_id": field},
            summary="候选输入无法解析，结论为 uncertain。",
            missing_information=("report_id",),
        )

        payload = json.loads(report.to_json())
        self.assertIsNone(payload["report_id"])
        self.assertEqual(payload["verdict"], "uncertain")

    def test_field_validation_rejects_invalid_sidecar_values(self) -> None:
        invalid_values = (
            {"status": "unknown", "confidence": 0.5, "evidence": "说明"},
            {"status": "correct", "confidence": -0.01, "evidence": "说明"},
            {"status": "correct", "confidence": 1.01, "evidence": "说明"},
            {"status": "correct", "confidence": float("nan"), "evidence": "说明"},
            {"status": "correct", "confidence": True, "evidence": "说明"},
            {"status": "correct", "confidence": 0.5, "evidence": "   "},
            {
                "status": "incorrect",
                "confidence": 1.0,
                "evidence": "说明",
                "suggested_fix": {"unexpected": "mapping"},
            },
            {
                "status": "incorrect",
                "confidence": 1.0,
                "evidence": "说明",
                "suggested_fix": {"file": "a.py", "line": "9-3", "code": "x"},
            },
            {
                "status": "incorrect",
                "confidence": 1.0,
                "evidence": "说明",
                "suggested_fix": ["GHSA-AAAA-BBBB-CCCC", {"file": "a.py"}],
            },
        )

        for values in invalid_values:
            with self.subTest(values=values), self.assertRaises(ValueError):
                FieldValidation(**values)

        valid = FieldValidation(
            status="incorrect",
            confidence=1.0,
            evidence="位置需要修正。",
            suggested_fix={"file": "a.py", "line": "3-9", "code": "safe()"},
        )
        self.assertEqual(valid.to_dict()["suggested_fix"]["line"], "3-9")

    def test_validation_report_rejects_invalid_verdict_and_summary(self) -> None:
        field = FieldValidation(
            status="uncertain", confidence=0.0, evidence="证据不足。"
        )

        with self.assertRaises(ValueError):
            ValidationReport(
                report_id=None,
                verdict="unknown",
                fields={"report_id": field},
                summary="无法验证。",
            )
        with self.assertRaises(ValueError):
            ValidationReport(
                report_id=None,
                verdict="uncertain",
                fields={"report_id": field},
                summary="  ",
            )


if __name__ == "__main__":
    unittest.main()
