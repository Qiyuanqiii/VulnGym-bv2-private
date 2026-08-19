from __future__ import annotations

from dataclasses import FrozenInstanceError
import json
import unittest

from vulngym_agent.orchestrator.budget import (
    BUDGET_RESOURCES,
    LLM_CALLS,
    REPAIR_ITERATIONS,
    TOOL_CALLS,
    Budget,
    BudgetEvent,
    BudgetExceeded,
    Limits,
    Usage,
)


class LimitsTests(unittest.TestCase):
    def test_defaults_and_canonical_new_name(self) -> None:
        limits = Limits()

        self.assertEqual(limits.max_llm_calls, 16)
        self.assertEqual(limits.max_tool_calls, 80)
        self.assertEqual(limits.max_repair_iterations, 2)
        self.assertEqual(limits.max_iterations, 2)
        self.assertEqual(
            limits.to_dict(),
            {
                "max_llm_calls": 16,
                "max_tool_calls": 80,
                "max_repair_iterations": 2,
            },
        )
        self.assertNotIn("max_iterations", limits.to_canonical_json())
        self.assertEqual(json.loads(limits.to_canonical_json()), limits.to_dict())

    def test_reads_legacy_max_iterations_but_writes_new_name(self) -> None:
        limits = Limits.from_dict(
            {"max_llm_calls": 4, "max_tool_calls": 7, "max_iterations": 1}
        )
        from_json = Limits.from_json('{"max_iterations":0}')

        self.assertEqual(limits, Limits(4, 7, 1))
        self.assertEqual(from_json.max_repair_iterations, 0)
        self.assertEqual(
            set(limits.to_dict()),
            {"max_llm_calls", "max_tool_calls", "max_repair_iterations"},
        )

    def test_accepts_equal_legacy_and_new_values(self) -> None:
        limits = Limits.from_dict(
            {"max_iterations": 2, "max_repair_iterations": 2}
        )

        self.assertEqual(limits.max_repair_iterations, 2)

    def test_rejects_conflicting_legacy_value_and_unknown_fields(self) -> None:
        with self.assertRaisesRegex(ValueError, "conflicts"):
            Limits.from_dict(
                {"max_iterations": 1, "max_repair_iterations": 2}
            )
        with self.assertRaisesRegex(ValueError, "unknown limit"):
            Limits.from_dict({"max_llm_call": 3})
        with self.assertRaisesRegex(ValueError, "JSON object"):
            Limits.from_json("[]")

    def test_limits_are_immutable_and_reject_invalid_integer_boundaries(self) -> None:
        with self.assertRaises(FrozenInstanceError):
            Limits().max_llm_calls = 99  # type: ignore[misc]

        self.assertEqual(Limits(0, 0, 0), Limits(0, 0, 0))
        for field_name in (
            "max_llm_calls",
            "max_tool_calls",
            "max_repair_iterations",
        ):
            for invalid in (-1, True, False, 1.5, "1", None):
                with self.subTest(field=field_name, invalid=invalid):
                    values = {
                        "max_llm_calls": 1,
                        "max_tool_calls": 1,
                        "max_repair_iterations": 1,
                    }
                    values[field_name] = invalid
                    with self.assertRaises(ValueError):
                        Limits(**values)  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValueError, "cannot exceed 2"):
            Limits(max_repair_iterations=3)


class UsageAndEventTests(unittest.TestCase):
    def test_usage_is_immutable_validated_and_incremented_functionally(self) -> None:
        usage = Usage(llm_calls=1)
        changed = usage.incremented(TOOL_CALLS, 2)

        self.assertEqual(usage, Usage(llm_calls=1))
        self.assertEqual(changed, Usage(llm_calls=1, tool_calls=2))
        with self.assertRaises(FrozenInstanceError):
            usage.llm_calls = 2  # type: ignore[misc]

        for invalid in (-1, True, 1.2, "1"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                Usage(llm_calls=invalid)  # type: ignore[arg-type]

    def test_budget_event_is_immutable_and_has_no_nondeterministic_fields(self) -> None:
        event = BudgetEvent(
            sequence=1,
            resource=LLM_CALLS,
            amount=1,
            usage_after=Usage(llm_calls=1),
            operation="produce",
        )

        self.assertEqual(
            event.to_dict(),
            {
                "sequence": 1,
                "resource": "llm_calls",
                "amount": 1,
                "usage_after": {
                    "llm_calls": 1,
                    "tool_calls": 0,
                    "repair_iterations": 0,
                },
                "operation": "produce",
            },
        )
        self.assertNotIn("time", json.dumps(event.to_dict()))
        with self.assertRaises(FrozenInstanceError):
            event.amount = 2  # type: ignore[misc]


class BudgetTests(unittest.TestCase):
    def test_require_would_exceed_remaining_and_exact_boundary(self) -> None:
        budget = Budget(Limits(1, 2, 0))

        self.assertEqual(budget.remaining(), Usage(1, 2, 0))
        self.assertEqual(budget.remaining(TOOL_CALLS), 2)
        self.assertFalse(budget.would_exceed(LLM_CALLS))
        self.assertTrue(budget.would_exceed(REPAIR_ITERATIONS))
        budget.require(LLM_CALLS)
        self.assertEqual(budget.usage, Usage())

        event = budget.charge(LLM_CALLS, operation="initial_generation")

        self.assertEqual(event.sequence, 1)
        self.assertEqual(budget.usage, Usage(llm_calls=1))
        self.assertEqual(budget.remaining(LLM_CALLS), 0)
        self.assertTrue(budget.would_exceed(LLM_CALLS))

        with self.assertRaises(BudgetExceeded) as raised:
            budget.require(LLM_CALLS)
        self.assertEqual(raised.exception.resource, LLM_CALLS)
        self.assertEqual(raised.exception.requested, 1)
        self.assertEqual(raised.exception.remaining, 0)
        self.assertEqual(raised.exception.to_dict()["error"], "budget_exceeded")
        self.assertEqual(len(budget.events), 1)

    def test_rejected_charge_is_atomic_and_does_not_append(self) -> None:
        budget = Budget(Limits(max_llm_calls=1))
        budget.charge_llm_call(operation="first")
        before = budget.to_dict()

        with self.assertRaises(BudgetExceeded):
            budget.charge(LLM_CALLS, 2, operation="too-large")

        self.assertEqual(budget.to_dict(), before)

    def test_run_charged_charges_before_failure_and_never_refunds(self) -> None:
        budget = Budget(Limits(max_tool_calls=2))

        def fail() -> None:
            self.assertEqual(budget.usage.tool_calls, 1)
            raise RuntimeError("tool failed")

        with self.assertRaisesRegex(RuntimeError, "tool failed"):
            budget.run_charged(TOOL_CALLS, fail, operation="git.show")

        self.assertEqual(budget.usage.tool_calls, 1)
        self.assertEqual(len(budget.events), 1)
        self.assertEqual(budget.events[0].operation, "git.show")

        result = budget.run_charged(
            TOOL_CALLS,
            lambda left, right=0: left + right,
            2,
            right=3,
            operation="git.diff",
        )
        self.assertEqual(result, 5)
        self.assertEqual(budget.usage.tool_calls, 2)

    def test_event_sequence_and_convenience_charges_are_append_only(self) -> None:
        budget = Budget()
        first = budget.charge_llm_call(operation="produce")
        second = budget.charge_tool_call(operation="read_advisory")
        third = budget.charge_repair_iteration(operation="repair-1")

        self.assertEqual((first.sequence, second.sequence, third.sequence), (1, 2, 3))
        self.assertEqual(budget.ledger, (first, second, third))
        with self.assertRaises(AttributeError):
            budget.events.append(first)  # type: ignore[attr-defined]

        exported = budget.to_dict()
        exported["events"].clear()
        self.assertEqual(len(budget.events), 3)

    def test_serialization_is_json_safe_and_reproducible(self) -> None:
        first = Budget({"max_llm_calls": 2, "max_iterations": 1})
        second = Budget({"max_llm_calls": 2, "max_repair_iterations": 1})
        for budget in (first, second):
            budget.charge(LLM_CALLS, operation="candidate-0")
            budget.charge(REPAIR_ITERATIONS, operation="repair-1")

        self.assertEqual(first.to_canonical_json(), second.to_canonical_json())
        self.assertEqual(json.loads(first.to_canonical_json()), first.to_dict())
        self.assertNotIn("max_iterations", first.to_canonical_json())
        self.assertNotIn("timestamp", first.to_canonical_json())

    def test_invalid_resource_amount_operation_and_callable_do_not_charge(self) -> None:
        budget = Budget()

        for resource in ("llm", "", None, 1):
            with self.subTest(resource=resource), self.assertRaises(ValueError):
                budget.charge(resource)  # type: ignore[arg-type]
        for amount in (0, -1, True, False, 1.5, "1"):
            with self.subTest(amount=amount), self.assertRaises(ValueError):
                budget.charge(LLM_CALLS, amount)  # type: ignore[arg-type]
        for operation in ("", "   ", 1):
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                budget.charge(LLM_CALLS, operation=operation)  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValueError, "callable"):
            budget.run_charged(LLM_CALLS, 42)  # type: ignore[arg-type]

        self.assertEqual(budget.usage, Usage())
        self.assertEqual(budget.events, ())
        self.assertEqual(
            BUDGET_RESOURCES,
            frozenset({LLM_CALLS, TOOL_CALLS, REPAIR_ITERATIONS}),
        )


if __name__ == "__main__":
    unittest.main()
