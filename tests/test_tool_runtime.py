from __future__ import annotations

from dataclasses import FrozenInstanceError
import hashlib
import json
import math
import unittest

from vulngym_agent.orchestrator import Budget, BudgetExceeded, Limits
from vulngym_agent.tools import (
    ArtifactRef,
    AttemptToolRuntime,
    ToolArtifact,
    ToolBlocked,
    ToolCallEnvelope,
    ToolDefinition,
    ToolHandlerOutput,
    ToolLedgerMismatch,
    ToolNotAllowed,
    ToolReferenceError,
    ToolRuntimeFinalized,
)


TASK_ID = "TASK-GHSA-AAAA-BBBB-CCCC"


def _artifact(envelope: ToolCallEnvelope, artifact_id: str = "ART-source-1") -> ToolArtifact:
    return ToolArtifact(
        task_id=envelope.task_id,
        attempt=envelope.attempt,
        policy_scope=envelope.policy_scope,
        tool_call_id=envelope.tool_call_id,
        artifact_id=artifact_id,
        kind="source.snippet",
        payload={"file": "src/a.py", "lines": [10, 11], "text": "return value"},
    )


class AttemptToolRuntimeTests(unittest.TestCase):
    def _runtime(
        self,
        handler,
        *,
        budget: Budget | None = None,
        attempt: int = 0,
        allowlist=("git.read_blob",),
        definitions: tuple[ToolDefinition, ...] | None = None,
    ) -> AttemptToolRuntime:
        registry = definitions or (
            ToolDefinition(
                name="git.read_blob",
                contract_id="test.git.read_blob@1",
                handler=handler,
            ),
        )
        return AttemptToolRuntime(
            task_id=TASK_ID,
            attempt=attempt,
            policy_scope="t2.initial" if attempt == 0 else f"t2.repair-{attempt}",
            budget=budget or Budget(Limits(max_tool_calls=8)),
            registry=registry,
            allowlist=allowlist,
        )

    def test_success_is_charged_first_scoped_content_addressed_and_sealed(self) -> None:
        budget = Budget(Limits(max_tool_calls=2))
        seen: list[ToolCallEnvelope] = []

        def handler(envelope: ToolCallEnvelope) -> ToolHandlerOutput:
            self.assertEqual(budget.usage.tool_calls, 1)
            seen.append(envelope)
            return ToolHandlerOutput(
                output={"found": True, "order": [2, 1]},
                artifacts=(_artifact(envelope),),
            )

        runtime = self._runtime(handler, budget=budget)
        result = runtime.call(
            "TOOL-00001", "git.read_blob", {"commit": "a" * 40, "path": "src/a.py"}
        )

        self.assertEqual(result.status, "success")
        self.assertEqual(result.task_id, TASK_ID)
        self.assertEqual(result.attempt, 0)
        self.assertEqual(result.policy_scope, "t2.initial")
        self.assertEqual(result.tool_call_id, "TOOL-00001")
        self.assertEqual(result.tool_name, "git.read_blob")
        self.assertEqual(result.arguments_sha256, seen[0].arguments_sha256)
        self.assertEqual(result.operation, seen[0].operation)
        self.assertIn("TOOL-00001:git.read_blob", result.operation)
        self.assertEqual(budget.events[0].operation, result.operation)
        self.assertEqual(result.budget_event_sequence, budget.events[0].sequence)
        self.assertEqual(len(result.artifact_refs), 1)
        self.assertEqual(
            result.artifact_refs[0].artifact_sha256,
            runtime.artifacts[0].artifact_sha256,
        )
        record = result.to_tool_call_record()
        self.assertEqual(record.task_id, TASK_ID)
        self.assertEqual(record.attempt, 0)
        self.assertEqual(record.policy_scope, "t2.initial")
        self.assertEqual(record.operation, result.operation)
        self.assertEqual(record.budget_event_sequence, budget.events[0].sequence)
        self.assertEqual(record.result_sha256, result.result_sha256)

        self.assertIsNone(runtime.sealed_transcript)
        transcript = runtime.finalize()
        self.assertIs(runtime.sealed_transcript, transcript)
        records, artifacts = transcript
        self.assertEqual(records, (result,))
        self.assertEqual(artifacts, runtime.artifacts)
        self.assertEqual(json.loads(json.dumps(transcript.to_dict())), transcript.to_dict())
        self.assertEqual(runtime.finalize(), transcript)
        with self.assertRaises(ToolRuntimeFinalized):
            runtime.call("TOOL-00002", "git.read_blob", {})
        self.assertEqual(budget.usage.tool_calls, 1)

    def test_contracts_and_nested_values_are_deeply_immutable(self) -> None:
        original = {"nested": {"values": [1, 2]}}
        artifact = ToolArtifact(
            task_id=TASK_ID,
            attempt=0,
            policy_scope="t2.initial",
            tool_call_id="TOOL-00001",
            artifact_id="ART-one",
            kind="source.snippet",
            payload=original,
        )
        original["nested"]["values"].append(3)

        self.assertEqual(artifact.to_dict()["payload"]["nested"]["values"], [1, 2])
        with self.assertRaises(TypeError):
            artifact.payload["new"] = 1
        with self.assertRaises(AttributeError):
            artifact.payload["nested"]["values"].append(3)
        with self.assertRaises(FrozenInstanceError):
            artifact.kind = "changed"  # type: ignore[misc]

        envelope = ToolCallEnvelope(
            task_id=TASK_ID,
            attempt=0,
            policy_scope="t2.initial",
            tool_call_id="TOOL-00001",
            tool_name="git.read_blob",
            arguments={"nested": {"value": 1}},
        )
        with self.assertRaises(TypeError):
            envelope.arguments["x"] = 2

    def test_registry_and_attempt_allowlist_are_fixed(self) -> None:
        calls = 0

        def handler(envelope: ToolCallEnvelope) -> ToolHandlerOutput:
            nonlocal calls
            calls += 1
            return ToolHandlerOutput()

        budget = Budget(Limits(max_tool_calls=4))
        source = {
            "git.read_blob": ToolDefinition(
                name="git.read_blob",
                contract_id="test.git.read_blob@1",
                handler=handler,
            )
        }
        runtime = AttemptToolRuntime(
            task_id=TASK_ID,
            attempt=0,
            policy_scope="t2.initial",
            budget=budget,
            registry=source,
            allowlist=("git.read_blob",),
        )
        source["shell"] = ToolDefinition(
            name="shell", contract_id="test.shell@1", handler=handler
        )

        self.assertNotIn("shell", runtime.registry)
        with self.assertRaises(TypeError):
            runtime.registry["other"] = ToolDefinition(
                name="other", contract_id="test.other@1", handler=handler
            )
        with self.assertRaises(ToolNotAllowed):
            runtime.call("TOOL-00001", "shell", {})
        self.assertEqual(calls, 0)
        self.assertEqual(budget.usage.tool_calls, 0)

        definitions = (
            ToolDefinition(
                name="git.read_blob",
                contract_id="test.git.read_blob@1",
                handler=handler,
            ),
            ToolDefinition(
                name="git.diff", contract_id="test.git.diff@1", handler=handler
            ),
        )
        restricted = self._runtime(
            handler,
            budget=budget,
            definitions=definitions,
            allowlist=("git.read_blob",),
        )
        with self.assertRaises(ToolNotAllowed):
            restricted.call("TOOL-00002", "git.diff", {})
        self.assertEqual(budget.usage.tool_calls, 0)

    def test_registry_digest_uses_ordered_manifest_contracts_not_callables(self) -> None:
        def first_handler(envelope: ToolCallEnvelope) -> ToolHandlerOutput:
            return ToolHandlerOutput(output={"handler": "first"})

        def second_handler(envelope: ToolCallEnvelope) -> ToolHandlerOutput:
            return ToolHandlerOutput(output={"handler": "second"})

        def digest(definitions: tuple[ToolDefinition, ...]) -> str:
            runtime = AttemptToolRuntime(
                task_id=TASK_ID,
                attempt=0,
                policy_scope="t2.initial",
                budget=Budget(),
                registry=definitions,
                allowlist=(),
            )
            return runtime.finalize().registry_sha256

        v1 = (
            ToolDefinition(
                name="git.read_blob",
                contract_id="test.git.read_blob@1",
                handler=first_handler,
            ),
            ToolDefinition(
                name="git.diff",
                contract_id="test.git.diff@1",
                handler=first_handler,
            ),
        )
        same_contracts_different_callables = (
            ToolDefinition(
                name="git.diff",
                contract_id="test.git.diff@1",
                handler=second_handler,
            ),
            ToolDefinition(
                name="git.read_blob",
                contract_id="test.git.read_blob@1",
                handler=second_handler,
            ),
        )
        v2 = (
            ToolDefinition(
                name="git.read_blob",
                contract_id="test.git.read_blob@2",
                handler=first_handler,
            ),
            ToolDefinition(
                name="git.diff",
                contract_id="test.git.diff@1",
                handler=first_handler,
            ),
        )

        expected = hashlib.sha256(
            json.dumps(
                [
                    ["git.diff", "test.git.diff@1"],
                    ["git.read_blob", "test.git.read_blob@1"],
                ],
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(digest(v1), expected)
        self.assertEqual(digest(same_contracts_different_callables), expected)
        self.assertNotEqual(digest(v2), expected)

    def test_invalid_and_duplicate_tool_contracts_are_rejected(self) -> None:
        def handler(envelope: ToolCallEnvelope) -> ToolHandlerOutput:
            return ToolHandlerOutput()

        for contract_id in (
            "",
            "missing-version",
            "test.bad contract@1",
            "test.bad\ncontract@1",
            f"test.{'x' * 190}@1",
        ):
            with self.subTest(contract_id=contract_id), self.assertRaisesRegex(
                ValueError, "contract_id"
            ):
                ToolDefinition(
                    name="git.read_blob",
                    contract_id=contract_id,
                    handler=handler,
                )

        duplicate_contracts = (
            ToolDefinition(
                name="git.read_blob",
                contract_id="test.shared-contract@1",
                handler=handler,
            ),
            ToolDefinition(
                name="git.diff",
                contract_id="test.shared-contract@1",
                handler=handler,
            ),
        )
        with self.assertRaisesRegex(ValueError, "duplicate tool contract_id"):
            AttemptToolRuntime(
                task_id=TASK_ID,
                attempt=0,
                policy_scope="t2.initial",
                budget=Budget(),
                registry=duplicate_contracts,
                allowlist=(),
            )

        duplicate_names = (
            ToolDefinition(
                name="git.read_blob",
                contract_id="test.git.read_blob@1",
                handler=handler,
            ),
            ToolDefinition(
                name="git.read_blob",
                contract_id="test.git.read_blob@2",
                handler=handler,
            ),
        )
        with self.assertRaisesRegex(ValueError, "duplicate tool definition"):
            AttemptToolRuntime(
                task_id=TASK_ID,
                attempt=0,
                policy_scope="t2.initial",
                budget=Budget(),
                registry=duplicate_names,
                allowlist=(),
            )

    def test_blocked_and_error_calls_have_stable_digests_and_records(self) -> None:
        def blocked(envelope: ToolCallEnvelope) -> ToolHandlerOutput:
            raise ToolBlocked("policy_denied", {"reason": "commit outside allowlist"})

        def failed(envelope: ToolCallEnvelope) -> ToolHandlerOutput:
            raise OSError("host-specific path that must not enter the digest")

        budget = Budget(Limits(max_tool_calls=4))
        runtime = AttemptToolRuntime(
            task_id=TASK_ID,
            attempt=0,
            policy_scope="t2.initial",
            budget=budget,
            registry=(
                ToolDefinition(
                    name="git.read_blob",
                    contract_id="test.git.read_blob@1",
                    handler=blocked,
                ),
                ToolDefinition(
                    name="git.diff",
                    contract_id="test.git.diff@1",
                    handler=failed,
                ),
            ),
            allowlist=("git.read_blob", "git.diff"),
        )

        blocked_result = runtime.call("TOOL-00001", "git.read_blob", {})
        error_result = runtime.call("TOOL-00002", "git.diff", {})

        self.assertEqual(blocked_result.status, "blocked")
        self.assertEqual(blocked_result.error_code, "policy_denied")
        self.assertRegex(blocked_result.error_sha256 or "", r"^[0-9a-f]{64}$")
        self.assertEqual(error_result.status, "error")
        self.assertEqual(error_result.error_code, "handler_error")
        self.assertEqual(
            error_result.error,
            {"exception_type": "builtins.OSError"},
        )
        self.assertRegex(error_result.error_sha256 or "", r"^[0-9a-f]{64}$")
        self.assertIsNone(blocked_result.to_tool_call_record().result_sha256)
        self.assertEqual(
            blocked_result.to_tool_call_record().error_code,
            "policy_denied",
        )
        self.assertEqual(budget.usage.tool_calls, 2)
        self.assertEqual(len(runtime.finalize().records), 2)

        replay = self._runtime(blocked)
        replay_result = replay.call("TOOL-00001", "git.read_blob", {})
        self.assertEqual(replay_result.error_sha256, blocked_result.error_sha256)
        self.assertEqual(replay_result.result_sha256, blocked_result.result_sha256)

    def test_budget_exceeded_does_not_execute_or_create_fake_record(self) -> None:
        called = False

        def handler(envelope: ToolCallEnvelope) -> ToolHandlerOutput:
            nonlocal called
            called = True
            return ToolHandlerOutput()

        budget = Budget(Limits(max_tool_calls=0))
        runtime = self._runtime(handler, budget=budget)

        with self.assertRaises(BudgetExceeded):
            runtime.call("TOOL-00001", "git.read_blob", {})

        self.assertFalse(called)
        self.assertEqual(runtime.records, ())
        self.assertEqual(runtime.artifacts, ())
        self.assertEqual(budget.events, ())
        self.assertEqual(runtime.finalize().records, ())

    def test_argument_digest_is_canonical_and_references_are_explicit(self) -> None:
        envelopes: list[ToolCallEnvelope] = []

        def handler(envelope: ToolCallEnvelope) -> ToolHandlerOutput:
            envelopes.append(envelope)
            if envelope.tool_call_id == "TOOL-00001":
                return ToolHandlerOutput(artifacts=(_artifact(envelope),))
            return ToolHandlerOutput(output={"used": True})

        runtime = self._runtime(handler)
        first = runtime.call("TOOL-00001", "git.read_blob", {"b": 2, "a": 1})
        ref = first.artifact_refs[0]
        second = runtime.call(
            "TOOL-00002", "git.read_blob", {"artifact": ref, "mode": "inspect"}
        )

        self.assertEqual(
            first.arguments_sha256,
            ToolCallEnvelope(
                task_id=TASK_ID,
                attempt=0,
                policy_scope="t2.initial",
                tool_call_id="TOOL-00001",
                tool_name="git.read_blob",
                arguments={"a": 1, "b": 2},
            ).arguments_sha256,
        )
        self.assertEqual(
            envelopes[1].to_dict()["arguments"]["artifact"],
            {"$artifact_ref": ref.to_dict()},
        )
        self.assertEqual(second.status, "success")

    def test_forged_cross_runtime_and_cross_attempt_refs_fail_before_charge(self) -> None:
        def handler(envelope: ToolCallEnvelope) -> ToolHandlerOutput:
            return ToolHandlerOutput(artifacts=(_artifact(envelope),))

        first_runtime = self._runtime(handler)
        issued = first_runtime.call("TOOL-00001", "git.read_blob", {}).artifact_refs[0]
        forged = ArtifactRef(**issued.to_dict())

        with self.assertRaises(ToolReferenceError):
            first_runtime.call("TOOL-00002", "git.read_blob", {"artifact": forged})
        with self.assertRaises(ToolReferenceError):
            first_runtime.call(
                "TOOL-00002",
                "git.read_blob",
                {"artifact": {"$artifact_ref": issued.to_dict()}},
            )
        self.assertEqual(len(first_runtime.records), 1)

        second_budget = Budget(Limits(max_tool_calls=3))
        second_runtime = self._runtime(handler, budget=second_budget, attempt=1)
        with self.assertRaises(ToolReferenceError):
            second_runtime.call(
                "TOOL-00003", "git.read_blob", {"artifact": issued}
            )
        self.assertEqual(second_budget.usage.tool_calls, 0)

    def test_artifact_scope_and_duplicate_ids_turn_into_charged_errors(self) -> None:
        calls = 0

        def handler(envelope: ToolCallEnvelope) -> ToolHandlerOutput:
            nonlocal calls
            calls += 1
            if calls == 1:
                artifact = _artifact(envelope)
            else:
                artifact = _artifact(envelope)  # duplicate across the attempt
            return ToolHandlerOutput(artifacts=(artifact,))

        runtime = self._runtime(handler)
        self.assertEqual(
            runtime.call("TOOL-00001", "git.read_blob", {}).status, "success"
        )
        second = runtime.call("TOOL-00002", "git.read_blob", {})

        self.assertEqual(second.status, "error")
        self.assertEqual(second.error_code, "handler_error")
        self.assertEqual(len(runtime.artifacts), 1)
        self.assertEqual(len(runtime.finalize().records), 2)

    def test_invalid_handler_contract_is_a_charged_error(self) -> None:
        def handler(envelope: ToolCallEnvelope):
            return {"not": "ToolHandlerOutput"}

        budget = Budget(Limits(max_tool_calls=1))
        runtime = self._runtime(handler, budget=budget)
        result = runtime.call("TOOL-00001", "git.read_blob", {})

        self.assertEqual(result.status, "error")
        self.assertEqual(result.error_code, "handler_error")
        self.assertEqual(budget.usage.tool_calls, 1)
        self.assertEqual(runtime.finalize().records, (result,))

    def test_duplicate_call_and_invalid_json_fail_before_charging(self) -> None:
        def handler(envelope: ToolCallEnvelope) -> ToolHandlerOutput:
            return ToolHandlerOutput()

        budget = Budget(Limits(max_tool_calls=5))
        runtime = self._runtime(handler, budget=budget)
        runtime.call("TOOL-00001", "git.read_blob", {})

        for arguments in ({"bad": math.nan}, {"bad": object()}):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                runtime.call("TOOL-00002", "git.read_blob", arguments)
        with self.assertRaises(ValueError):
            runtime.call("TOOL-00001", "git.read_blob", {})
        self.assertEqual(budget.usage.tool_calls, 1)

        too_deep: dict[str, object] = {}
        cursor = too_deep
        for _ in range(18):
            child: dict[str, object] = {}
            cursor["child"] = child
            cursor = child
        with self.assertRaisesRegex(ValueError, "depth"):
            runtime.call("TOOL-00002", "git.read_blob", too_deep)
        self.assertEqual(budget.usage.tool_calls, 1)

    def test_finalize_detects_unowned_or_mismatched_budget_events(self) -> None:
        def handler(envelope: ToolCallEnvelope) -> ToolHandlerOutput:
            return ToolHandlerOutput()

        budget = Budget(Limits(max_tool_calls=3))
        runtime = self._runtime(handler, budget=budget)
        runtime.call("TOOL-00001", "git.read_blob", {})
        budget.charge_tool_call(operation="tool:unowned")

        with self.assertRaises(ToolLedgerMismatch):
            runtime.finalize()
        self.assertIsNone(runtime.sealed_transcript)
        with self.assertRaises(ToolLedgerMismatch):
            runtime.finalize()
        with self.assertRaises(ToolRuntimeFinalized):
            runtime.call("TOOL-00002", "git.read_blob", {})

    def test_constructor_rejects_invalid_scope_registry_and_allowlist(self) -> None:
        definition = ToolDefinition(
            name="git.read_blob",
            contract_id="test.git.read_blob@1",
            handler=lambda envelope: ToolHandlerOutput(),
        )
        budget = Budget()
        with self.assertRaises(ValueError):
            AttemptToolRuntime(
                task_id=TASK_ID,
                attempt=3,
                policy_scope="t2.repair-3",
                budget=budget,
                registry=(definition,),
                allowlist=("git.read_blob",),
            )
        with self.assertRaisesRegex(ValueError, "unregistered"):
            AttemptToolRuntime(
                task_id=TASK_ID,
                attempt=0,
                policy_scope="t2.initial",
                budget=budget,
                registry=(definition,),
                allowlist=("git.diff",),
            )
        with self.assertRaisesRegex(ValueError, "key"):
            AttemptToolRuntime(
                task_id=TASK_ID,
                attempt=0,
                policy_scope="t2.initial",
                budget=budget,
                registry={"git.diff": definition},
                allowlist=(),
            )


if __name__ == "__main__":
    unittest.main()
