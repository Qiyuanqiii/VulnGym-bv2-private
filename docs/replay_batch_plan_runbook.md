# Replay batch and final-gate plan runbook

`python -m vulngym_agent.replay_batch_plan_cli` packages the outputs of the
existing single-task replay authoring workflow into the exact replay roots
consumed by the native-Linux final gate. It can also build and independently
verify the fixed `FinalGatePlanV1` authorization artifact.

This is a control-plane builder, not a replay generator or evaluator. It never
calls a model, synthesizes a response, executes a benchmark task, reads scoring
gold, or claims that a finding is correct. Empty smoke pairs are rejected. The
formal 70 responses must first be authored and closed task by task with
`vulngym_agent.replay_authoring_cli`.

The builder also requires one externally frozen authoring index produced by
the trusted author/critic/reviewer closure process. The CLI cannot generate
this index from the directory it is about to package: doing so would allow an
arbitrary replacement replay to legitimize itself. Retain both the index
semantic digest and its exact wire digest outside the replay publication root.

## 1. Input layout

Publish each completed single-task pair into a split-specific private root. The
test root must contain exactly the 20 public test task IDs and the train root
exactly the 50 public train task IDs:

```text
/srv/vulngym/replay-publications/test/
  VG-TEST-.../
    d2.json
    d3.json
/srv/vulngym/replay-publications/train/
  VG-TRAIN-.../
    d2.json
    d3.json
```

Each task directory must be the final `--output-root` of the single-task
`finalize` command. Both transcripts must be non-empty canonical
`OciReplayConfigV1` values bound to the same task and the fixed
`replay`/`offline-v1` backend. An empty/deferred smoke fixture is not formal
input.

The canonical authoring index covers all 70 tasks in exact test-then-train
public order. Formal builds require `vulngym.replay-authoring-index.v2` and its
externally retained semantic/wire pins. Version 2 binds the authenticated
split exports, sealed-batch provenance, task/snapshot and receipt pins,
registered actor keys, and D2/D3 pins; each split readback authority also
signs its observations, while a separate index authority signs the complete
index. The externally pinned public-key registry fixes all six verification
identities. The v1 format is historical read-only input and is always rejected
by `build-split`.

Use mutually disjoint private directories. On Linux, input/output directories
must not be group- or world-writable, and replay files must be private regular
files with one link. Every build output must be absent; the CLI never repairs
or overwrites an existing publication.

## 2. Build and verify both replay splits

Run the test build first. Retain its canonical stdout through a trusted control
channel:

```bash
umask 077
python -B -m vulngym_agent.replay_batch_plan_cli build-split \
  --benchmark-root /srv/vulngym/benchmark \
  --split test \
  --authoring-output-root /srv/vulngym/replay-publications/test \
  --authoring-index-file /srv/vulngym/control/frozen-authoring-index.json \
  --expected-authoring-index-sha256 "${AUTHORING_INDEX_SHA256}" \
  --expected-authoring-index-wire-sha256 "${AUTHORING_INDEX_WIRE_SHA256}" \
  --trust-registry-file /srv/vulngym/control/replay-trust-registry-v2.json \
  --expected-trust-registry-sha256 "${TRUST_REGISTRY_SHA256}" \
  --expected-trust-registry-wire-sha256 "${TRUST_REGISTRY_WIRE_SHA256}" \
  --output-root /srv/vulngym/inputs/test-replay \
  > /srv/vulngym/control/test-replay-build-summary.json
```

The summary supplies `replay_manifest_sha256` and
`replay_manifest_wire_sha256`. Independently re-read the committed root with
both pins:

```bash
python -B -m vulngym_agent.replay_batch_plan_cli verify-split \
  --benchmark-root /srv/vulngym/benchmark \
  --split test \
  --replay-root /srv/vulngym/inputs/test-replay \
  --expected-manifest-sha256 "${TEST_REPLAY_SHA256}" \
  --expected-manifest-wire-sha256 "${TEST_REPLAY_WIRE_SHA256}"
```

Repeat for all 50 training tasks:

```bash
python -B -m vulngym_agent.replay_batch_plan_cli build-split \
  --benchmark-root /srv/vulngym/benchmark \
  --split train \
  --authoring-output-root /srv/vulngym/replay-publications/train \
  --authoring-index-file /srv/vulngym/control/frozen-authoring-index.json \
  --expected-authoring-index-sha256 "${AUTHORING_INDEX_SHA256}" \
  --expected-authoring-index-wire-sha256 "${AUTHORING_INDEX_WIRE_SHA256}" \
  --trust-registry-file /srv/vulngym/control/replay-trust-registry-v2.json \
  --expected-trust-registry-sha256 "${TRUST_REGISTRY_SHA256}" \
  --expected-trust-registry-wire-sha256 "${TRUST_REGISTRY_WIRE_SHA256}" \
  --output-root /srv/vulngym/inputs/train-replay \
  > /srv/vulngym/control/train-replay-build-summary.json

python -B -m vulngym_agent.replay_batch_plan_cli verify-split \
  --benchmark-root /srv/vulngym/benchmark \
  --split train \
  --replay-root /srv/vulngym/inputs/train-replay \
  --expected-manifest-sha256 "${TRAIN_REPLAY_SHA256}" \
  --expected-manifest-wire-sha256 "${TRAIN_REPLAY_WIRE_SHA256}"
```

The packaged layout is the existing strict evaluator contract:

```text
<split-replay-root>/
  manifest.json
  configs/<task-id>/d2.json
  configs/<task-id>/d3.json
```

Task order comes from the pinned public benchmark, not filesystem enumeration.
`build-split` loads only the public registry and rejects an index signed by a
different self-supplied registry, even when that index's hashes and signature
are internally consistent. Registry semantic/wire pins must come from the
independent final-gate policy, not from the replay producer.
The builder re-reads the complete staging tree before publication and re-reads
the committed tree afterward. POSIX uses a parent-fd-relative
`renameat2(RENAME_NOREPLACE)`; Windows uses a no-replace path rename plus
before/after identity checks and fails closed on ambiguity. Building from
identical input bytes at a different new output path produces identical files
and identical manifest semantic/wire pins.

## 3. Build the final-gate plan

Wait until the final local OCI image ID and both sealed-batch manifest pins are
known. The two snapshot key IDs must differ. This command verifies all 70
replay pairs again before writing the plan:

```bash
python -B -m vulngym_agent.replay_batch_plan_cli build-plan \
  --benchmark-root /srv/vulngym/benchmark \
  --test-replay-root /srv/vulngym/inputs/test-replay \
  --test-replay-manifest-sha256 "${TEST_REPLAY_SHA256}" \
  --test-replay-manifest-wire-sha256 "${TEST_REPLAY_WIRE_SHA256}" \
  --train-replay-root /srv/vulngym/inputs/train-replay \
  --train-replay-manifest-sha256 "${TRAIN_REPLAY_SHA256}" \
  --train-replay-manifest-wire-sha256 "${TRAIN_REPLAY_WIRE_SHA256}" \
  --test-sealed-batch-manifest-sha256 "${TEST_SEALED_MANIFEST_SHA256}" \
  --train-sealed-batch-manifest-sha256 "${TRAIN_SEALED_MANIFEST_SHA256}" \
  --test-key-id "${TEST_KEY_ID}" \
  --train-key-id "${TRAIN_KEY_ID}" \
  --runtime-image-id "${RUNTIME_IMAGE_ID}" \
  --output-root /srv/vulngym/control/final-gate-plan \
  > /srv/vulngym/control/final-gate-plan-build-summary.json
```

The output root contains only `final-gate-plan.json`. Retain the summary's
`plan_sha256` and `plan_wire_sha256` outside the evaluator host, then perform an
independent readback:

```bash
python -B -m vulngym_agent.replay_batch_plan_cli verify-plan \
  --benchmark-root /srv/vulngym/benchmark \
  --test-replay-root /srv/vulngym/inputs/test-replay \
  --train-replay-root /srv/vulngym/inputs/train-replay \
  --plan-root /srv/vulngym/control/final-gate-plan \
  --expected-plan-sha256 "${PLAN_SHA256}" \
  --expected-plan-wire-sha256 "${PLAN_WIRE_SHA256}" \
  --runtime-image-id "${RUNTIME_IMAGE_ID}"
```

`build-plan` binds caller-supplied sealed manifest pins but intentionally does
not read or re-verify sealed source. The mandatory native-Linux preflight and
final runner authenticate those sealed batches with their separate key files.
Pass `/srv/vulngym/control/final-gate-plan/final-gate-plan.json` and the retained
plan pins to the commands in `native_linux_final_gate_runbook.md`.

## 4. Status and failure handling

- Exit `0` means a canonical path-free summary says `published` or `verified`.
- Exit `2` means the input, layout, binding, or pin was rejected.
- Exit `11` means publication committed but its final readback was uncertain;
  inspect the exact output by retained digest and do not rebuild over it.
- Exit `130` means an interrupt occurred before a confirmed commit.

Pre-commit failures deliberately retain the randomly named staging directory.
The program never recursively deletes a staging path by name because another
process could replace that name between an identity check and deletion. A
trusted operator may remove a retained directory only after independently
binding its parent chain, directory identity, and exact expected membership.

Neither `published` nor `verified` is benchmark acceptance. Issue #90 closes
only after all real task responses have passed the author/critic/reviewer
workflow and both 20/50 replay roots, their independent readbacks, and their
safe evidence receipt are committed. Issues #94 and #95 still require the real
native-Linux test-first execution and final-gate receipt.
