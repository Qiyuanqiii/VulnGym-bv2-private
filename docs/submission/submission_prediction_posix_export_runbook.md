# Submission-prediction POSIX export runbook

This runbook converts the already-pinned Lane A closed-loop replay outputs into
the submission-facing prediction bundle:

- `entries.jsonl`
- `validation.jsonl`
- `manifest.json`

The export command intentionally requires native POSIX filesystem semantics for
descriptor-relative, no-replace publication. Windows-native execution is
expected to fail closed with `platform_unsupported`; run this handoff on native
Linux, WSL with the project/runtime mounted, or another supported POSIX host.

## Inputs

Set these paths on the POSIX host:

```bash
export REPO_ROOT=/path/to/VulnGym-bv2-producer
export RUNTIME_ROOT=/path/to/VulnGym-bv2-runtime
export OUTPUT_ROOT="$RUNTIME_ROOT/submission-predictions/lane-a-40-v1"
```

Then run each export from `$REPO_ROOT`.

| Batch | Source replay dir under `$RUNTIME_ROOT` | Tasks | Source replay dataset SHA-256 | Output dir under `$OUTPUT_ROOT` |
| --- | --- | ---: | --- | --- |
| `test11` | `lane-a-closed-loop/combined-strict-fallback-v1/test11/closed-loop-output-allow-deferred` | 11 | `41c43389faa823a115890637bb4b85cf770dde8b87defde751b53e6efb18c57b` | `test11` |
| `train23` | `lane-a-closed-loop/combined-strict-fallback-v1/train23/closed-loop-output-allow-deferred` | 23 | `c2d30c379a8742d251c2d82c575da6c358add86f7d2046cf5af0e47c0a444cc0` | `train23` |
| `identifier-subset-v2/test1` | `lane-a-closed-loop/identifier-subset-v2/test1/closed-loop-output-generic-allow-deferred` | 1 | `c2151999e0c68a6c38c6f02ea5c6dfe9c189169251ee948b57585f6bf5a5763d` | `identifier-subset-v2-test1` |
| `identifier-subset-v2/train4` | `lane-a-closed-loop/identifier-subset-v2/train4/closed-loop-output-generic-allow-deferred` | 4 | `797f75f8df8bca392d30c542fb494793ec5b4e6b137e4e540607312eb973e5fe` | `identifier-subset-v2-train4` |
| `strict-v2/train-43ac81` | `lane-a-closed-loop/strict-v2/train-43ac81-v1/closed-loop-output` | 1 | `2143c8cfdbcbaf3f8da159eed584fbb402a7710f2a70562ea6f21bd68295b068` | `strict-v2-train-43ac81` |

## Export and verify loop

```bash
set -euo pipefail

cd "$REPO_ROOT"
mkdir -p "$OUTPUT_ROOT"

run_one() {
  local name="$1"
  local replay_rel="$2"
  local digest="$3"
  local count="$4"
  local out_rel="$5"
  local replay_dir="$RUNTIME_ROOT/$replay_rel"
  local out_dir="$OUTPUT_ROOT/$out_rel"

  export_json="$(
    python -B -m vulngym_agent.submission_prediction_cli export \
      --replay-dir "$replay_dir" \
      --replay-dataset-sha256 "$digest" \
      --expected-task-count "$count" \
      --output-dir "$out_dir"
  )"
  printf '%s\n' "$export_json"

  submission_sha="$(
    python -c 'import json, sys; print(json.loads(sys.stdin.read())["submission_sha256"])' \
      <<<"$export_json"
  )"

  python -B -m vulngym_agent.submission_prediction_cli verify \
    --submission-dir "$out_dir" \
    --replay-dir "$replay_dir" \
    --source-replay-dataset-sha256 "$digest" \
    --submission-sha256 "$submission_sha" \
    --expected-task-count "$count"
}

run_one test11 \
  lane-a-closed-loop/combined-strict-fallback-v1/test11/closed-loop-output-allow-deferred \
  41c43389faa823a115890637bb4b85cf770dde8b87defde751b53e6efb18c57b \
  11 test11

run_one train23 \
  lane-a-closed-loop/combined-strict-fallback-v1/train23/closed-loop-output-allow-deferred \
  c2d30c379a8742d251c2d82c575da6c358add86f7d2046cf5af0e47c0a444cc0 \
  23 train23

run_one identifier-subset-v2-test1 \
  lane-a-closed-loop/identifier-subset-v2/test1/closed-loop-output-generic-allow-deferred \
  c2151999e0c68a6c38c6f02ea5c6dfe9c189169251ee948b57585f6bf5a5763d \
  1 identifier-subset-v2-test1

run_one identifier-subset-v2-train4 \
  lane-a-closed-loop/identifier-subset-v2/train4/closed-loop-output-generic-allow-deferred \
  797f75f8df8bca392d30c542fb494793ec5b4e6b137e4e540607312eb973e5fe \
  4 identifier-subset-v2-train4

run_one strict-v2-train-43ac81 \
  lane-a-closed-loop/strict-v2/train-43ac81-v1/closed-loop-output \
  2143c8cfdbcbaf3f8da159eed584fbb402a7710f2a70562ea6f21bd68295b068 \
  1 strict-v2-train-43ac81
```

## Expected review evidence before POSIX export

The Windows-native review command can already re-read the source replay outputs
and confirm the current 40-task status:

| Batch | Tasks | Complete | Incomplete | Input failures | Review evidence SHA-256 |
| --- | ---: | ---: | ---: | ---: | --- |
| `test11` | 11 | 8 | 3 | 0 | `367bd779089dbb5942b323cfd553d3d8c4908f526e4e3ecb1fe02492c5a3b46a` |
| `train23` | 23 | 19 | 4 | 0 | `a1c49ec59abbbe0df612826594026a436158aab2c34a5c126f89ba7bf2ca8d72` |
| `identifier-subset-v2/test1` | 1 | 1 | 0 | 0 | `4988b1e6d5c490fc8878b377679fa128dc73e1ce4595796f1a2723b25eb5f652` |
| `identifier-subset-v2/train4` | 4 | 4 | 0 | 0 | `ba9d2403d1c4f28a9a738b16c8825539e01d93f515079f262bbd6382874764b0` |
| `strict-v2/train-43ac81` | 1 | 0 | 1 | 0 | `86fad1282f1b5f25f26c3b19fc0bffd15cd3798d2d6d95e5a120f284f0737e0b` |
| Total | 40 | 32 | 8 | 0 | mixed |

Formal export is still required before these predictions can be called a
submission bundle.
