# Lane A real OpenClaw batch receipt

This receipt records the first real T2-to-T1 Lane A batch that uses cleared
public inputs, local repository facts, deterministic replay responses, and the
production closed-loop runner.

## Scope

- Batch size: 3 public OpenClaw tasks.
- Input source: cleared public task, report, advisory-cache, and repository-map
  files prepared from the public benchmark records.
- Runtime storage: external to the repository.
- Repository boundary: no non-public evaluator material, host paths, or source
  snippets are committed here.

## Result

The batch reached the T1 closed-loop runner successfully:

```json
{"contract_version":1,"entries_written":0,"failed":0,"finalized":0,"input_failures":0,"manual_review":3,"record_limit_reached":false,"records_seen":3,"require_all_finalized":false,"status":"ok","tasks_run":3}
```

All three records are intentionally held for manual review by the current T1
validator.  That is a conservative verifier outcome, not a runner failure:
the closed loop executed all records and produced validation evidence without
input or runtime failures.

## Reproducibility checks

- Targeted regression suite: `70 tests`, `OK`.
- Independent replay A: `status=ok`, `manual_review=3`.
- Independent replay B: `status=ok`, `manual_review=3`.
- Replay A/B file comparison: `12` files each, hashes match.
- Public-output marker scan: `37` checked files, `0` matches for host paths or
  restricted-material markers.

## Artifact digests

| Artifact | SHA-256 |
| --- | --- |
| `run_tasks.jsonl` | `4987ec2151f9d4115c527b554a0b00909f309e0f0485f375866b20c12b115cb8` |
| `decisions.json` | `4a862559a4a39daa6b903dc56e5be0f8623db1a7ef999497883cd8facea441b4` |
| `repo-map.json` | `24b765e7b9d3c1ced64a20c7d3aca5993724d7f33c185e8637395f46af505eca` |
| `exact-replay.json` | `db9d8c960a4bbacbf46e00bd1e4980f2f825aa28c4c501f9efa1c184099002f9` |
| `closed-loop-output/run_manifest.jsonl` | `dcc3b64c151b86529e5e26acdad9da2a78d22ee2b16aead30bcf4d71849609a2` |
| `closed-loop-output/validation.jsonl` | `4aae526e57271fee16dc6404e99dc3869bed2897eefa1fb8d4ef9b51332f0676` |
| `closed-loop-output/deferred.jsonl` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `closed-loop-output/entries.jsonl` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| closed-loop output manifest | `da3a51c156f11e76c782158bc774ff43697731ebdf08a9b85d1cc284730aba65` |

## Remaining gap

This closes the minimum real-batch proof for Lane A.  The next acceptance risk
is scaling the same flow from the 3-task public batch to the full 20 public test
tasks and then to the 50 training tasks, while reducing manual-review outcomes
or documenting them with reviewer-approved justification.
