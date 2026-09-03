# Lane A hybrid readiness receipt

This receipt records the current hybrid route for Lane A: keep T1 conservative,
scale the real T2-to-T1 batches where public inputs are already strict-ready,
and turn the remaining `manual_review` outcomes into explicit reviewer evidence
instead of silently weakening validation.

## Scope

- Dataset target: the public 20-task test split and 50-task training split.
- Input boundary: public task records, public reports, public advisory metadata,
  and local repository facts only.
- Excluded inputs: evaluator-only answer files, split-control artifacts, and
  raw mapping internals.
- Repository boundary: evidence files committed to this repository must be
  sanitized and reproducible; bulky runtime products remain outside git.

## Current strict-readiness diagnosis

The current strict public materializer accepts a task only when it can match a
cleared public report to a public advisory and resolve a same-repository 40-hex
fix commit whose single parent is the vulnerable checkout. This is deliberately
narrow: it prevents accidental use of hidden evaluator facts, but it does not
cover every public advisory style.

The preparer and offline materializer now use the same strict candidate
selection rule: if several public reports share a task snapshot, the selected
anchor must be the unique report candidate whose public advisory and local Git
facts satisfy the strict rule. A lexicographically earlier but non-anchorable
report is audited as not run instead of causing a later materialization failure.

| Split | Tasks | Strict-ready | Blocked | Strict-ready rate |
| --- | ---: | ---: | ---: | ---: |
| Public test | 20 | 8 | 12 | 40.0% |
| Public train | 50 | 14 | 36 | 28.0% |
| Total | 70 | 22 | 48 | 31.4% |

Observed blocker taxonomy:

| Split | Blocker | Count |
| --- | --- | ---: |
| Public test | `advisory_identifier_mismatch` | 5 |
| Public test | `fix_candidate_missing` | 8 |
| Public test | `fix_candidate_unavailable` | 2 |
| Public test | `gh_response_invalid` | 1 |
| Public train | `advisory_identifier_mismatch` | 7 |
| Public train | `fix_candidate_missing` | 24 |
| Public train | `fix_candidate_unavailable` | 5 |
| Public train | `gh_response_invalid` | 1 |

Fallback action plan from the same diagnosis:

| Split | Action | Count |
| --- | --- | ---: |
| Public test | `strict_ready` | 8 |
| Public test | `identifier_subset_policy_candidate` | 3 |
| Public test | `local_graph_child_policy_candidate` | 4 |
| Public test | `mixed_public_anchor_policy_candidate` | 2 |
| Public test | `refresh_local_repository` | 2 |
| Public test | `refresh_public_metadata` | 1 |
| Public train | `strict_ready` | 14 |
| Public train | `identifier_subset_policy_candidate` | 7 |
| Public train | `local_graph_child_policy_candidate` | 23 |
| Public train | `refresh_local_repository` | 5 |
| Public train | `refresh_public_metadata` | 1 |

Local commit-graph fallback probe:

| Split | Probe result | Count |
| --- | --- | ---: |
| Public test | `unique_direct_child` | 3 |
| Public test | `no_direct_child` | 3 |
| Public train | `unique_direct_child` | 11 |
| Public train | `no_direct_child` | 12 |

The probe is intentionally graph-only: it identifies whether a blocked task has
exactly one local single-parent child commit of the vulnerable checkout, but it
does not inspect or publish source paths during broad diagnosis. The 14
`unique_direct_child` tasks are therefore high-confidence automation
candidates, but each still needs the formal materializer to validate source
diffs before it can join a real T2-to-T1 batch.

## Local direct-child fallback materialization

A narrow fallback policy is now implemented for tasks whose public advisory has
no GitHub commit reference at all. The policy remains fail-closed: it requires
exact public identifier equality and exactly one local single-parent child of
the vulnerable checkout. If any candidate advisory in the task group contains a
GitHub commit reference, the strict public-reference policy keeps precedence.

Validation of the 14 graph candidates produced 13 usable fallback
materializations. One training candidate, `VG-TRAIN-640FF6DE344026468477`,
was rejected with `non_source_diff` and remains out of the automatic batch.

| Split | Fallback graph candidates | Fallback materialized | Rejected |
| --- | ---: | ---: | ---: |
| Public test | 3 | 3 | 0 |
| Public train | 11 | 10 | 1 |
| Total | 14 | 13 | 1 |

Current machine-materializable coverage with the strict and fallback policies
combined:

| Split | Tasks | Strict-ready | Fallback materialized | Total materializable | Rate |
| --- | ---: | ---: | ---: | ---: | ---: |
| Public test | 20 | 8 | 3 | 11 | 55.0% |
| Public train | 50 | 14 | 10 | 24 | 48.0% |
| Total | 70 | 22 | 13 | 35 | 50.0% |

Fallback materialization digests:

| Batch | Tasks | Materialization SHA-256 | Manifest wire SHA-256 |
| --- | ---: | --- | --- |
| `test3` | 3 | `130188977378e0d71a45485ca9799a95b02cd3fc38a635aa00b3446c34db4b0a` | `eed9c4ea32dad976716c70a56dbb355f36e0f54d9be0ee49d773cfda6197981f` |
| `train10` | 10 | `f8e266ed412e0933ff9cd03c255bdccabbb72d086f7f10d03a2852a3e0ce0ab1` | `b92ca1f4bac6d603e1e51bb36e0890042888e6a0aa39c8135bb5b90ab0fad131` |

The remaining blockers are materialization gaps, not T1/T2 runtime failures.
They need separate reviewer-auditable policies or refresh steps before they can
be safely added to automated batches.

## Real T2-to-T1 batch result

The strict-ready public test batch has been expanded from 3 to 8 real tasks and
executed through deterministic replay plus the production closed-loop runner.

Authoring summary:

```json
{"exact_replay_verified":true,"response_count":20,"status":"published","status_counts":{"manual_review":8},"task_count":8,"verdict_counts":{"incorrect":1,"uncertain":5}}
```

Closed-loop runner summary:

```json
{"contract_version":1,"entries_written":0,"failed":0,"finalized":0,"input_failures":0,"manual_review":8,"record_limit_reached":false,"records_seen":8,"require_all_finalized":false,"status":"ok","tasks_run":8}
```

Independent replay checks:

- Replay A and replay B each produced `12` public output files.
- Replay A/B file hashes matched byte-for-byte.
- Public marker scan returned `0` restricted marker/path hits.
- Verified submission readback saw `8` tasks, `6` complete candidate/report
  pairs, `0` input failures, and `2` producer-deferred tasks:
  `VG-TEST-A1EBF05AB83CEA26E60E` and `VG-TEST-F18FEB614A9AFF680A8E`.

The two producer-deferred tasks are both stopped before prediction publication
because the public evidence only supports a fix-side guard clue and does not
establish a vulnerable-side guard location. Keeping them deferred is the safer
review posture.

## Artifact digests

These digests identify the sanitized public artifacts for the 8-task strict
batch. Runtime paths are intentionally omitted from this committed receipt.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `run_tasks.jsonl` | 5989 | `c148ab62d737898dcba7be4db863d607838ded64748d18fea8ace3eee2a3a948` |
| `decisions.json` | 2818 | `528321920896781c0901550f9f3deaa423a38a42f1481f31b18c37c2ea829b93` |
| `repo-map.json` | 164 | `3f97367e107d0b7321e0e10031269d60123cde37077566528ac85d2f8ba50ce0` |
| `exact-replay-allow-deferred.json` | 8913 | `a6d7c4ebbe04f9900c0fa7065b70af84013fc6a918d23eb873477e08c63adeb3` |
| `closed-loop-output-allow-deferred/run_manifest.jsonl` | 9540 | `9c45026349818403abb8f8c67183f886fa2cc20ccb168f1878f3c5b655fd009a` |
| `closed-loop-output-allow-deferred/candidates.jsonl` | 22805 | `8f8e6dc1a437e23f33e699e2db6c1be92eb25b00cc3ba9902e8ddfb07d5c1b69` |
| `closed-loop-output-allow-deferred/validation.jsonl` | 39976 | `80248c3b9a09fa4cdd09460bfaaedea3e3841b91b734123e7047b7d7aedaa8d3` |
| `closed-loop-output-allow-deferred/deferred.jsonl` | 6712 | `1370769708fefe31a8d1632c2525222ab7930f4669c006045554933765d902d4` |
| `closed-loop-output-allow-deferred/entries.jsonl` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

Dataset-level public output digests:

| Digest | Value |
| --- | --- |
| dataset manifest | `b3f68bd0d3721e15dc48b4c1d27a15ed9e3f8f56b13ce225d29f7275c147fcaf` |
| candidate stream | `8f8e6dc1a437e23f33e699e2db6c1be92eb25b00cc3ba9902e8ddfb07d5c1b69` |
| validation stream | `9daf8b7e6d4928a063fee3cff60cb43158753781dbeac7e71f10aca54b2c1cec` |
| validation file | `80248c3b9a09fa4cdd09460bfaaedea3e3841b91b734123e7047b7d7aedaa8d3` |
| entries stream | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

## Why `manual_review` remains expected

T1 currently proves hard, directly checkable facts such as schema shape, public
identifiers, repository URL, commit, source link, and code-location consistency.
It intentionally refuses to promote semantic fields when the evidence is only
suggestive:

- entry reachability and runtime route evidence;
- critical operation and guard placement;
- source-to-operation trace completeness;
- vulnerability title and category.

That conservatism is desirable for the competition handoff: a record that lacks
proof should be reviewable, not auto-finalized. The hybrid route therefore has
two workstreams:

1. Improve T2/T1 evidence collection so more records become mechanically
   provable.
2. Export concise review evidence for records that remain `manual_review`, so
   reviewers can see exactly which facts passed, which fact categories are
   missing, and why the system refused to finalize them. This is now available
   through `submission_prediction_cli review`.

## Publication note

`submission_prediction_cli export` is designed to use native POSIX filesystem
semantics for atomic no-replace publication. On Windows it correctly rejects the
formal export path with `platform_unsupported`. This is a packaging constraint,
not a batch-data failure. Formal final export should run on native Linux or
another supported POSIX environment, while Windows can continue to run the
closed-loop and readback checks.

## Next acceptance work

1. Merge strict and fallback-materialized tasks into expanded Lane A batches
   and run the real T2-to-T1 closed loop for 11 public test tasks and 24 public
   training tasks.
2. Use the reviewer evidence export on every expanded batch and archive the
   resulting `review_evidence_sha256` with the batch receipt.
3. Add narrow T1 promotions only where evidence is exact and reproducible. Do
   not globally lower the finalized threshold and do not auto-finalize records
   with known incorrect entry-point evidence.
4. Continue the remaining 35-task materialization backlog through identifier
   subset policy, local repository refresh, public metadata refresh, and manual
   review where no direct-child policy can be justified.
