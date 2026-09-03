# Lane A manual-review evidence note

This note explains the current hybrid Lane A result for submission review. It
is intentionally conservative: `manual_review` means the T2 candidate reached
the real deterministic T1 validator, but T1 did not have enough exact,
mechanically reproducible evidence to mark the full Entry as `correct`.

It is not a runtime failure. The expanded hybrid batches completed with zero
input failures:

| Batch | Public split | Tasks | Complete candidate/report pairs | Producer-deferred or incomplete | Finalized |
| --- | --- | ---: | ---: | ---: | ---: |
| `test11` | test | 11 | 8 | 3 | 0 |
| `train23` | train | 23 | 19 | 4 | 0 |
| `identifier-subset-v2/test1` | test | 1 | 1 | 0 | 0 |
| `identifier-subset-v2/train4` | train | 4 | 4 | 0 | 0 |
| Total | mixed | 39 | 32 | 7 | 0 |

The validator currently proves these fields deterministically for every
complete candidate/report pair:

- `schema`
- `report_id`
- `vuln_ids`
- `source_link`
- `repo_url`
- `commit`
- `entry_id`
- `origin`
- `verify`

The fields that remain semantic are deliberately left for review rather than
being promoted by weak heuristics:

- `entry_point` reachability and exact location;
- `critical_operation` as the real vulnerable sink or missing guard;
- `trace` completeness;
- `project` naming;
- `vuln_title`;
- `vuln_category_l1`;
- `vuln_category_l2`.

Observed reviewer-evidence aggregation:

| Batch | Correct field checks | Incorrect field checks | Uncertain field checks | Main incorrect field | Main uncertain fields |
| --- | ---: | ---: | ---: | --- | --- |
| `test11` | 72 | 2 | 54 | `entry_point` | `critical_operation`, `entry_point`, `trace`, title/category |
| `train23` | 171 | 2 | 131 | `entry_point` | `critical_operation`, `entry_point`, `trace`, title/category |
| `identifier-subset-v2/test1` | 9 | 0 | 7 | none | `critical_operation`, `entry_point`, `trace`, title/category |
| `identifier-subset-v2/train4` | 36 | 1 | 27 | `entry_point` | `critical_operation`, `entry_point`, `trace`, title/category |

Producer-deferred rows are also expected in this conservative route:

| Batch | `guard_only_exists_on_fix_side` | `no_entry_candidate` | `required_checks_unavailable` |
| --- | ---: | ---: | ---: |
| `test11` | 3 | 0 | 0 |
| `train23` | 3 | 1 | 0 |
| `identifier-subset-v2/test1` | 0 | 0 | 0 |
| `identifier-subset-v2/train4` | 0 | 0 | 1 |

The reviewer evidence files are path-free summaries. They include status,
completion state, Entry/report digests, field-level status counts,
incorrect/uncertain field names, missing-information categories, and deferred
reason codes. They omit field evidence text, source snippets, prompts, model
responses, and local paths.

Digest anchors:

| Batch | Closed-loop dataset SHA-256 | Review evidence SHA-256 |
| --- | --- | --- |
| `test11` | `41c43389faa823a115890637bb4b85cf770dde8b87defde751b53e6efb18c57b` | `367bd779089dbb5942b323cfd553d3d8c4908f526e4e3ecb1fe02492c5a3b46a` |
| `train23` | `c2d30c379a8742d251c2d82c575da6c358add86f7d2046cf5af0e47c0a444cc0` | `a1c49ec59abbbe0df612826594026a436158aab2c34a5c126f89ba7bf2ca8d72` |
| `identifier-subset-v2/test1` | `c2151999e0c68a6c38c6f02ea5c6dfe9c189169251ee948b57585f6bf5a5763d` | `4988b1e6d5c490fc8878b377679fa128dc73e1ce4595796f1a2723b25eb5f652` |
| `identifier-subset-v2/train4` | `797f75f8df8bca392d30c542fb494793ec5b4e6b137e4e540607312eb973e5fe` | `ba9d2403d1c4f28a9a738b16c8825539e01d93f515079f262bbd6382874764b0` |

The next engineering choice is therefore not whether the pipeline runs. It
does. The choice is how aggressively to promote semantic facts:

1. Keep the current strict T1 and submit `manual_review` evidence as the honest
   audit trail for uncertain fields.
2. Add narrow T1 promotions only for facts that can be re-proved from public
   advisory text, local Git topology, and exact source snippets without using
   hidden answers.
3. Leave rows with incorrect `entry_point` or missing vulnerable-side operation
   evidence unfinalized until stronger evidence exists.
