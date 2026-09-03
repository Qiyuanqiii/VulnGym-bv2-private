# Lane A manual-review evidence note

This note explains the current hybrid Lane A result for submission review. It
is intentionally conservative: `manual_review` means the T2 candidate reached
the real deterministic T1 validator, but T1 did not have enough exact,
mechanically reproducible evidence to mark the full Entry as `correct`.

It is not a runtime failure. The expanded hybrid batches completed with zero
input failures:

| Batch | Public split | Tasks | Complete candidate/report pairs | Producer-deferred or incomplete | Finalized |
| --- | --- | ---: | ---: | ---: | ---: |
| `test11-v3-authz-scope` | test | 11 | 11 | 0 | 0 |
| `train24-v5-unsafe-option` | train | 24 | 24 | 0 | 0 |
| `identifier-subset-v2/test1` | test | 1 | 1 | 0 | 0 |
| `identifier-subset-v2/train4` | train | 4 | 4 | 0 | 0 |
| Total | mixed | 40 | 40 | 0 | 0 |

A later guard-anchor authoring probe over the same `train24` workload improves
the code-level terminal-candidate coverage from 20/24 to 22/24 by adding
old-side anchors for sanitizer/normalizer replacements and assertion namespace
calls. Substituting that probe for `train24-v2-review-anchor` would make the
then-current 40-task covered set 35 complete candidate/report pairs and 5
producer-deferred or incomplete rows. The added terminal reports are still
`manual_review`: one is `uncertain`, and one is intentionally rejected as
`incorrect`.

A follow-up `.svelte` entry-search probe then improves the same workload from
22/24 to 23/24 terminal candidate/report pairs. The newly completed row remains
`manual_review` with an `uncertain` verdict; the single remaining non-terminal
training row is stopped before report generation because the review anchor is
only present on the fix side. Substituting this later probe would make the
then-current 40-task covered set 36 complete candidate/report pairs and 4
producer-deferred or incomplete rows, still with 0 finalized rows.

A later removed-unsafe-option guard-anchor probe completes the same `train24`
workload at 24/24 terminal candidate/report pairs. That row also remains
`manual_review` with an `uncertain` verdict.

A follow-up access-scope and permissive-authorization-decision probe over the
same `test11` workload completes the three remaining test rows, moving them
from producer-deferred to complete `manual_review`. The current 40-task covered
set is therefore 40 complete candidate/report pairs, 0 producer-deferred or
incomplete rows, and 0 finalized rows.

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
| `test11-v3-authz-scope` | 99 | 1 | 76 | `entry_point` | `critical_operation`, `entry_point`, `trace`, title/category |
| `train24-v5-unsafe-option` | 216 | 3 | 165 | `entry_point` | `critical_operation`, `entry_point`, `trace`, title/category |
| `identifier-subset-v2/test1` | 9 | 0 | 7 | none | `critical_operation`, `entry_point`, `trace`, title/category |
| `identifier-subset-v2/train4` | 36 | 1 | 27 | `entry_point` | `critical_operation`, `entry_point`, `trace`, title/category |

Producer-deferred rows are now cleared for the current covered set:

| Batch | `guard_only_exists_on_fix_side` | `no_entry_candidate` | `required_checks_unavailable` |
| --- | ---: | ---: | ---: |
| `test11-v3-authz-scope` | 0 | 0 | 0 |
| `train24-v5-unsafe-option` | 0 | 0 | 0 |
| `identifier-subset-v2/test1` | 0 | 0 | 0 |
| `identifier-subset-v2/train4` | 0 | 0 | 0 |

The reviewer evidence files are path-free summaries. They include status,
completion state, Entry/report digests, field-level status counts,
incorrect/uncertain field names, missing-information categories, and deferred
reason codes. They omit field evidence text, source snippets, prompts, model
responses, and local paths.

These digests are reviewer evidence over the pinned closed-loop replay outputs,
not the final submission-prediction export bundle. The formal
`entries.jsonl`/`validation.jsonl`/`submission_manifest.json` export now runs on
both POSIX and Windows-native hosts for batches where every task has a terminal
candidate/report pair. Incomplete replay batches are intentionally rejected
with `incomplete_predictions` and must remain review evidence until the missing
candidate/report pairs are produced.

Digest anchors:

| Batch | Closed-loop dataset SHA-256 | Review evidence SHA-256 |
| --- | --- | --- |
| `test11-v3-authz-scope` | `8a314a8d9b5dd4c29e4e576e52e24a6e507ae973949a41743273dac3fe415c2a` | `68305bc9de4e857761831f302c9ef8116b16f6a119755ae7ef80ebc2d62c553c` |
| `train24-v5-unsafe-option` | `04ec0206095c0b6038190403efc56d531a1eca6184b2503928dd6df36c4bfec2` | `22445fb9b6f306ad1b5e683e61f96e1d09006fd5c6c2a4316ad0a262ddfbf800` |
| `identifier-subset-v2/test1` | `c2151999e0c68a6c38c6f02ea5c6dfe9c189169251ee948b57585f6bf5a5763d` | `4988b1e6d5c490fc8878b377679fa128dc73e1ce4595796f1a2723b25eb5f652` |
| `identifier-subset-v2/train4` | `797f75f8df8bca392d30c542fb494793ec5b4e6b137e4e540607312eb973e5fe` | `ba9d2403d1c4f28a9a738b16c8825539e01d93f515079f262bbd6382874764b0` |

Formal export anchors for the latest complete replay batches:

| Batch | Submission SHA-256 |
| --- | --- |
| `test11-v3-authz-scope` | `f06618b509afb7843ddcbfa94e6585cff76c22b56fe79e06d2ec0fbc1e3c557e` |
| `train24-v5-unsafe-option` | `48aebd686a749d8b25c95facb8445206910c4056d13ea366d54420f02a5cbcb8` |

The four latest covered-set exports can be combined into one 40-line package
with `submission_prediction_cli combine`. Its combined source-set SHA-256 is
`7ae810b9b157c071b77f494d69dacbbad9b062297cfb75af6c2c4f80d870ab48`; its
submission SHA-256 is
`0ff24779c984e82f4f83773d3f9b1694a8a4a4bb2c0134c5c6eeaa89b1430508`.

The next engineering choice is therefore not whether the pipeline runs. It
does. The choice is how aggressively to promote semantic facts:

1. Keep the current strict T1 and submit `manual_review` evidence as the honest
   audit trail for uncertain fields.
2. Add narrow T1 promotions only for facts that can be re-proved from public
   advisory text, local Git topology, and exact source snippets without using
   hidden answers.
3. Leave rows with incorrect `entry_point` or missing vulnerable-side operation
   evidence unfinalized until stronger evidence exists.
