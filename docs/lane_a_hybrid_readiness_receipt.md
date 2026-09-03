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

Current machine-materializable coverage with the strict, local direct-child
fallback, and identifier-subset fallback policies combined, after full
source-diff and materialized-advisory-fact validation:

| Split | Tasks | Strict materialized | Local-child fallback materialized | Identifier-subset materialized | Validated automatic-policy rejected | Total materialized | Rate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Public test | 20 | 8 | 3 | 1 | 1 | 12 | 60.0% |
| Public train | 50 | 14 | 10 | 4 | 2 | 28 | 56.0% |
| Total | 70 | 22 | 13 | 5 | 3 | 40 | 57.1% |

`VG-TRAIN-43AC81B29F131DE6F550` is now materialized after adding `.svelte` to
the bounded source-diff suffix set; its public fix changes
`src/lib/components/common/RichTextInput.svelte`. The remaining rejected
automatic-policy candidates are `VG-TEST-942B24B6D9A484E361A2`, whose public
advisory projection exposes an additional vulnerability identifier during
fact extraction; `VG-TRAIN-640FF6DE344026468477`, whose local-child candidate
still has no bounded source diff; and `VG-TRAIN-D335B462947DB4339FB5`, whose
identifier-subset projection exposes an additional GHSA identifier in public
prose. These tasks are kept out of the automatic Lane A batch until manual
review or a stronger fact-isolation rule exists.

Fallback materialization digests:

| Batch | Tasks | Materialization SHA-256 | Manifest wire SHA-256 |
| --- | ---: | --- | --- |
| `test3` | 3 | `130188977378e0d71a45485ca9799a95b02cd3fc38a635aa00b3446c34db4b0a` | `eed9c4ea32dad976716c70a56dbb355f36e0f54d9be0ee49d773cfda6197981f` |
| `train10` | 10 | `f8e266ed412e0933ff9cd03c255bdccabbb72d086f7f10d03a2852a3e0ce0ab1` | `b92ca1f4bac6d603e1e51bb36e0890042888e6a0aa39c8135bb5b90ab0fad131` |

Combined materialization digests:

| Batch | Tasks | Materialization SHA-256 | Manifest wire SHA-256 | Assignments wire SHA-256 |
| --- | ---: | --- | --- | --- |
| `test11` | 11 | `597c830fc0f0c3a3bda8c26e208be74fea2da8cc7d2a3916f68916f232e634e5` | `dd3e3a990bf4664825502d513628f1388cb3ca4ecbbcbcc811b9bed27e56148b` | `68fc4b6ee7b7311eeac9ab8041795e72ca6439bac8632a8f51bf25a33c4db881` |
| `train23` | 23 | `fb91367fc08b6bbe455e40deb0a032adfc9d226d41232b0fcecafb05a535d5f4` | `58efc9205c844fcf329828d6e448d9e2269ccf1630c8c2417945ef5033d45861` | `3535765558f59804cb3d43c4c1f5847d0c56cae2fdf2bb7907cb0bc5c07f863a` |
| `strict-v2/train-43ac81` | 1 | `2a19d26d9c98278ee184e4fdd88cb7cca135d2f562837b04f298b19142904295` | `3f707160d40dc045dcd55f81d3df572cacfac188c5595459e02bded9be0f2e04` | `03d72d2f99e1fb425add42dfc4c2dcbafbbb7f8b96a72ee83dc30ae8e862c748` |

Identifier-subset v2 incremental materialization digests:

| Batch | Tasks | Materialization SHA-256 | Manifest wire SHA-256 | Assignments wire SHA-256 |
| --- | ---: | --- | --- | --- |
| `test1` | 1 | `5cf347e0c6d88794bcff121efe1c4865a465633f278b5a0a33825f688003074a` | `1215ca68e7bf95cb8721587498ea7f0ea023820e75b341d5ae2f3390b64b7e70` | `f0b5297945ecbee60a7b7635100cf84bb487dfc98cbb90cd8401a1e2252993d7` |
| `train4` | 4 | `eb15e47ae2f2f73921bff306168e08034e7a0d18e9fe449ee83ae9ffd7c915e8` | `9030a5a986ac14433ed34bfcd5c0e214ab0e8c3ae40c32ba71882e56b3ef090f` | `ea1532aa53e192a3d1d57e0da0549e7a1e69fc21567c06b651771800831fd53` |

Verified Lane A task-bundle digests:

| Bundle | Tasks | Bundle SHA-256 | Manifest wire SHA-256 | Run tasks wire SHA-256 |
| --- | ---: | --- | --- | --- |
| `test11` | 11 | `b0136dd45da74d7f11a3e4f56b72f922611b381627dde6064681f927cea7ddd8` | `a0c268d4bd3aa098665ed284e339f0f8bee25afd7e5451f7773df8390e4d1ef7` | `02d36aaebc31c3931b08fe13fd2882b6d85c96954d643aa56abe95bf214af3a4` |
| `train23` | 23 | `022d1903ffc074cb2cd4ade53d461e95c49d058eaf442bf5768e441d110a1db8` | `1191aa2fbf53ad0942d0d178ce56d5a6ef469c43ab1bebdefcc5af5be0de6c6f` | `0d3e01ac78ad8a57652c22fd59cec2e97597db83ee56c2879520be5eb7ad9a96` |
| `identifier-subset-v2/test1` | 1 | `a45d3e141460b465b086479132f7dba9c361d8cdee39daac92d84fa56a4eb346` | `f50b8d4ed0ae9e72752af7ced754612abfc2932f5485264f1dfa53d977605992` | `9963e72eaa55da50a59ed630335242817b73c918b9058e3adebb748de6ba7467` |
| `identifier-subset-v2/train4` | 4 | `ef1a0eba5b89ac1b888290ad346d3214b2c1f7bc23fe56afc8c7fa2a970335f3` | `26764457d17c4f7f64ef39d5d0cf05abb526e4d2e37ce49665e4b2df8171e34c` | `87b7fceed24afad8f4cf186f3dd14305fac7756add52b0a7189435673316fdc8` |
| `strict-v2/train-43ac81` | 1 | `e09255bd6256f5a4448ff528735df302bc4bfc168c8e6d6fe0424ce3723e16ce` | `2c8ead8e61afd7489a4d000d7d0b6be87d86367c8894384616fff46979b50fa7` | `e381a4419e5ce513088d4603a7b2e80a26e666540abb0b37f20f9ba93dd4fae9` |

All listed task bundles were verified against their pinned public task and assignment
inputs, and a public marker scan over the committed bundle files returned no
restricted path or private-control markers.

The remaining blockers are materialization gaps, not T1/T2 runtime failures.
They need separate reviewer-auditable policies or refresh steps before they can
be safely added to automated batches.

## Historical strict-only T2-to-T1 batch result

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

## Expanded hybrid T2-to-T1 batch result

The verified strict+fallback task bundles were then executed through the same
offline authoring and production closed-loop path.

Authoring summaries:

| Batch | Tasks | Exact replay verified | Response count | Status counts | Verdict counts |
| --- | ---: | --- | ---: | --- | --- |
| `test11` | 11 | true | 27 | `manual_review=11` | `incorrect=2`, `uncertain=6` |
| `test11-v3-authz-scope` | 11 | true | 33 | `manual_review=11` | `incorrect=1`, `uncertain=10` |
| `train23` | 23 | true | 61 | `manual_review=23` | `incorrect=2`, `uncertain=17` |
| `train24-v2-review-anchor` | 24 | true | 64 | `manual_review=24` | `incorrect=2`, `uncertain=18` |
| `train24-v5-unsafe-option` | 24 | true | 72 | `manual_review=24` | `incorrect=3`, `uncertain=21` |
| `identifier-subset-v2/test1` | 1 | true | 3 | `manual_review=1` | `uncertain=1` |
| `identifier-subset-v2/train4` | 4 | true | 12 | `manual_review=4` | `incorrect=1`, `uncertain=3` |
| `strict-v2/train-43ac81` | 1 | true | 1 | `manual_review=1` | none |

Closed-loop runner summaries:

| Batch | Tasks run | Records seen | Manual review | Finalized | Input failures | Status |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `test11` | 11 | 11 | 11 | 0 | 0 | ok |
| `test11-v3-authz-scope` | 11 | 11 | 11 | 0 | 0 | ok |
| `train23` | 23 | 23 | 23 | 0 | 0 | ok |
| `train24-v2-review-anchor` | 24 | 24 | 24 | 0 | 0 | ok |
| `train24-v5-unsafe-option` | 24 | 24 | 24 | 0 | 0 | ok |
| `identifier-subset-v2/test1` | 1 | 1 | 1 | 0 | 0 | ok |
| `identifier-subset-v2/train4` | 4 | 4 | 4 | 0 | 0 | ok |
| `strict-v2/train-43ac81` | 1 | 1 | 1 | 0 | 0 | ok |

Reviewer evidence summaries:

| Batch | Complete candidate/report pairs | Producer-deferred or incomplete | Review evidence SHA-256 |
| --- | ---: | ---: | --- |
| `test11` | 8 | 3 | `367bd779089dbb5942b323cfd553d3d8c4908f526e4e3ecb1fe02492c5a3b46a` |
| `test11-v3-authz-scope` | 11 | 0 | `68305bc9de4e857761831f302c9ef8116b16f6a119755ae7ef80ebc2d62c553c` |
| `train23` | 19 | 4 | `a1c49ec59abbbe0df612826594026a436158aab2c34a5c126f89ba7bf2ca8d72` |
| `train24-v2-review-anchor` | 20 | 4 | `161cdcd470bb1d5629b533355c4e553e61c8cf5645f28b4c343018d82adf3c62` |
| `train24-v5-unsafe-option` | 24 | 0 | `22445fb9b6f306ad1b5e683e61f96e1d09006fd5c6c2a4316ad0a262ddfbf800` |
| `identifier-subset-v2/test1` | 1 | 0 | `4988b1e6d5c490fc8878b377679fa128dc73e1ce4595796f1a2723b25eb5f652` |
| `identifier-subset-v2/train4` | 4 | 0 | `ba9d2403d1c4f28a9a738b16c8825539e01d93f515079f262bbd6382874764b0` |
| `strict-v2/train-43ac81` | 0 | 1 | `86fad1282f1b5f25f26c3b19fc0bffd15cd3798d2d6d95e5a120f284f0737e0b` |

The current non-duplicated 40-task covered set is `test11-v3-authz-scope`,
`train24-v5-unsafe-option`, `identifier-subset-v2/test1`, and
`identifier-subset-v2/train4`: 40 complete candidate/report pairs, 0
producer-deferred or incomplete rows, and 0 finalized rows.

Expanded batch digests:

| Batch | Exact replay wire SHA-256 | Closed-loop dataset SHA-256 | Run manifest SHA-256 | Candidates SHA-256 | Validation SHA-256 | Deferred SHA-256 |
| --- | --- | --- | --- | --- | --- | --- |
| `test11` | `bac85d8812aa6264304526ab9450ad5bd76834b186a621d7f3abe6a78b2b1bd1` | `41c43389faa823a115890637bb4b85cf770dde8b87defde751b53e6efb18c57b` | `be4fdb904065063cc61f5a36b8c5a24454e7eea280a3256cda2ef0e84ca171de` | `e4d17d173ccd24f1536bf7383548a16db56f7e9dd4a6c1f352a0c0452fe862d2` | `b10e2da85b42b23cab02b7ecc222605aa425f4cfcb374823c625df1c86baff0f` | `a8e96613c0f7dfd4e93d1f17ed79b7c487ce273cdd8cea6463cace41f6e98538` |
| `test11-v3-authz-scope` | `48f32f812c392d3fbcc312418c44de8020715a854a782290dffa2efbce120841` | `8a314a8d9b5dd4c29e4e576e52e24a6e507ae973949a41743273dac3fe415c2a` | `350ff783e3996a878939efba3acfcfe691f5dd5f40dcc70100776811c735fb7a` | `80f81a4bc72206a9b97017b181fd7ad1668c7f61bd855ae4234ce003c8ff96db` | `eeecb74b6fc93bd3eef2e0e80190d77f70e954ea60696d8c41d149b49872a723` | `26a4e2c056e280325c2683793f82f4f751f6823da36f1eb7cdbb0e5728a3b90e` |
| `train23` | `da63ac0c59111570dfd66647736f41a84ab6641c09acb56a01bb8916823e4655` | `c2d30c379a8742d251c2d82c575da6c358add86f7d2046cf5af0e47c0a444cc0` | `5e8ddfe00aa29e1711932649b9695a30678864600b00fa2a45202a2e56f5b745` | `6f77234e1a1a73155ad8dfa07a2279ada65ef7eb2c3b6b3242c6464ca1eb5475` | `f21c634627a8d04b152e375b294f321ce66e0549e7adef7aa9dfa7359c7d18ae` | `be0fa4b02530d1003e813f2ec98ad5f5bf18a2f845c148245b86a81e3d2cbc92` |
| `train24-v2-review-anchor` | `689ee3419e18cb7cd8518cb7d09e6a78b183a1aa9c39389153931228df32e563` | `a2b6f487a6bd1208728d91777f605c5834ba50c35fba6fd9843e46eb7c21925b` | `b779ff87595f80a916cac4da6440e1a5b90a78ec17ce8b8dc5fb813631fb52c9` | `0c063d86c11dc6efb76f7d2b61e6123d1d4b88c0063da3dbaf080fe7a88cd506` | `a6df0c7d01b550b48a717fbc372dd64c859b4241de299d287f4e299cb832e973` | `e3ded47d4e6fe8629f907a775ec23f06099fdcc594e291745d63937c55277ff5` |
| `train24-v5-unsafe-option` | `2b63187933e47f127771c0e338d2d716483fbec7379649e8b673c73d8dd9569e` | `04ec0206095c0b6038190403efc56d531a1eca6184b2503928dd6df36c4bfec2` | `2ed3e5be8906cbbb2846e3e003508d57c76e1c889f03988bb106f7af6122bbd3` | `3dddb01036d470160a71cf96463c39df230d6ab221605f0ccb9c77348d801f8f` | `4a545bea1487b53aaf8785c67480b53092c3ed99f71db77e8cd6844ba4b7664d` | `46cbbb4d03cb249e86dd15ad6c5bfebf2d2b9cd2539a1eea398ba80fa3f03c0c` |
| `identifier-subset-v2/test1` | `fe8f6458f2b66e646fafb47fe1cbd0c87e7c387068a7c86e530fd4eefa94af9c` | `c2151999e0c68a6c38c6f02ea5c6dfe9c189169251ee948b57585f6bf5a5763d` | `c8b40e284877579b5254277f3132a7fe06123067d6877a3af35ec9703397b20b` | `e1fae809c8139c71f7c05ab8996584ba9be7d208f15ffcca9a68b883ee9fd089` | `c2259ac296e48d3a2a648f4ad7d5178a783ca2db376ba7f88fad7cf6e2525004` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `identifier-subset-v2/train4` | `58508e0083b0e96b086aea5d8c296fd63e3356e84e867c92e08e11c0ca1914c2` | `797f75f8df8bca392d30c542fb494793ec5b4e6b137e4e540607312eb973e5fe` | `cf487d6767064b6d7d6a81c0aebc631d3a385f8cb6577342deec948428d2b351` | `d8540ad5841ed9e866ea0e51360b0b67f611babc80ae36cddb4fbe3d147ea796` | `d4b608305e004a8ae6c5e2a66784799c0f5d22ffaa1670d48aa39570979d712f` | `83dc9d5425336b24d2b81a2c092bbd273b04ae9e384c750d7902d2fa879d95a2` |
| `strict-v2/train-43ac81` | `6ff129a830443d3e0a6a09e60259ea4c117e37438372c9d6652eb49ea2f5aa91` | `2143c8cfdbcbaf3f8da159eed584fbb402a7710f2a70562ea6f21bd68295b068` | `82277e4f72a9e873aaa9b322f81444758ab0a19967cdabc9afeee90fb811f430` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `abc2089b78a11c0ee41c1af4cfc1c028f286341c8ff6e2cb16b2a7833620a82c` |

The expanded closed-loop and review evidence marker scan covered `30` generated
public files and found `0` restricted path or private-control marker hits. The
identifier-subset v2 incremental scan covered `61` generated files, excluding
trusted local repo-map configuration files, and found `0` restricted marker or
local-path hits. The strict-v2 `train-43ac81` incremental scan covered `26`
generated files, excluding trusted local repo-map configuration files, and found
`0` restricted marker or local-path hits. The newer `test11-v3-authz-scope` and
`train24-v5-unsafe-option` replays are the current consolidated test/training
views for the 40-task covered set.

### Guard-anchor authoring probe

After adding old-side guard anchors for sanitizer/normalizer replacements and
assertion namespace calls, a local exact-replay authoring probe over the same
24 training tasks completed successfully. This probe is code-level readiness
evidence; it does not replace the pinned `train24-v2-review-anchor` publication
bundle until the sanitized public artifacts are regenerated.

| Probe | Exact replay SHA-256 | Exact replay wire SHA-256 | Responses | Terminal candidate/report pairs | Producer-deferred or incomplete | Finalized |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| `train24-v3-guard-anchor` | `e02e18f01ae7c48b6542acdc72255ab484af41db9060718fa5cd847345b98130` | `5a1f966bbf98a29665c91e8965de46dd002335def2e26176fcbf3cdbbb2bca6c` | 68 | 22 | 2 | 0 |
| `train24-v4-svelte-entry` | `1b6b3abdfacba443b264a7457485c02720bea2ce16d22db62761db035679b1e6` | `e94ac5eef4ea121e3396ce0b57ea9dc7671cfb0a046c96b54dbf40b6cf3a1ca1` | 70 | 23 | 1 | 0 |
| `train24-v5-unsafe-option` | `588e4fce68753c9c1462c96e4ce3b1f5e93eb4acc9168a1fff304212b5e4978d` | `2b63187933e47f127771c0e338d2d716483fbec7379649e8b673c73d8dd9569e` | 72 | 24 | 0 | 0 |

The two additional terminal candidate/report pairs are
`VG-TRAIN-727D94F6A27E96DB4DAC` (`uncertain`) and
`VG-TRAIN-8FEE6A4371C6C410BCB8` (`incorrect`). The remaining non-terminal rows
are `VG-TRAIN-43AC81B29F131DE6F550` (`no_entry_candidate`) and
`VG-TRAIN-747C63B97771B863292B` (`guard_only_exists_on_fix_side`). At this
intermediate point, replacing `train24-v2-review-anchor` in the non-duplicated
covered set would have produced 35 terminal candidate/report pairs, 5
producer-deferred or incomplete rows, and 0 finalized rows.

After adding `.svelte` to the bounded entry-search language set, a follow-up
probe over the same 24 tasks moved `VG-TRAIN-43AC81B29F131DE6F550` from
`no_entry_candidate` to complete `manual_review` with an `uncertain` verdict.
The only remaining non-terminal training row in that probe is
`VG-TRAIN-747C63B97771B863292B`
(`guard_only_exists_on_fix_side`). The closed-loop runner accepted the replay
with `tasks_run=24`, `manual_review=24`, `failed=0`, and `input_failures=0`.
At this intermediate point, replacing `train24-v2-review-anchor` in the
non-duplicated covered set would have produced 36 terminal candidate/report
pairs, 4 producer-deferred or incomplete rows, and 0 finalized rows.

After adding a narrow old-side anchor for removed unsafe deserialization
options, the follow-up `train24-v5-unsafe-option` probe moved
`VG-TRAIN-747C63B97771B863292B` from
`guard_only_exists_on_fix_side` to complete `manual_review` with an
`uncertain` verdict. The closed-loop runner accepted this replay with
`tasks_run=24`, `manual_review=24`, `failed=0`, and `input_failures=0`.
The runner dataset SHA-256 is
`04ec0206095c0b6038190403efc56d531a1eca6184b2503928dd6df36c4bfec2`.
`submission_prediction_cli export` and double-pin `verify` both succeeded for
this batch, producing submission SHA-256
`48aebd686a749d8b25c95facb8445206910c4056d13ea366d54420f02a5cbcb8` and
review-evidence SHA-256
`22445fb9b6f306ad1b5e683e61f96e1d09006fd5c6c2a4316ad0a262ddfbf800`.
Before the follow-up test-side probe, replacing `train24-v2-review-anchor` in
the non-duplicated covered set would have produced 37 terminal candidate/report
pairs, 3 producer-deferred or incomplete rows, and 0 finalized rows.

After adding access-scope propagation anchors and removed permissive
authorization-decision anchors, the follow-up `test11-v3-authz-scope` probe
moved `VG-TEST-A1EBF05AB83CEA26E60E`,
`VG-TEST-BF91B957B02CA987C926`, and
`VG-TEST-F18FEB614A9AFF680A8E` from
`guard_only_exists_on_fix_side` to complete `manual_review`. The closed-loop
runner accepted this replay with `tasks_run=11`, `manual_review=11`,
`failed=0`, and `input_failures=0`. The runner dataset SHA-256 is
`8a314a8d9b5dd4c29e4e576e52e24a6e507ae973949a41743273dac3fe415c2a`.
`submission_prediction_cli export` and double-pin `verify` both succeeded for
this batch, producing submission SHA-256
`f06618b509afb7843ddcbfa94e6585cff76c22b56fe79e06d2ec0fbc1e3c557e`
and review-evidence SHA-256
`68305bc9de4e857761831f302c9ef8116b16f6a119755ae7ef80ebc2d62c553c`.
With `test11-v3-authz-scope` and `train24-v5-unsafe-option` replacing the older
test/training replays in the current non-duplicated covered set, all 40 covered
tasks now have complete candidate/report pairs, 0 are producer-deferred or
incomplete, and 0 are finalized.

The current covered-set exports can now be mechanically combined with
`submission_prediction_cli combine`. The combined package rebases local
sub-batch `entry_id` and `input_line` values into a single 40-line order and
publishes a path-free manifest. Readback of the combined package succeeded with
source-set SHA-256
`7ae810b9b157c071b77f494d69dacbbad9b062297cfb75af6c2c4f80d870ab48`,
submission SHA-256
`0ff24779c984e82f4f83773d3f9b1694a8a4a4bb2c0134c5c6eeaa89b1430508`,
`status_counts={"manual_review":40}`, and
`verdict_counts={"incorrect":5,"uncertain":35}`.

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

`submission_prediction_cli export` now supports both native POSIX hosts and
Windows-native hosts. POSIX uses descriptor-relative publication where
available; Windows uses private staging, no-replace final rename, and
post-publication readback. Export remains stricter than review: incomplete
replays are rejected with `incomplete_predictions` instead of producing a
partial submission bundle. The exact export/verify command matrix is in
`docs/submission/submission_prediction_posix_export_runbook.md`.

## Next acceptance work

1. Add narrow T1 promotions only where evidence is exact and reproducible. Do
   not globally lower the finalized threshold and do not auto-finalize records
   with known incorrect entry-point evidence.
2. Continue the remaining 30-task materialization backlog through identifier
   subset policy, local repository refresh, public metadata refresh, and manual
   review where no direct-child policy can be justified.
3. Turn the expanded reviewer evidence into the final submission-facing
   narrative: every `manual_review` must explain which exact facts passed,
   which facts are still semantic, and why no hidden answer was used.
