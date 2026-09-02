# Full-Entry submission projection runbook

This runbook publishes the answer-file surface for Lane A. It does not run a
model, T2, or T1. It re-reads one already closed `closed_loop_cli` replay under
an externally supplied dataset digest and projects each complete terminal
candidate together with the T1 report that validated that same candidate.

This output is distinct from Lane B `findings.jsonl`. A Lane A submission
contains complete 15-field VulnGym Entries and their full validation reports.

## Export

Formal export is supported only on native POSIX hosts that provide
descriptor-relative directory operations and atomic no-replace rename
(`renameat2`). Run the final export and its native acceptance gate on Linux.
Non-POSIX hosts, including Windows, fail with `platform_unsupported` before
reading the source replay or changing the output. They may still run the
read-only `verify` command against an existing submission.

The replay dataset digest must come from a trusted channel outside the replay
directory. The output directory must not exist. Keep the replay, output, and
all protected inputs on disjoint filesystem objects; the writer checks both
canonical paths and directory identities.

```bash
export TMPDIR=/srv/vulngym/tmp

python -B -m vulngym_agent.submission_prediction_cli export \
  --replay-dir /srv/vulngym/lane-a/test-replay \
  --replay-dataset-sha256 <TRUSTED_REPLAY_DATASET_SHA256> \
  --expected-task-count 20 \
  --output-dir /srv/vulngym/lane-a/test-submission \
  --protected-path /srv/vulngym/benchmark-private
```

The fixed output contains:

```text
test-submission/
  entries.jsonl
  validation.jsonl
  submission_manifest.json
```

Every Entry has all 15 formal fields and `verify=0`. Every manifest task row
binds the task ID, physical input line, terminal status, Entry/report identity,
and the semantic digest of both records. `finalized` requires a `correct` T1
verdict. A `manual_review` row retains its actual non-correct T1 report rather
than being silently dropped or relabelled.

Export fails if the replay contains an input failure, a missing terminal
candidate/report pair, an unsupported terminal status, or a task count other
than the fixed expected count. It publishes through a private staging
directory and a no-replace rename. Suspicious staging replacement is retained
for diagnosis. Any failed staging transaction is retained in full; the writer
does not unlink staging names because identity-check-then-unlink cleanup cannot
exclude a same-user replacement race.

Successful stdout is canonical, path-free JSON. Record both
`source_replay_dataset_sha256` and `submission_sha256` outside the output
directory.

## Independent verification

Do not verify the submission only against its own manifest. Formal verification
must receive the original replay and both external digests; it re-reads the
pinned replay and compares every projected task, Entry, T1 report, status, and
ordering field.

```powershell
python -B -m vulngym_agent.submission_prediction_cli verify `
  --submission-dir D:\VulnGym-bv2-runtime\lane-a\test-submission `
  --replay-dir D:\VulnGym-bv2-runtime\lane-a\test-replay `
  --source-replay-dataset-sha256 <TRUSTED_REPLAY_DATASET_SHA256> `
  --submission-sha256 <EXTERNAL_SUBMISSION_SHA256> `
  --expected-task-count 20 `
  --protected-path D:\VulnGym-bv2-runtime\benchmark-private
```

The verifier does not read benchmark gold. Protected path spellings are also
rejected from replay artifacts, and output/replay/protected roots are guarded
against symlink, reparse-point, hard-link, rename, and exact-root or ancestor
identity aliases where the host exposes the required primitives. Descendant
bind mounts remain the responsibility of the native runtime's fixed mount
policy; this projector does not claim to enumerate the host mount table.

## Exit status and recovery

- `0`: export or independent verification completed.
- `2`: rejected before any publication was confirmed.
- `11`: publication may have committed. Preserve the output and verify it
  under the expected external digests; never blindly rerun to the same path.
- `130`: interrupted before publication was possible.

Digest closure proves which bytes were projected from which replay. It does
not prove that the model's semantic conclusion is true, and it does not replace
the blind evaluator or the required native-Linux gate.
