# VulnGym 50/20 reproducible split

This package derives 50 answered training tasks and 20 answer-free public test
tasks from the public Tencent VulnGym v0.1.4 data. It does not import or modify
`vulngym_agent/`.

## What one task means

A task is one immutable `(repo_url, commit)` repository snapshot. All
advisories at that snapshot are co-located, and every advisory contains all of
its source entries as acceptable gold. This is stricter than advisory-only
grouping: neither an advisory nor an identical repository snapshot can cross
from train to test.

Only snapshots for which **every advisory and every entry is `verify = 1`** are
eligible. Starting from 408 entries / 184 advisories, the source has 393
verified entries and 174 fully verified advisories. Excluding any snapshot that
contains a partial or unverified advisory leaves 156 eligible snapshot tasks,
172 advisories, and 380 entries.

The sampling algorithm is deterministic and balances three marginal axes:

- repository (`repo_url`);
- vulnerability category (`vuln_category_l1`);
- primary language derived from `entry_point.file` and
  `critical_operation.file` using the versioned extension map in `config/`;
  Go, Python, and TypeScript are retained and rarer labels form `Other`.

It uses eight stable-hash restarts followed by deterministic pair swaps. The
seed, objective, targets, actual counts, and errors are recorded in
`reports/stratification.json`.

## Files

- `public/train.jsonl`: 50 records with `task` and `gold`.
- `public/test.jsonl`: 20 records containing only opaque task ID, repository,
  vulnerable commit, split, and instruction ID.
- `private/test_gold.jsonl`: evaluator-only task-ID-to-gold mapping (Git-ignored).
- `private/selection_lock.json`: exact evaluator-only split provenance
  (Git-ignored).
- `manifests/source_and_hash_manifest.json`: upstream revision, source hashes,
  build policy, and public artifact hashes.
- `manifests/SHA256SUMS`: checksums for all public/static deliverables except
  the checksum file itself.
- `schemas/benchmark-record.schema.json`: train, test, and private-gold record
  schema.
- `reports/schema_validation.json`: formal JSON Schema and cross-row checks.
- `reports/leakage_check.json`: advisory, entry, identifier, snapshot, all-node
  location, normalized long-code, field-denylist, and token leakage checks.

## Build and verify

From the repository root, using Python 3.11 or newer:

```powershell
python -m pip install -r benchmarks/vulngym_50_20_v1/requirements.txt
python -B scripts/build_vulngym_50_20.py
python -B scripts/build_vulngym_50_20.py --check
```

For a stronger filesystem boundary, write evaluator files to a separate
access-controlled root from the start (and pass the same option to `--check`):

```powershell
python -B scripts/build_vulngym_50_20.py `
  --private-output-root D:\secure\vulngym_50_20_gold
```

`--check` pins and re-hashes `data/entries.jsonl`, `data/reports.jsonl`,
`SCHEMA.md`, and `LICENSE`, rebuilds every generated artifact in memory, reruns
JSON Schema and leakage checks, and compares all outputs byte-for-byte.

The public task contract identified by `vulngym-whitebox-locate-v1` is:

1. Check out the exact `repo_url` at `commit` without applying a fix.
2. Perform white-box vulnerability discovery on that snapshot.
3. Emit JSONL findings containing `repo_url`, `commit`, `entry_point` and
   `critical_operation`; each location contains repository-relative `file` and
   positive `line` (integer or inclusive `start-end` range). `trace` is
   optional.
4. Score findings outside the agent sandbox against all verified entries in
   the task gold. Advisory-level recall is primary; entry-level recall is
   secondary, consistent with `examples/evaluate.py`.

## Gold isolation protocol

The agent-visible allowlist is exactly:

```text
public/test.jsonl
<target repository checkout at the requested commit>
```

For a closed-book evaluation, copy those inputs into a separate sandbox. Do
not mount this VulnGym checkout, `data/`, `private/`, the generator, evaluator
logs, or other tasks, and disable network access. The evaluator process reads
`private/test_gold.jsonl` from outside the sandbox.

The original VulnGym annotations and GitHub advisories are public. Therefore
"private gold" here means withheld derivative artifact plus runtime isolation;
it cannot mean that the underlying vulnerability facts have never been public.
An agent that can read the source dataset or use the Internet can correlate
`repo_url` and `commit` back to public answers.

See `NOTICE.md` for attribution and licensing notes.
