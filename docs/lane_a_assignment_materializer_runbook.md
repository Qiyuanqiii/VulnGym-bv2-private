# Lane A advisory-assignment materializer

This tool deterministically creates the reviewed assignment and local evidence
package consumed by `lane_a_task_bundle_cli`. `build` and `verify` are strictly
offline: neither command invokes `gh`, Git remotes, credential helpers, or a
network transport.

## Cleared inputs

Use the `tasks.jsonl` member of an independently verified answer-free task
export. The other inputs are:

- canonical public `reports.jsonl` metadata only (the ten report-level fields
  documented in `SCHEMA.md`);
- a canonical, LF-terminated sanitized advisory cache;
- a canonical, LF-terminated repository map whose entries are sorted by
  normalized GitHub URL and point to complete offline repositories.

Do not supply `entries.jsonl`, a selection lock, a source map, gold data, or
training-answer payloads. Input files must be regular, singly-linked files and
must not traverse aliases, symlinks, junctions, or reparse points.

Each advisory-cache line has exactly this shape:

```json
{"description":"Public advisory prose.","ghsa_id":"GHSA-1111-2222-3333","identifiers":[{"type":"GHSA","value":"GHSA-1111-2222-3333"}],"references":["https://github.com/example/repo/commit/0123456789abcdef0123456789abcdef01234567"],"summary":"Public advisory title"}
```

`references` is a sorted, unique list. The materializer accepts a fix candidate
only when a reference is an exact HTTPS URL for the task's normalized GitHub
repository followed by `/commit/` and 40 hexadecimal characters. It then
requires exactly one candidate whose immutable commit object has exactly the
answer-free vulnerable commit as its only parent.

### Separate optional network pre-step

Fetch outside the build environment, one requested GHSA at a time:

```powershell
gh api -H "Accept: application/vnd.github+json" /advisories/GHSA-1111-2222-3333 > GHSA-1111-2222-3333.raw.json
```

Review and reduce those responses to the five-field cache contract above,
sort references and rows, serialize canonical UTF-8 JSON with LF framing, and
pin the finished cache. Never pass the raw API response to `build`. This
network step is intentionally not part of the materializer CLI.

## Review-time pins

Compute pins in a separate review step. Production commands require every pin
to be supplied again and never learn one from an existing output:

```python
from vulngym_agent.lane_a_assignment_materializer import compute_lane_a_assignment_input_pins

print(compute_lane_a_assignment_input_pins(
    r"D:\cleared\test-export\tasks.jsonl",
    r"D:\cleared\reports.jsonl",
    r"D:\cleared\ghsa-cache.jsonl",
    r"D:\cleared\repos.json",
))
```

The result contains semantic and exact-wire SHA-256 values for all four inputs
plus the task count.

## Offline build

```powershell
python -B -m vulngym_agent.lane_a_assignment_materializer_cli build `
  --public-tasks-file D:\cleared\test-export\tasks.jsonl `
  --reports-file D:\cleared\reports.jsonl `
  --advisory-cache-file D:\cleared\ghsa-cache.jsonl `
  --repo-map-file D:\cleared\repos.json `
  --expected-public-tasks-sha256 TASKS_SEMANTIC_SHA256 `
  --expected-public-tasks-wire-sha256 TASKS_WIRE_SHA256 `
  --expected-reports-sha256 REPORTS_SEMANTIC_SHA256 `
  --expected-reports-wire-sha256 REPORTS_WIRE_SHA256 `
  --expected-advisory-cache-sha256 CACHE_SEMANTIC_SHA256 `
  --expected-advisory-cache-wire-sha256 CACHE_WIRE_SHA256 `
  --expected-repo-map-sha256 REPO_MAP_SEMANTIC_SHA256 `
  --expected-repo-map-wire-sha256 REPO_MAP_WIRE_SHA256 `
  --expected-task-count 20 `
  --protected-path D:\cleared `
  --output-dir D:\lane-a\assignment-package
```

The v1 policy joins by exact `(normalized repo_url, vulnerable commit)`, chooses
the lexicographically smallest `report_id`, then its smallest public
`entry_id`. It publishes one runnable assignment per task. Every other entry
and report for the same snapshot is listed in `coverage-audit.jsonl`; it is not
claimed as executed coverage. The audit labels the chosen ID as a
`deterministic_evaluation_anchor_not_finding_provenance`: selection does not
claim that T2 found, reconstructed, or was guided by that public Entry's
private source locations.

Changed paths are obtained by comparing the vulnerable and fix Git trees.
Only bounded UTF-8 diffs for source suffixes supported by the current T2 entry
searcher are emitted. A missing, mode-only, binary, non-source, oversized, or
ambiguous diff rejects the whole build.

The acceptance bounds are the downstream T2 toolbox bounds, not the broader
evidence-loader defaults: each advisory and combined patch file is at most
256 KiB, each per-path Git diff is at most 96 KiB, and the two source blobs for
a diff total at most 512 KiB (with each blob at most 256 KiB). The complete
identifier tuple extracted from the materialized advisory must exactly equal
the selected public report's normalized `vuln_ids`; extra and missing IDs both
fail closed.

The output directory contains `assignments.jsonl`, `coverage-audit.jsonl`,
`manifest.json`, and one flat `advisory-GHSA-....json` and
`patch-GHSA-....diff` pair per selected task. Publication uses a private sibling
staging directory, descriptor/handle-bound readback, an atomic no-replace
rename, and final readback. Failures never auto-delete staging. Exit code `11`
means publication may already be committed; verify before taking any action.

## Independent verification

```powershell
python -B -m vulngym_agent.lane_a_assignment_materializer_cli verify `
  --public-tasks-file D:\cleared\test-export\tasks.jsonl `
  --reports-file D:\cleared\reports.jsonl `
  --advisory-cache-file D:\cleared\ghsa-cache.jsonl `
  --repo-map-file D:\cleared\repos.json `
  --expected-public-tasks-sha256 TASKS_SEMANTIC_SHA256 `
  --expected-public-tasks-wire-sha256 TASKS_WIRE_SHA256 `
  --expected-reports-sha256 REPORTS_SEMANTIC_SHA256 `
  --expected-reports-wire-sha256 REPORTS_WIRE_SHA256 `
  --expected-advisory-cache-sha256 CACHE_SEMANTIC_SHA256 `
  --expected-advisory-cache-wire-sha256 CACHE_WIRE_SHA256 `
  --expected-repo-map-sha256 REPO_MAP_SEMANTIC_SHA256 `
  --expected-repo-map-wire-sha256 REPO_MAP_WIRE_SHA256 `
  --expected-task-count 20 `
  --materialization-dir D:\lane-a\assignment-package `
  --expected-materialization-sha256 MATERIALIZATION_SHA256 `
  --expected-manifest-wire-sha256 MANIFEST_WIRE_SHA256
```

Verification reopens every original pinned input and offline Git object store,
regenerates every byte, and compares the published directory twice.

For the next step, use
`D:\lane-a\assignment-package\assignments.jsonl` as the assignment input and
`D:\lane-a\assignment-package` as the closed-loop `--package-root`. When
publishing the separate task bundle, pass the whole assignment-package
directory as a protected path and place the bundle under a disjoint output
parent.
