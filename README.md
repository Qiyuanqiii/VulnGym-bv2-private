<p align="center">
  <img src="./img/wukong_logo.png" alt="VulnGym" height="60">
</p>

<h4 align="center">
    <p>
        <a href="./README_zh.md">中文</a> |
        <a href="#">English</a>
    </p>
</h4>

<p align="center">
  <a href="https://github.com/Tencent/VulnGym/stargazers"><img alt="GitHub Stars" src="https://img.shields.io/github/stars/Tencent/VulnGym?color=gold"></a>
  <a href="https://github.com/Tencent/VulnGym/network/members"><img alt="GitHub Forks" src="https://img.shields.io/github/forks/Tencent/VulnGym?color=gold"></a>
  <a href="./LICENSE"><img alt="License" src="https://img.shields.io/badge/License-CC--BY--4.0-blue.svg"></a>
</p>

<p align="center">
  <b>A Real-World, Project-Level Vulnerability Benchmark for White-Box Vulnerability-Hunting Agents</b>
</p>

<p align="center">
  <a href="https://github.com/Tencent/VulnGym"><img src="https://img.shields.io/badge/⭐-Give VulnGym a Star-yellow?style=flat&logo=github" alt="Give VulnGym a Star"></a>
  <a href="https://huggingface.co/datasets/tencent/VulnGym"><img src="https://img.shields.io/badge/🤗%20HuggingFace-Dataset-yellow?style=flat" alt="HuggingFace Dataset"></a>
</p>

**VulnGym** is a project-level benchmark for white-box vulnerability-hunting agents, designed to evaluate an agent's vulnerability detection capabilities within **real-world engineering contexts**, with **verifiable vulnerability trigger paths and code-semantic evidence chains**.

**Three core design principles:**
- **🏗️ Real project-level evaluation units** — every sample is bound to a specific vulnerable commit of a real repository, evaluating an agent's ability to discover and locate vulnerabilities inside real multi-file, multi-module engineering projects.
- **🧠 Comprehensive vulnerability-type coverage** — the benchmark covers both business-logic defects that demand cross-module code-semantic reasoning (e.g., authorization bypass, broken authentication) and traditional security flaws (e.g., injection, path traversal), providing a comprehensive assessment of an agent's ability to discover diverse vulnerability classes.
- **✅ Verifiable vulnerability paths** — each sample ships with a human-reviewed **reachable entry point** (`entry_point`), **critical operation** (`critical_operation`), and **cross-module reasoning chain** (`trace`), enabling reproducible, explainable, and deterministic evaluation.

---

## 📢 What's New
- **2026-06-26** — 🔧 v0.1.4 data refresh: human-audited entries grew from **350 → 393 / 408 (96.3 %)**, covering **178 / 184 advisories (96.7 %)**. This release updates only human-audit status flags; row counts, schema, `desc` coverage, and vulnerability-type distribution are unchanged.
- **2026-06-18** — 🔧 v0.1.3 data refresh: human-audited entries grew from **274 → 350 / 408 (85.8 %)**, covering **163 / 184 advisories (88.6 %)**. In addition, a `desc` field was added to the `entry_point` / `critical_operation` / `trace` nodes of 400 entries, giving a natural-language explanation of each node's role in the vulnerability chain.
- **2026-05-31** — 🔧 v0.1.2 data refresh: human-audited entries grew from **113 → 274 / 408 (67.2 %)**, covering **137 / 184 advisories (74.5 %)**. Additionally, `entry_point` / `critical_operation` / `trace` annotations were refined on 80 entries for improved accuracy.
- **2026-05-17** — 🔧 v0.1.1 data refresh: added a `verify` field on every entry to mark human-audit status; **113 / 408 entries** (covering **61 / 184 advisories**) are now human-verified. Selected `entry_point` / `critical_operation` / `trace` values were also refined.
- **2026-05-15** — 🎉 VulnGym v0.1.0 officially open-sourced!



## Table of Contents

- [🔍 Why VulnGym](#-why-vulngym)
- [✨ Dataset overview](#-dataset-overview)
- [📈 Baseline evaluation results](#-baseline-evaluation-results)
- [📦 Repository layout](#-repository-layout)
- [🚀 Quick start](#-quick-start)
- [📊 Evaluating your tool](#-evaluating-your-tool)
- [📖 Citation](#-citation)
- [🤝 Contribution Guide](#-contribution-guide)
- [🙏 Acknowledgements](#-acknowledgements)
- [📄 License](#-license)

---

## 🔍 Why VulnGym

Existing vulnerability benchmarks have the following limitations when
evaluating the real-world vulnerability-hunting capabilities of AI agents:

| Limitation | Manifestation |
|---|---|
| **Insufficient evaluation granularity** | Most benchmarks use functions or diff snippets as the evaluation unit, failing to reflect an agent's ability to locate vulnerabilities within complete engineering projects |
| **Narrow vulnerability types** | Over-emphasis on pattern-matchable CWE flaws such as SQL injection and buffer overflow, with little coverage of categories requiring deep contextual reasoning |
| **Coarse-grained ground truth** | Typically binary labels (vulnerable / not vulnerable) or patch diffs, unable to precisely verify whether the agent locates the correct entry point and defect site |


## ✨ Dataset overview

This is the **v0.1.4 release** of VulnGym. Data is provided
as two JSONL files under the `data/` directory:

- `reports.jsonl` — aggregated records at the GitHub Advisory granularity
- `entries.jsonl` — annotated records at the reachable entry point granularity

Each record contains `repo_url` and `commit`, allowing you to check out the
full vulnerable source tree for the corresponding version.

### Data scale

| Metric | Value |
|---|---|
| Advisories (reports) | **184** |
| Reachable entry points (entries) | **408** |
| Distinct projects | 38 |
| Distinct repositories | 23 |
| Human-audited entries (`verify = 1`) | **393 / 408 (96.3 %)** |
| Human-audited advisories (≥ 1 verified entry) | **178 / 184 (96.7 %)** |

### Human audit status

Starting in v0.1.1, every row in `entries.jsonl` carries a `verify` field
(`int`, `0` or `1`):

- `verify == 1` — the entry's `entry_point`, `critical_operation`, and
  `trace` have been reviewed and confirmed by a human annotator. These
  rows form a high-confidence ground-truth subset and are recommended
  for strict, reproducible benchmarking.
- `verify == 0` — automatically annotated; not yet human-confirmed.
  Useful for scale and recall studies, but values may still be refined
  in future releases.

Of the **184** advisories, **174** have all of their entries verified and
**4** are partially verified, for a total of **178** advisories with at
least one human-audited entry. Future releases will continue to expand
the verified subset.

### Vulnerability type distribution

Every entry carries a two-level classification: `vuln_category_l1`
(coarse type) and `vuln_category_l2` (fine-grained sub-type). **71.2 %** of
advisories are business-logic vulnerabilities, classified with a
**12-class + 1 fallback** taxonomy (see below). The remaining 28.8 %
cover traditional vulnerability types. Full data model and field
definitions are in [`SCHEMA.md`](SCHEMA.md).

The initial release (v0.1.0) draws primarily from recent high-star open-source projects and focuses on frequently occurring business-logic vulnerabilities; future releases will continue expanding vulnerability categories and project coverage.

> Note: one advisory may map to multiple entries — the counts below
> are by **advisory (vulnerability)**, not by entry.

**Business-logic advisories (131 / 184, 71.2 %) — `vuln_category_l2` breakdown:**

| Sub-category | Advisories | % of BL |
|---|---|---|
| BL-AUTHZ-BROKEN — broken authorization logic | 31 | 23.7 % |
| BL-AUTHZ-MISSING — missing authorization | 23 | 17.6 % |
| BL-AGENT-CAPABILITY — AI / Agent capability boundary bypass | 20 | 15.3 % |
| BL-PRIV-ESC — privilege escalation | 13 | 9.9 % |
| BL-AUTH-BYPASS — authentication bypass | 11 | 8.4 % |

<details>
<summary>7 more sub-categories (33 advisories, 25.2 % of BL)</summary>

| Sub-category | Advisories | % of BL |
|---|---|---|
| BL-ORIGIN-INTEGRITY — origin / signature / integrity check missing | 8 | 6.1 % |
| BL-WORKFLOW-VIOLATION — workflow / state-machine violation | 7 | 5.3 % |
| BL-INSECURE-DEFAULT — insecure default configuration | 6 | 4.6 % |
| BL-RACE-LOGIC — business-layer race condition | 4 | 3.1 % |
| BL-MULTI-TENANT — multi-tenant / isolation failure | 3 | 2.3 % |
| BL-MASS-ASSIGNMENT — mass assignment / parameter pollution | 3 | 2.3 % |
| BL-TRUST-BOUNDARY — implicit trust in internal input | 2 | 1.5 % |

</details>

<br>

**Traditional vulnerability advisories (53 / 184, 28.8 %) — top `vuln_category_l1`:**

| Category | Advisories | % of Trad. |
|---|---|---|
| Code Injection | 12 | 22.6 % |
| Path Traversal / File ops | 9 | 17.0 % |
| Command Injection | 8 | 15.1 % |
| XSS | 5 | 9.4 % |
| Sandbox Escape | 5 | 9.4 % |

<details>
<summary>4 more categories (14 advisories, 26.4 % of Trad.)</summary>

| Category | Advisories | % of Trad. |
|---|---|---|
| SSRF | 4 | 7.5 % |
| Authentication Bypass | 3 | 5.7 % |
| Deserialization | 2 | 3.8 % |
| Other (Template Injection, RCE, Supply Chain, etc.) | 5 | 9.4 % |

</details>

> Future releases will continue expanding vulnerability categories and project coverage.



## 📈 Baseline evaluation results

> 🚧 **Coming soon** — We are systematically evaluating mainstream tools and AI agents. Results will be published alongside the technical report.


## 📦 Repository layout

```
VulnGym/
├── README.md                    # English version
├── README_zh.md                 # 中文版
├── SCHEMA.md                    # field reference & validation invariants
├── CHANGELOG.md
├── CITATION.cff
├── LICENSE                      # CC-BY-4.0
├── data/
│   ├── reports.jsonl            # 184 rows — one GitHub Advisory per row
│   └── entries.jsonl            # 408 rows — one entry point per row, with human-audit flag (verify)
├── schemas/                      # strict Entry / T1 validation / evidence contracts
├── vulngym_agent/               # experimental B-v2 automation foundation
├── docs/                         # field dictionary, taxonomy, and B-v2 design
├── tests/                        # standard-library regression tests
└── examples/                     # loaders and evaluation utilities
```

---

## 🚀 Quick start

```bash
git clone https://github.com/Tencent/VulnGym.git
cd VulnGym
python3 examples/load_dataset.py
```

Or load directly in Python:

```python
import json
with open("data/entries.jsonl", encoding="utf-8") as f:
    entries = [json.loads(line) for line in f if line.strip()]

xss = [e for e in entries if e["vuln_category_l1"] == "XSS"]
print(len(xss), "XSS entries")
print(xss[0]["entry_point"], "→", xss[0]["critical_operation"])

# Restrict to the human-audited high-confidence subset
verified = [e for e in entries if e["verify"] == 1]
print(len(verified), "human-audited entries")
```

Pandas:

```python
import pandas as pd
reports = pd.read_json("data/reports.jsonl", lines=True)
entries = pd.read_json("data/entries.jsonl", lines=True)
```

HuggingFace `datasets`:

VulnGym is also published on the HuggingFace Hub: [tencent/VulnGym](https://huggingface.co/datasets/tencent/VulnGym).

```python
from datasets import load_dataset

# Load directly from the HuggingFace Hub
ds = load_dataset("tencent/VulnGym")

# Or load from local JSONL files
ds = load_dataset("json", data_files={
    "reports": "data/reports.jsonl",
    "entries": "data/entries.jsonl",
})
```

### Experimental B-v2 deterministic T1 gate and controlled T2 producer

The B-v2 tools require Python 3.10 or newer. For a reproducible test
environment, install `requirements-dev.txt` and run the standard-library test
suite:

```bash
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
```

The repository includes an executable deterministic T1 slice of the T1 × T2
automation design. It validates JSONL rows independently, safely reads bounded
local advisory/reference/patch packages, reads immutable Git objects without
checkout, checks GHSA/CVE IDs, parent/ancestry facts, exact paths, and code
within the ±5-line tolerance, parses bounded unified diffs, derives conservative
Sink/Guard review candidates, and searches an explicit source-file allow-list
for route/RPC/CLI/handler/export entry clues.

The controlled production slice is available as Python APIs under
`vulngym_agent.agents` and `vulngym_agent.orchestrator`. `T2TaskInputV1` is a
strict, versioned, path-free task contract. An orchestrator-owned
`ProducerExecutionContext`, composed by `LocalT2ContextFactory`, binds it to
trusted local package/repository roots, a fixed tool registry, model backend,
and per-attempt budget. `LocalStructuredT2Producer` can generate a candidate
offline from real local Git objects and can perform supported, narrowly scoped
repairs. It emits an explicit defer instead of a partial Entry when evidence is
ambiguous, a required capability is unavailable, or a budget/contract check
fails.

`RepairPlan` is fail-closed: field-specific tool permissions may be narrowed,
but required checks cannot be removed, and an empty tool allow-list means
deny-all. Repair may only apply a T1-provided `suggested_fix` to an authorized
field while preserving locked fields and task identity. The current repair
path supports narrowly constrained title/category changes while executing its
available task, advisory, and Schema checks; its semantic choice remains
untrusted and is not a final T1 judgment. Plans that require dedicated
source-location, patch-region, ancestry, or trace-continuity verifiers defer;
those full-field verifiers are not complete yet.

The `ClosedLoopOrchestrator` works with both deterministic fakes and the real
producer interface. It creates a fresh T1 validator per round, permits at most
two narrowly authorized repairs, closes tool/model records against budget
events, and routes uncertainty, regressions, budget exhaustion, no-progress,
and sidecar conflicts to explicit terminal states. Code, fixed policies, and
local runtime configuration are trusted; model output and all task/evidence
data are untrusted. Canonical digests, hash chains, and unsigned JSON
transcripts establish internal closure and binding only—they are not digital
signatures and do not establish the external truth of a repository, advisory,
or model conclusion.

The offline closed-loop batch entry point and its atomic replay-artifact writer
are now implemented. They consume one strict `RunTask` object per physical
JSONL line, run T2 followed by a fresh T1 for every validation round, and only
put finalized entries closed by a `correct` T1 report in `entries.jsonl`.

The following is the exact shape of one `tasks.jsonl` line (package paths are
relative POSIX paths under the trusted package root; no local root belongs in a
task):

```json
{"task_id":"task:ghsa-w7xj","report_id":"GHSA-W7XJ-8FX7-WFCH","entry_id":"entry-00057","inputs":{"contract_version":1,"input_line":1,"repo_url":"https://github.com/open-webui/open-webui","package":{"advisory":"advisories/GHSA-W7XJ-8FX7-WFCH.json","references":[],"patches":["patches/GHSA-W7XJ-8FX7-WFCH.diff"]},"hints":{"project":"open-webui","fix_commits":[],"source_paths":["src/lib/components/common/RichTextInput.svelte"],"entry_symbols":[],"critical_mode":"auto"}}}
```

`inputs.input_line` must equal the physical line number. The trusted repository
map is a separate strict JSON document and uses canonical GitHub URLs plus
absolute local roots:

```json
{"contract_version":1,"repositories":[{"repo_url":"https://github.com/open-webui/open-webui","path":"/srv/vulngym/repos/open-webui"}]}
```

The current CLI deliberately has no online model adapter. It uses a bounded,
request-free exact-request fixture as its offline backend:

```json
{"contract_version":2,"backend_id":"exact-replay","model_id":"offline-v1","responses":[{"task_id":"task:ghsa-w7xj","attempt":0,"policy_scope":"t2.initial","stage":"plan","model_call_id":"MODEL-example-plan","backend_id":"exact-replay","model_id":"offline-v1","request_sha256":"<64-lower-case-hex>","status":"success","response":{"stage-specific":"structured result"},"error_code":null}]}
```

The angle-bracket value above is documentation notation. A real response
record discretely binds every immutable `ModelRequest` identity field:
task, attempt, policy scope, stage, call ID, backend ID, model ID, and the
64-character lower-case request digest. Lookup uses that collision-free field
tuple directly; a caller-supplied or delimiter-flattened operation string
cannot substitute for the individual checks. Each identity is registered and consumed exactly
once, so missing, reused, or unused responses abort publication. The fixture
contains no prompt or request payload and is test/reproduction input, **not**
benchmark gold or an independent T1 judgment. Hidden acceptance gold must stay
physically outside the task, fixture, package, and repository roots and must
never be used to prepare model responses.

With those inputs prepared, the minimal batch command is:

```bash
python -m vulngym_agent.closed_loop_cli \
  --tasks tasks.jsonl \
  --replay-responses replay-responses.json \
  --repo-map repo-map.json \
  --package-root /srv/vulngym/packages \
  --output-dir /srv/vulngym/runs/run-001
```

The output parent must already exist and `--output-dir` itself must not exist
or overlap any task, fixture, map, package, or repository input. Exit status is
`0` for a clean batch (`manual_review` is allowed by default), `1` for row/task
failures or, with `--require-all-finalized`, any manual-review outcome, and `2`
for fatal configuration/I/O, total task-byte overflow, or exact-replay closure
failure. Input defaults are 1 MiB per JSONL line, 64 MiB for the complete task
file, and 10,000 records (`--max-input-line-bytes`, `--max-task-bytes`, and
`--max-records`); hard ceilings are 32 MiB, 1 GiB, and 100,000 respectively.
Replay fixtures separately default to 16 MiB and 50,000 responses.
If `--max-records` truncates a batch while fixtures for later records remain,
those unused fixtures fail exact closure and the entire directory is not
published.

One staging transaction publishes `entries.jsonl`, `validation.jsonl`, the
sidecars `states.jsonl`, `candidates.jsonl`, `validations.jsonl`,
`evidence.jsonl`, `tool_calls.jsonl`, `model_calls.jsonl`,
`repair_history.jsonl`, `deferred.jsonl`, and `errors.jsonl`, plus
`run_manifest.jsonl`. `validation.jsonl` is the formal report stream;
`validations.jsonl` is the attempt-linked replay sidecar. Read or verify the
closed bundle without invoking T1, T2, Git, or a model:

```python
from vulngym_agent.orchestrator import (
    read_closed_loop_artifacts,
    verify_closed_loop_artifacts,
)

bundle = read_closed_loop_artifacts("/srv/vulngym/runs/run-001")
manifest = verify_closed_loop_artifacts("/srv/vulngym/runs/run-001")
print(bundle.manifest.dataset_sha256, manifest.entry_count)
```

Artifacts intentionally retain bounded, public or otherwise cleared Evidence
snippets and the Schema-required Entry code snippets. Keep bundles in the
private repository or another controlled directory. They never persist raw
model prompts/responses, producer assumptions, exception text, or configured
local roots; model-call sidecars contain only bound metadata/digests, and T1
does not read them. Canonical digests detect corruption and close references,
but are unsigned and do not authenticate external truth.

#### Pinned 50/20 benchmark harness (phases A/B)

The public-data contract and replay-to-finding projection harness are now
implemented. Keep the benchmark bundle outside this implementation repository,
mount it read-only on the trusted harness host, and pass that external root via
`--benchmark-root`. The runtime profile is fixed to `vulngym-50-20-v1`, source
revision `cd69f7e163e08485ab5496115ae03439cda6e27e`, and public-manifest
SHA-256
`d4ef4a663a30a39d2ccd89dc89f70d19a06686ae86179c537cd5139b8ff00a73`.
The reader does not discover the bundle: it opens only the pinned manifest,
record schema, manifest schema, and public train/test JSONL files. A modified
or substituted profile fails closed.

```bash
# Validate the complete pinned public profile and print a count-only summary.
python -m vulngym_agent.benchmark_cli validate \
  --benchmark-root /srv/vulngym/benchmark-public

# Export answer-free snapshot tasks; the new output directory receives
# tasks.jsonl and manifest.json.
python -m vulngym_agent.benchmark_cli export-tasks \
  --benchmark-root /srv/vulngym/benchmark-public \
  --split test \
  --output-dir /srv/vulngym/exports/test-tasks

# Verify every indexed replay bundle, project formal Entries to findings, and
# run the aggregate-only public-training oracle.
python -m vulngym_agent.benchmark_cli project-train \
  --benchmark-root /srv/vulngym/benchmark-public \
  --artifact-root /srv/vulngym/replays/train \
  --bundle-index /srv/vulngym/attestations/train-index.json \
  --bundle-index-sha256 <64-lower-case-index-file-sha256> \
  --output-dir /srv/vulngym/projections/train

# Produce a blind-test submission without loading public training gold or
# invoking a scoring oracle.
python -m vulngym_agent.benchmark_cli project-test \
  --benchmark-root /srv/vulngym/benchmark-public \
  --artifact-root /srv/vulngym/replays/test \
  --bundle-index /srv/vulngym/attestations/test-index.json \
  --bundle-index-sha256 <64-lower-case-index-file-sha256> \
  --output-dir /srv/vulngym/projections/test
```

The angle-bracket digest is documentation notation; a real projection must
receive the lower-case SHA-256 of the exact index bytes through a trusted
channel. The index is strict JSON with no additional keys and has this shape:

```json
{"bundles":[{"dataset_sha256":"<64-lower-case-replay-dataset-sha256>","task_id":"VG-TEST-<20-UPPER-HEX>"}],"contract_version":1,"manifest_sha256":"d4ef4a663a30a39d2ccd89dc89f70d19a06686ae86179c537cd5139b8ff00a73","profile_id":"vulngym-50-20-v1","split":"test"}
```

It must contain exactly one entry for every task in the selected split, with
no missing, extra, or repeated task IDs and no repeated dataset digests. Each
`dataset_sha256` binds the corresponding fully verified closed-loop replay
directory under `<artifact-root>/<task_id>`. The index-file digest and replay
dataset digests detect substitution or corruption relative to values supplied
by the trusted evaluator; they do **not** prove that a source tree, fixture, or
model conclusion is authentic.

Both projection commands publish `findings.jsonl`, `task_results.jsonl`, and
`manifest.json` in one no-overwrite transaction. `project-train` additionally
publishes `aggregate.json`; the training oracle exposes totals and recall only,
never task/advisory/Entry identities or per-item matches. `project-test` does
not read the public training file, does not call the oracle, and does not
publish a score or `aggregate.json`. Projection emits at most 64 findings per
task by default; `--top-k` has a hard maximum of 256. The fixed public-training
matcher uses the official inclusive line tolerance of 5.

Phases A/B provide strict public contracts, answer-free task export, replay
verification, bounded multi-finding projection, and the train-only aggregate
oracle. Phase C, described below, now closes the source-delivery boundary. It
does **not** make the current advisory/fix-anchored
`LocalStructuredT2Producer` a source-only multi-finding producer. Phase D (that
producer plus an independent semantic T1) and phase E (the isolated 50/20 run)
remain pending, as do the online-model backend and full-field required-check
verifiers.

#### Sealed source-snapshot preparation (phase C)

`python -m vulngym_agent.snapshot_cli` now prepares and independently verifies
authenticated, source-only snapshot batches. A trusted preparer opens the full
local Git repository, resolves each task's exact commit and root tree, and
materializes only that commit's regular source files under
`bundles/<task_id>/tree`. The published tree has no `.git` directory or other
history surface. Symlinks, Gitlinks/submodules, LFS pointers, unsafe or
colliding paths, empty directories, and unsupported Git storage arrangements
fail closed.

Each task's canonical manifest and HMAC bind the task ID, exact repository URL
and commit, root-tree object ID, snapshot policy, file modes, and every file's
Git blob object ID, byte length, and SHA-256. The outer batch manifest also
binds the public task-export manifest digest, exact `tasks.jsonl` digest,
source-map digest, all task snapshot manifests/content roots, and aggregate
counts; the HMAC envelope separately binds its key ID. HMAC here is an
integrity mechanism inside the trusted evaluator domain. It is not a public
provenance signature and cannot establish who published a repository or
whether an external source is authentic.

The preparer requires trusted digest pins for all discovery inputs. The
source-map is strict canonical JSON whose sorted `sources` array must cover the
task export exactly by `(repo_url, commit)`, with neither missing nor extra
repositories:

```json
{"kind":"sealed_snapshot_source_map","profile_id":"vulngym-50-20-v1","public_manifest_sha256":"<public-manifest-sha256>","schema_version":"1.0.0","sources":[{"commit":"<40-lower-case-hex>","repo_root":"/srv/vulngym/repos/project","repo_url":"https://github.com/owner/project"}],"tasks_sha256":"<tasks-jsonl-sha256>"}
```

```bash
# Prepare every task in one private staging area, verify every task, bind the
# batch, verify it again, and publish the complete directory once.
python -m vulngym_agent.snapshot_cli prepare \
  --task-export-dir /srv/vulngym/exports/test-tasks \
  --expected-tasks-sha256 <tasks-jsonl-sha256> \
  --expected-public-manifest-sha256 <public-manifest-sha256> \
  --source-map /srv/vulngym/config/source-map.json \
  --expected-source-map-sha256 <source-map-file-sha256> \
  --output-dir /srv/vulngym/sealed/test \
  --key-file /srv/vulngym/secrets/snapshot-hmac.key \
  --key-id evaluator-snapshot-v1

# Authenticate the outer manifest and deeply re-verify every task bundle.
python -m vulngym_agent.snapshot_cli verify-batch \
  --sealed-root /srv/vulngym/sealed/test \
  --expected-manifest-sha256 <sealed-batch-manifest-sha256> \
  --key-file /srv/vulngym/secrets/snapshot-hmac.key \
  --expected-key-id evaluator-snapshot-v1
```

Preparation is one no-replace batch transaction: no official output appears
until all task trees and both verification passes close. Fixed aggregate caps
are 100 tasks, 1,000,000 files, 1,000,000 total path nodes, and 16 GiB of file
content. The no-replace `renameat2` operation on Linux and the handle-anchored
directory rename on Windows are publication commit points. These are the two
supported publication platforms; other POSIX systems fail closed rather than
falling back to a non-atomic rename. If a post-commit
identity or durability check fails, the command reports publication as
uncertain; callers must treat the destination as possibly committed and verify
the exact expected manifest rather than attempting path-name-based cleanup.

The HMAC key, source repositories, task-export/control material, and each
bundle's `control/` directory stay on the trusted evaluator side. An agent gets
only one `tree/`, mounted read-only, plus its one answer-free task and a bounded
output location. Its sandbox must not expose the key, control data, source Git
repository, another task tree, benchmark repository, evaluation logs, scoring
material, or network access. Phase C proves the delivered bytes and their
binding to the preparer's selected Git objects; it does not perform source-only
finding discovery or semantic validation.

For the eventual blind run, scoring truth must remain physically isolated in
separate evaluator storage and must never be used to prepare tasks, fixtures,
or model responses. Each producer sandbox must be offline and receive only one
answer-free task, its sealed source tree, and a bounded output location. Do not
mount the benchmark repository, the training split, raw data/generator inputs,
evaluation logs, or scoring material into that sandbox. The trusted evaluator
may validate and project outputs after the producer exits; this repository does
not yet claim that the 50/20 acceptance has passed.

The deterministic T1 CLI writes separate validation, evidence, and
run-manifest files:

```bash
python -m vulngym_agent data/entries.jsonl

# Inspect every row against one locally cloned target repository:
python -m vulngym_agent candidates.jsonl --repo-root /path/to/target-repo

# Rows may use {"package": {...}, "entry": {...}}; paths are relative to this root:
python -m vulngym_agent packaged-candidates.jsonl \
  --package-root /path/to/local-evidence \
  --repo-map repos.json
```

For multi-repository batches, pass `--repo-map` with a JSON object whose keys
are exact `repo_url` values and whose values are local repository roots
(relative paths are resolved from the map file). The
default outputs are `outputs/validation.jsonl`, `artifacts/evidence.jsonl`, and
`artifacts/run_manifest.jsonl`. A wrapper package requires `advisory` and may
declare `references` / `patches` as relative POSIX paths. It cannot declare a
repository path: the Entry's exact `repo_url` remains the sole repository-map
key. Per-file/per-package/declared-file limits default to 8 MiB/32 MiB/64 and
are configurable. JSONL lines, records, and trace nodes default to 1 MiB,
10,000, and 64; hard limits prevent CLI overrides from making these inputs
unbounded.
This slice can reject advisory-ID mismatches and a known fix commit submitted as
the vulnerable commit; ancestry or source existence alone deliberately remains
`uncertain` rather than being presented as vulnerability-semantic proof. Patch
guards and removed dangerous calls are lexical review clues only, and entry
search never claims runtime reachability. See the
[B-v2 architecture](docs/b_v2_architecture.md),
[field dictionary](docs/field_dictionary.md), and
[error taxonomy](docs/error_taxonomy.md).

Repository mappings must point to a normal clone or bare repository root.
Linked-worktree/submodule gitfiles, common directories, alternate object
databases, and `info/grafts` history overrides are rejected so evidence reads
cannot escape the authorized root or forge ancestry.
Commit-graph and replace-object acceleration are disabled for topology facts.
All three output paths must stay outside mapped target repositories.
Evidence-package paths also reject absolute/drive/UNC paths, `..`, backslashes,
symlinks, junctions/reparse points, and duplicate declarations. Output paths
must remain outside the package root as well. Every path component is checked
before and after opening; supported POSIX systems use directory handles with
no-follow traversal, while Windows verifies the opened handle's final path.


## 📊 Evaluating your tool

Write your tool's findings to a JSONL file (one finding per line) and run:

```bash
python3 examples/evaluate.py path/to/your_findings.jsonl -v
```

Each finding must carry at least `repo_url`, `commit`, `entry_point`
(reachable entry point), and `critical_operation` (core defect location).
`trace` (cross-module reasoning chain) is optional and ignored by the
matcher. See `examples/example_result.jsonl` for a working sample.

The script reports two metrics:

- **Advisory-level recall** (primary) — `covered_advisories /
  usable_advisories`. An advisory is covered if **at least one** of its
  entries is matched.
- **Entry-level recall** (secondary) — `matched_entries / usable_entries`.

**Default matching policy**

| Aspect | Default |
|---|---|
| Path match | normalized, exact |
| Line tolerance | inclusive span distance `≤ 5` on entry_point **and** critical_operation; reported ranges are width-bounded to the ground-truth span plus tolerance on both sides |
| Direction | strict (entry_point-to-entry_point, critical_operation-to-critical_operation) |
| Invalid ground-truth line | excluded from numerator and denominator; includes the retired `line == 0` sentinel in older/custom data |

All policies are documented and configurable via CLI arguments
(`--line-tolerance`, etc.).

> **Note:** The current evaluator **only computes recall / coverage** and
> cannot penalize over-reporting. The resulting numbers should be
> interpreted as coverage metrics, not a full precision-aware benchmark.


## 📖 Citation

> 📚 **A companion paper is in preparation.** Until it is released, please cite VulnGym using the dataset entry below; we will update this section once the paper is publicly available.

```bibtex
@misc{vulngym2026,
  title        = {VulnGym: A Real-World, Project-Level Vulnerability Benchmark
                  for White-Box Vulnerability-Hunting Agents},
  author       = {{Tencent Wukong Code Security Team and contributors}},
  year         = {2026},
  version      = {0.1.4},
  howpublished = {\url{https://github.com/Tencent/VulnGym}},
  note         = {Dataset. A companion paper is in preparation; please check
                  the repository for the latest citation.}
}
```

Once the paper is public, the entry below will be filled in and should be preferred:

```bibtex
@inproceedings{vulngym2026paper,
  title     = {TBA — A companion paper for VulnGym is in preparation.},
  author    = {{To be announced}},
  year      = {TBA},
  note      = {Placeholder; will be replaced once the paper is publicly available.}
}
```

See `CITATION.cff` for the machine-readable form.

---

## 🤝 Contribution Guide

VulnGym aims to be an **open, reproducible, and continuously evolving**
community benchmark. Contributions from both academia and industry are
warmly welcomed:

- 🧠 **Dataset contributions** — new advisories, additional reachable
  entry points for existing advisories, corrections to `entry_point` /
  `critical_operation` / `trace`.
- 🔧 **Evaluator improvements** — precision / F1, per-category
  breakdowns, statistical significance (bootstrap CI), alternative
  matching policies.
- 📊 **Evaluation result submissions** — submit your tool's evaluation
  results via PR to be included in the baseline comparison.
- 💬 **Discussions & feedback** — file an
  [Issue](https://github.com/Tencent/VulnGym/issues) or start a
  [Discussion](https://github.com/Tencent/VulnGym/discussions).

Please read `SCHEMA.md` before proposing data changes — all invariants
listed there are enforced at release time.

---

## 🙏 Acknowledgements

VulnGym is jointly built by the **Tencent Wukong Security Team**
together with the following academic partners (listed in no particular
order, final order TBD):
- ARISE Lab, The Chinese University of Hong Kong
- Systems Software & Security Lab, Fudan University
- JC STEM Lab of Intelligent Cybersecurity, The University of Hong Kong
- Narwhal-Lab, Peking University
- Network Threat Analysis Lab, Institute of Information Engineering, Chinese Academy of Sciences

Many thanks to all partners for their outstanding contributions to
VulnGym.

---

## 📄 License

The dataset is released under **CC-BY-4.0** — see [`LICENSE`](LICENSE).
You may use it for commercial and academic purposes with attribution.
Source code paths and commit hashes referenced in `entry_point` /
`critical_operation` / `trace` fields belong to their respective upstream
projects under their original licenses; consult the referenced
repositories before reusing any quoted code fragment.
