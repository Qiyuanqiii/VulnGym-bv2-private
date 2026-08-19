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

### Experimental B-v2 deterministic T1 fact gate

The B-v2 tools require Python 3.10 or newer. For a reproducible test
environment, install `requirements-dev.txt` and run the standard-library test
suite:

```bash
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
```

The repository now includes the third executable slice of the T1 × T2
automation design. It validates JSONL rows independently, safely reads bounded
local advisory/reference/patch packages, reads immutable Git objects without
checkout, checks GHSA/CVE IDs, parent/ancestry facts, exact paths, and code
within the ±5-line tolerance, parses bounded unified diffs, derives conservative
Sink/Guard review candidates, and searches an explicit source-file allow-list
for route/RPC/CLI/handler/export entry clues.

The next control-plane slice is also available as a Python API under
`vulngym_agent.orchestrator`: strict `ProductionOutcome` / `RepairPlan` /
`Budget` / `RunState` contracts and a FakeT2-testable
`ClosedLoopOrchestrator`. It creates a fresh T1 validator per round, permits at
most two narrowly authorized repairs, and routes uncertainty, regressions,
budget exhaustion, no-progress, and sidecar conflicts to explicit terminal
states. A real T2 producer and closed-loop batch CLI are not implemented yet.

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
