# Issue and commit traceability

This document records the private collaboration workflow for the VulnGym B-v2
T2-to-T1 automation project. It implements the submission requirement for an
auditable modification history without treating commit count as evidence that
the final 20+50 gate has run.

## Repository boundary

- Issue tracker and collaboration repository:
  `Qiyuanqiii/VulnGym-bv2-private`.
- Public `origin` and `upstream` are read-only inputs for this project. They are
  not authorized push destinations.
- Test gold, evaluator keys, target repositories, sealed source trees, host
  absolute paths, and sensitive runtime logs must not be committed.
- Runtime work records only safe manifests, receipts, counts, and digests.

## Native Issue hierarchy

GitHub parent/sub-issue relationships are authoritative. Markdown checklists
may summarize progress, but they do not replace the native relationship graph.

| Level | Issue | Scope |
| --- | --- | --- |
| Epic | [#7](https://github.com/Qiyuanqiii/VulnGym-bv2-private/issues/7) | Complete the reproducible 50+20 T2-to-T1 acceptance loop |
| Phase | [#8](https://github.com/Qiyuanqiii/VulnGym-bv2-private/issues/8) | Governance and traceability |
| Phase | [#9](https://github.com/Qiyuanqiii/VulnGym-bv2-private/issues/9) | Stabilize and review the current control-plane diff |
| Phase | [#10](https://github.com/Qiyuanqiii/VulnGym-bv2-private/issues/10) | Fixed public benchmark and T2 data plane |
| Phase | [#11](https://github.com/Qiyuanqiii/VulnGym-bv2-private/issues/11) | Seal 70 source snapshots |
| Phase | [#12](https://github.com/Qiyuanqiii/VulnGym-bv2-private/issues/12) | Produce and review 70 D2/D3 replay pairs |
| Phase | [#13](https://github.com/Qiyuanqiii/VulnGym-bv2-private/issues/13) | Run the fixed OCI and native Linux gates |
| Phase | [#14](https://github.com/Qiyuanqiii/VulnGym-bv2-private/issues/14) | External validation and final submission |

Historical number ranges remain stable for audit purposes:

- historical completed capabilities: #15-#28;
- current engineering stabilization: #29-#36;
- reproducible public 50/20 dataset: #37;
- per-repository source sealing and aggregate verification: #38-#60;
- fixed replay batches and aggregate closure: #61-#90;
- native Linux runtime gates: #91-#96;
- external validation and submission: #97-#102;
- governance: #103-#106.

The active tracker was consolidated after the initial exhaustive breakdown.
There are now 12 open Issues; the repository- and batch-level records remain
closed, archived sub-issues under their aggregate owner:

| Active layer | Issues |
| --- | --- |
| Epic | #7 |
| Open phases | #12, #13, #14 |
| Replay aggregate | #90 |
| Native runtime and gates | #91, #92, #94, #95 |
| Evaluation and release | #97, #99, #102 |

Governance #8, engineering #9, benchmark/T2 #10, source phase #11, and source
aggregate #60 are complete. Source details #38-#59 are archived under #60,
replay details #61-#89 under #90, and the superseded engineering leaves are
closed or archived under their completed phase. This keeps the main view
human-readable while retaining the fixed task IDs and earlier acceptance
criteria for audit.

## Dependency direction

For GitHub's native dependency API, `issueId` is the blocked issue and
`blockingIssueId` is its prerequisite. The project uses this direction:

```text
leaf prerequisite -> blocked leaf -> phase -> epic
```

Important chains include:

```text
snapshot/source/replay/runtime hardening
  -> full normal and python -O regression
  -> independent diff review
  -> final OCI rebuild

source 70/70 + replay 70/70 + native host + final image
  -> preflight
  -> test 20/20
  -> train 50/50
  -> independent readback
  -> external scoring and final release
```

The test gate must close before the train gate can start. Source acquisition and
replay authoring may be parallelized where their native blockers allow it.

## Commit policy

1. Create or select the leaf Issue before changing files.
2. Keep commits narrow. Use `Refs #N` for intermediate commits and `Fixes #N`
   only when the Issue acceptance criteria are genuinely complete.
3. Do not compress snapshot-v2, source acquisition, replay authoring, runtime
   preflight, regression, and documentation into one giant commit.
4. A historical capability may be closed only when every cited full SHA is
   reachable in the private repository and the Issue title states its narrow
   scope. Branch-local or uncommitted work is not closure evidence.
5. A closure comment must include:
   - the complete commit SHA or SHAs;
   - exact verification commands and a result summary;
   - required artifact or receipt digests;
   - the reviewer identity or review Issue;
   - any residual limitation.
6. Framework completion never implies that source sealing, replay production,
   native Linux execution, or external scoring has completed.

The completed historical Issue set #15-#28 contains the full commit lists and
explicit scope boundaries. Dataset Issue #37 is backed by commit
`e4d38e3c73e5323b6409c111183cc997856f55df` on the private branch
`codex/issue-37-benchmark-50-20-v1`.

## AI-assisted work record

Issue bodies define the task and acceptance criteria. Commits identify the
implementation. A critic comments on failure paths and adversarial cases, and
an independent reviewer records the reviewed SHA and verification commands.
This Issue-to-commit-to-review chain is the durable AI coding usage record; raw
prompts, credentials, private gold, and sensitive runtime transcripts are not
repository artifacts.

## Install and verify the push guard

Install the tracked hook for this clone or worktree:

```powershell
git config core.hooksPath .githooks
git config --get core.hooksPath
```

The hook permits only `Qiyuanqiii/VulnGym-bv2-private` and rejects public or
unknown destinations. Test both paths without pushing objects:

```powershell
sh .githooks/pre-push private git@github.com:Qiyuanqiii/VulnGym-bv2-private.git
sh .githooks/pre-push origin git@github.com:Qiyuanqiii/VulnGym.git
```

The first command must return zero. The second must return nonzero with a clear
rejection message.
