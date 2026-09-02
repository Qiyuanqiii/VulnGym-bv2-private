# Replay authoring closure receipt runbook

`python -m vulngym_agent.replay_authoring_receipt_cli` closes the provenance
gap between the single-task replay authoring CLI and the 70-task batch-plan
CLI. It only emits canonical, path-free JSON. It does not call a model, score a
finding, accept or use an answer key, or derive approval from a replay
directory.

The three actor IDs are provenance claims rather than digital signatures.
Run the author, critic, and reviewer steps in independently controlled
sessions, retain their semantic and wire SHA-256 pins outside the replay
publication root, and do not reuse one identity across roles.

## 1. Produce an independent closure observation

Run this only after the single-task authoring `finalize` command has published
the task's `d2.json` and `d3.json` pair:

```bash
python -B -m vulngym_agent.replay_authoring_receipt_cli readback \
  --task-file /srv/vulngym/control/tasks/VG-TEST-....json \
  --expected-task-wire-sha256 "${TASK_WIRE_SHA256}" \
  --sealed-bundle-root /srv/vulngym/sealed/VG-TEST-... \
  --published-root /srv/vulngym/replay-publications/test/VG-TEST-... \
  --key-file /srv/vulngym/control/attestation.key \
  --key-id "${KEY_ID}" \
  > /srv/vulngym/control/observations/VG-TEST-....json
```

The reader replays the pair through the production offline closure path. Its
observation binds the task/split, task wire, answer-free public task identity,
D2/D3 semantic and wire digests, run semantic and wire digests, outcome, and
all response/candidate/finding/reviewer counts. Record the observation's
embedded `observation_sha256` and the SHA-256 of the complete file separately.

## 2. Obtain three independent approvals

Each actor reads the same double-pinned observation. Example for the critic:

```bash
python -B -m vulngym_agent.replay_authoring_receipt_cli approve \
  --observation-file /srv/vulngym/control/observations/VG-TEST-....json \
  --expected-observation-sha256 "${OBSERVATION_SHA256}" \
  --expected-observation-wire-sha256 "${OBSERVATION_WIRE_SHA256}" \
  --actor-role critic \
  --actor-id critic-agent-01 \
  > /srv/vulngym/control/approvals/VG-TEST-....critic.json
```

Repeat with roles `author` and `reviewer` under two other actor IDs. Approval
is mechanically unavailable unless the replay is finalized, D2 and D3 are
both non-empty, at least one candidate and finding exist, and no reviewer
verdict is deferred. Retain each approval's embedded `approval_sha256` and
complete-file SHA-256 outside the replay root.

## 3. Rerun and seal the per-task receipt

`seal-receipt` performs a fresh closure readback. Any replay, task, run, count,
or digest change makes all earlier approvals stale and the command fails:

```bash
python -B -m vulngym_agent.replay_authoring_receipt_cli seal-receipt \
  --task-file /srv/vulngym/control/tasks/VG-TEST-....json \
  --expected-task-wire-sha256 "${TASK_WIRE_SHA256}" \
  --sealed-bundle-root /srv/vulngym/sealed/VG-TEST-... \
  --published-root /srv/vulngym/replay-publications/test/VG-TEST-... \
  --key-file /srv/vulngym/control/attestation.key \
  --key-id "${KEY_ID}" \
  --author-approval-file /srv/vulngym/control/approvals/VG-TEST-....author.json \
  --expected-author-approval-sha256 "${AUTHOR_APPROVAL_SHA256}" \
  --expected-author-approval-wire-sha256 "${AUTHOR_APPROVAL_WIRE_SHA256}" \
  --critic-approval-file /srv/vulngym/control/approvals/VG-TEST-....critic.json \
  --expected-critic-approval-sha256 "${CRITIC_APPROVAL_SHA256}" \
  --expected-critic-approval-wire-sha256 "${CRITIC_APPROVAL_WIRE_SHA256}" \
  --reviewer-approval-file /srv/vulngym/control/approvals/VG-TEST-....reviewer.json \
  --expected-reviewer-approval-sha256 "${REVIEWER_APPROVAL_SHA256}" \
  --expected-reviewer-approval-wire-sha256 "${REVIEWER_APPROVAL_WIRE_SHA256}" \
  > /srv/vulngym/control/receipts/VG-TEST-....receipt.json
```

The three approval files must be canonical, double-pinned, role-complete, and
use distinct actor IDs. The receipt embeds no filesystem path.

## 4. Build the external 70-task authoring index

The receipt directory must contain exactly one
`<task_id>.receipt.json` file for each of the 20 test tasks followed by the 50
training tasks. The builder reads no replay directory:

```bash
python -B -m vulngym_agent.replay_authoring_receipt_cli build-index \
  --benchmark-root /srv/vulngym/benchmark \
  --receipt-root /srv/vulngym/control/receipts \
  > /srv/vulngym/control/frozen-authoring-index.json
```

Record the embedded `index_sha256` and SHA-256 of the complete canonical line.
Pass those two external pins to `replay_batch_plan_cli build-split`. The output
schema and digest domain are exactly the existing
`vulngym.replay-authoring-index.v1` contract.
