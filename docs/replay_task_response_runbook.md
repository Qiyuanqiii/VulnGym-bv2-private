# Replay task export and response binding

`vulngym_agent.replay_task_response_cli` is the credential-free bridge into
the existing single-task `replay_authoring_cli`. It performs two narrowly
defined operations and does not call a model or execute a benchmark task.

## 1. Export one authenticated split

The task export directory must be the fixed answer-free public export. The
sealed batch manifest digest, public task digest, public manifest digest, and
attestation key ID are independent operator inputs. The output directory must
not already exist.

```powershell
$env:TEMP = 'D:\VulnGym-bv2-runtime\tmp'
$env:TMP = $env:TEMP

python -B -m vulngym_agent.replay_task_response_cli export-split `
  --task-export-dir D:\VulnGym-bv2-runtime\exports\test `
  --expected-tasks-sha256 <TEST_TASKS_SHA256> `
  --expected-public-manifest-sha256 <PUBLIC_MANIFEST_SHA256> `
  --sealed-batch-root D:\VulnGym-bv2-runtime\sealed\test `
  --expected-batch-manifest-sha256 <TEST_BATCH_MANIFEST_SHA256> `
  --key-file D:\VulnGym-bv2-runtime\keys\test.key `
  --key-id <TEST_KEY_ID> `
  --output-root D:\VulnGym-bv2-runtime\authoring-inputs\test
```

The published layout is fixed:

```text
test/
  index.json
  tasks/
    <task-id>.json
    ...
```

Every task file is one newline-terminated canonical
`DiscoveryTaskInputV1`. `index.json` preserves the public split order and
binds every task filename, `task_id`, `snapshot_id`, and exact wire SHA-256.
It also binds the public task digest and the authenticated sealed-batch
manifest/content/key identity. It contains no source-map path or contents.

Successful stdout is one canonical path-free summary. Retain its
`index_sha256` and `index_wire_sha256` outside the export directory. Those two
values are the external authority for later reads; an index stored only beside
the files it authenticates is not an independent pin.

Verify the complete output before selecting a task:

```powershell
python -B -m vulngym_agent.replay_task_response_cli verify-export `
  --export-root D:\VulnGym-bv2-runtime\authoring-inputs\test `
  --expected-index-sha256 <EXTERNAL_INDEX_SHA256> `
  --expected-index-wire-sha256 <EXTERNAL_INDEX_WIRE_SHA256>
```

After that succeeds, read the selected task's `task_wire_sha256` from the
verified index and pass both the task file and that per-task pin to
`replay_authoring_cli`. Do not derive the pin from an unverified directory
scan.

## 2. Bind one model response

`replay_authoring_cli next-request` produces the sole pending request for the
current D2/D3 prefix. Preserve the exact pending bytes and independently
record their wire SHA-256. The model response body must be a single canonical,
newline-terminated JSON object; independently record its wire SHA-256 as well.

```powershell
python -B -m vulngym_agent.replay_task_response_cli bind-response `
  --pending-file D:\VulnGym-bv2-runtime\authoring\pending.json `
  --expected-pending-wire-sha256 <PENDING_WIRE_SHA256> `
  --response-body-file D:\VulnGym-bv2-runtime\authoring\model-body.json `
  --expected-response-body-wire-sha256 <MODEL_BODY_WIRE_SHA256> `
  --output-root D:\VulnGym-bv2-runtime\authoring\bound-response-001
```

The output directory contains only `response.json`. The envelope is the
production `ReplayAuthoringResponseV1` contract. It binds all of:

- `task_id`, D2/D3 role, and stage;
- request semantic SHA-256;
- one-based occurrence within the role transcript;
- current prefix-config semantic SHA-256;
- canonical response body and its semantic SHA-256.

Successful stdout additionally records the pending wire, response-body wire,
and final envelope wire digests. Verify the envelope under its external pin:

```powershell
python -B -m vulngym_agent.replay_task_response_cli verify-response `
  --response-root D:\VulnGym-bv2-runtime\authoring\bound-response-001 `
  --expected-response-wire-sha256 <EXTERNAL_RESPONSE_WIRE_SHA256>
```

Then append it through the existing prospective replay gate:

```powershell
python -B -m vulngym_agent.replay_authoring_cli respond `
  --task-file D:\VulnGym-bv2-runtime\authoring-inputs\test\tasks\<task-id>.json `
  --expected-task-wire-sha256 <PIN_FROM_VERIFIED_INDEX> `
  --sealed-bundle-root D:\VulnGym-bv2-runtime\sealed\test\bundles\<task-id> `
  --draft-root D:\VulnGym-bv2-runtime\authoring\drafts\<task-id> `
  --key-file D:\VulnGym-bv2-runtime\keys\test.key `
  --key-id <TEST_KEY_ID> `
  --response-file D:\VulnGym-bv2-runtime\authoring\bound-response-001\response.json
```

Replay prevention is a joint property. The binding CLI makes an old envelope
different from a later occurrence/prefix. `replay_authoring_cli respond` then
replays the current prefix prospectively and refuses stale, out-of-order,
unconsumed, or structurally rejected responses before updating the draft.
Creating the same envelope under another output path does not make it valid a
second time after the draft has advanced.

## Failure rules

- Exit `2`: rejected before a publication was confirmed; correct the input.
- Exit `11`: a publication may have committed; retain the directory and
  verify it under the expected external digest before doing anything else.
- Exit `130`: interrupted before a publication was confirmed.
- Existing output roots are never replaced.
- Pre-commit cleanup removes only transaction-created nodes whose filesystem
  identities still match; suspicious replacements are retained.
- The CLI accepts no source-map, provider command, API token, or network
  option.
