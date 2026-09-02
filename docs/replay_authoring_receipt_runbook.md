# Replay authoring receipt v2 runbook

`python -B -m vulngym_agent.replay_authoring_receipt_cli` turns each published
D2/D3 pair into a signed closure receipt and builds the fixed 20-test +
50-train authoring index used by the formal batch gate. It never reads a
private answer, gold file, selection lock, or raw source-map content. Every
output is one canonical, path-free JSON line.

Version 2 closes five independent chains:

1. externally held semantic/wire pins authenticate the public task export;
2. the existing snapshot HMAC key authenticates the complete sealed batch;
3. an Ed25519 readback authority signs the exact production observation;
4. three independently registered Ed25519 actors sign author, critic, and
   reviewer approvals; and
5. a sixth, index-only Ed25519 authority signs the complete 70-task index.

## 1. Provision and pin the public-key trust registry

Provision six independent raw 32-byte Ed25519 private keys with the dedicated
CLI. Private material must remain with its single signing step: readback keys
are loaded only by `readback`, actor keys only by `approve`, and the index key
only by `build-index`. `seal-receipt` and the formal batch reader load no
Ed25519 private key.

Create an owner-only private directory first on POSIX (`umask 077` and
`install -d -m 700 /srv/vulngym/keys`). Then invoke `generate-slot` exactly
once for each fixed purpose/role/key-ID assignment. For example:

```bash
python -B -m vulngym_agent.replay_trust_registry_cli generate-slot \
  --purpose actor-approval \
  --role author \
  --key-id author-2026-01 \
  --private-key-file /srv/vulngym/keys/author-2026-01.ed25519 \
  --registration-file /srv/vulngym/control/author-2026-01.registration.json
```

The command creates both files without replacement. The private file is
exactly 32 raw bytes and its value is never printed. The separate registration
is canonical JSON containing only the public key and its public identity.
Repeat for the six slots below with distinct key IDs and distinct output
paths.

Provisioning exits `2` only when no publication is known to remain. Exit `11`
means a newly created file could not be safely removed, its final identity is
uncertain, or the public success summary could not be delivered after the file
was published: preserve every involved path, inspect it under the expected
public identity, and never retry blindly. Exit `130` means interruption before
a publication was confirmed.

Create one canonical `vulngym.replay-authoring-trust-registry.v2` JSON line
with exactly this order:

```text
actor-approval/author
actor-approval/critic
actor-approval/reviewer
readback-attestation/test
readback-attestation/train
authoring-index/global
```

Each entry contains `purpose`, `role`, `key_id`, canonical base64 of the raw
32-byte public key, and its domain-separated
`replay_ed25519_public_key_fingerprint_v2` value. Key IDs, raw public keys,
and fingerprints must be globally unique, so cross-purpose reuse is rejected.
The registry includes `registry_sha256`, computed by `ReplayTrustRegistryV2`.

Pass the six registration files to `assemble-registry` in exactly the order
shown above. The option is intentionally repeated rather than discovered from
a directory:

```bash
python -B -m vulngym_agent.replay_trust_registry_cli assemble-registry \
  --registry-file /srv/vulngym/control/replay-trust-registry-v2.json \
  --registration-file /srv/vulngym/control/author.registration.json \
  --registration-file /srv/vulngym/control/critic.registration.json \
  --registration-file /srv/vulngym/control/reviewer.registration.json \
  --registration-file /srv/vulngym/control/test-readback.registration.json \
  --registration-file /srv/vulngym/control/train-readback.registration.json \
  --registration-file /srv/vulngym/control/index.registration.json
```

The registry is also created without replacement. Successful stdout contains
only its public semantic/wire pins and the six public fingerprints. Transfer
those pins through the independent operator/final-gate control channel before
using them; a producer must not select its own expected pins. Check a private
key against that pinned registry before releasing it to its signing step:

```bash
python -B -m vulngym_agent.replay_trust_registry_cli verify-slot \
  --purpose actor-approval \
  --role author \
  --key-id author-2026-01 \
  --private-key-file /srv/vulngym/keys/author-2026-01.ed25519 \
  --trust-registry-file /srv/vulngym/control/replay-trust-registry-v2.json \
  --expected-trust-registry-sha256 "${TRUST_REGISTRY_SHA256}" \
  --expected-trust-registry-wire-sha256 "${TRUST_REGISTRY_WIRE_SHA256}"
```

On Windows, Python cannot reliably establish or prove a secure DACL. Before
generation, the operator **must** create a dedicated non-reparse key directory,
disable unwanted inherited ACEs, and grant access only to the intended signing
identity plus explicitly approved recovery principals. Inspect the effective
ACL with `icacls D:\VulnGym\keys` before generation and inspect every generated
key with `icacls D:\VulnGym\keys\*.ed25519` afterward; do not use a key until
that review passes. The CLI still rejects symlinks/junctions/reparse points,
hard-linked or non-regular key files, changed path identities, and existing
destinations, but those checks are not a substitute for the DACL review.

Retain both `registry_sha256` and SHA-256 of the exact registry file in a
separate trusted control channel. Every command receives the same three
arguments:

```text
--trust-registry-file PATH
--expected-trust-registry-sha256 SHA256
--expected-trust-registry-wire-sha256 SHA256
```

The registry path or digests must not be chosen by the replay producer. The
operator/final-gate configuration fixes them independently.

## 2. Sign a production readback

Use the public split export from `replay_task_response_cli export-split` and
retain both its semantic and wire digests outside the export:

```bash
python -B -m vulngym_agent.replay_authoring_receipt_cli readback \
  --task-export-root /srv/vulngym/task-export/test \
  --task-id VG-TEST-... \
  --expected-task-export-index-sha256 "${TEST_EXPORT_SHA256}" \
  --expected-task-export-index-wire-sha256 "${TEST_EXPORT_WIRE_SHA256}" \
  --sealed-batch-root /srv/vulngym/sealed/test \
  --published-root /srv/vulngym/replay-publications/test/VG-TEST-... \
  --snapshot-key-file /srv/vulngym/keys/test-snapshot.hmac \
  --snapshot-key-id "${TEST_SNAPSHOT_KEY_ID}" \
  --expected-snapshot-key-fingerprint "${TEST_SNAPSHOT_KEY_FINGERPRINT}" \
  --trust-registry-file /srv/vulngym/control/replay-trust-registry-v2.json \
  --expected-trust-registry-sha256 "${TRUST_REGISTRY_SHA256}" \
  --expected-trust-registry-wire-sha256 "${TRUST_REGISTRY_WIRE_SHA256}" \
  --readback-private-key-file /srv/vulngym/keys/test-readback.ed25519 \
  > /srv/vulngym/control/observations/VG-TEST-....json
```

The observation binds the exact registry, split export, sealed batch, public
task wire/snapshot identity, D2/D3/run digests, and bounded closure counts.
Retain its embedded `observation_sha256` and whole-file SHA-256 independently.

## 3. Collect three independent approvals

Each actor verifies the pinned registry and signed observation, then loads
only its own raw Ed25519 private key. Example for the critic:

```bash
python -B -m vulngym_agent.replay_authoring_receipt_cli approve \
  --observation-file /srv/vulngym/control/observations/VG-TEST-....json \
  --expected-observation-sha256 "${OBSERVATION_SHA256}" \
  --expected-observation-wire-sha256 "${OBSERVATION_WIRE_SHA256}" \
  --actor-role critic \
  --actor-private-key-file /srv/vulngym/keys/critic.ed25519 \
  --trust-registry-file /srv/vulngym/control/replay-trust-registry-v2.json \
  --expected-trust-registry-sha256 "${TRUST_REGISTRY_SHA256}" \
  --expected-trust-registry-wire-sha256 "${TRUST_REGISTRY_WIRE_SHA256}" \
  > /srv/vulngym/control/approvals/VG-TEST-....critic.json
```

Repeat with the author and reviewer keys. Approval is unavailable unless the
replay is finalized, D2 and D3 are non-empty, at least one candidate and
accepted finding exist, reviewer coverage is complete, and no verdict is
deferred. Retain each approval's semantic and wire pins.

## 4. Freshly read back and seal one receipt

`seal-receipt` takes the same task-export, sealed-batch, published-root,
snapshot-HMAC, and trust-registry arguments as step 2. It additionally takes
the signed observation and all three pinned approvals:

```text
--observation-file PATH
--expected-observation-sha256 SHA256
--expected-observation-wire-sha256 SHA256
--ROLE-approval-file PATH
--expected-ROLE-approval-sha256 SHA256
--expected-ROLE-approval-wire-sha256 SHA256
```

No readback or actor private key is accepted. Sealing verifies all public-key
signatures and performs a fresh production readback. Any source, task,
snapshot, replay, run, count, registry, or signature change rejects the
receipt. Write stdout to exactly `<task_id>.receipt.json`.

## 5. Build the signed 70-task index

The receipt directory must contain exactly 70 private regular files named
`<task_id>.receipt.json`; no extra member is accepted. `build-index` requires
both externally pinned task exports, both snapshot-HMAC fingerprints, the
pinned trust registry, and only the index authority's private key:

```bash
python -B -m vulngym_agent.replay_authoring_receipt_cli build-index \
  --benchmark-root /srv/vulngym/benchmark \
  --receipt-root /srv/vulngym/control/receipts \
  --trust-registry-file /srv/vulngym/control/replay-trust-registry-v2.json \
  --expected-trust-registry-sha256 "${TRUST_REGISTRY_SHA256}" \
  --expected-trust-registry-wire-sha256 "${TRUST_REGISTRY_WIRE_SHA256}" \
  --index-private-key-file /srv/vulngym/keys/index.ed25519 \
  --test-task-export-root /srv/vulngym/task-export/test \
  --expected-test-task-export-index-sha256 "${TEST_EXPORT_SHA256}" \
  --expected-test-task-export-index-wire-sha256 "${TEST_EXPORT_WIRE_SHA256}" \
  --expected-test-snapshot-key-fingerprint "${TEST_SNAPSHOT_KEY_FINGERPRINT}" \
  --train-task-export-root /srv/vulngym/task-export/train \
  --expected-train-task-export-index-sha256 "${TRAIN_EXPORT_SHA256}" \
  --expected-train-task-export-index-wire-sha256 "${TRAIN_EXPORT_WIRE_SHA256}" \
  --expected-train-snapshot-key-fingerprint "${TRAIN_SNAPSHOT_KEY_FINGERPRINT}" \
  > /srv/vulngym/control/frozen-authoring-index-v2.json
```

The builder verifies every observation and actor signature using only the
registry public keys. It pre-opens the exact receipt directory and all 70
members. POSIX uses a directory descriptor and relative no-follow opens;
Windows holds no-delete ancestry handles and rejects reparse points. Identity
guards fail closed on member or ancestry changes, including A-to-B-to-A
pathname swaps.

Retain the index semantic and wire digests outside the replay producer. The
formal reader accepts only `vulngym.replay-authoring-index.v2`, verifies the
independently pinned registry and index signature, and preserves exact
test-then-train order. A v1 index remains available only to the explicit
legacy read-only parser and can never enter `build-split`.
