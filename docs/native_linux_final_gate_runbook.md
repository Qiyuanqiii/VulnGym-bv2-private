# Native Linux 20+50 final-gate runbook

This runbook prepares and operates the mandatory E4 mechanical gate. It does
not claim that the gate has run. A real native-Linux execution establishes
mechanical closure only after it publishes a `closed` receipt, an independent
readback succeeds, and the externally held receipt pins are retained. Dataset
acceptance additionally requires the separately specified trusted-gold quality
threshold.

The preflight command is intentionally read-only with respect to Docker and
the benchmark inputs. It never starts Docker, pulls or builds an image, creates
a container, or writes an evaluation output. It creates only a bounded,
ephemeral Docker CLI configuration below the explicit empty scratch root and
removes it before returning. It statically verifies the blind test inputs
before the training inputs, then uses only Docker
`version`, `info`, `image inspect`, `container ls`, and filtered `image ls`.

## 1. Trusted environment

Use a dedicated x86-64 Linux VM or physical host, not Docker Desktop, WSL,
WSL2, a developer workstation, or a container containing the evaluator.
Provision and freeze the host before loading benchmark material:

- at least 8 logical CPUs and 16 GiB total RAM visible to both the host and the
  Docker daemon, with at least 6 GiB host RAM currently available;
- at least 200 GiB of unique free local storage after filesystem identities are
  de-duplicated;
- an `ext4`, `xfs`, `btrfs`, or `zfs` evaluator filesystem;
- cgroup v2 with the `cpu`, `memory`, and `pids` controllers;
- a fixed Linux kernel, Docker Engine/CLI, containerd, and runc version;
- one daemon reachable only through a canonical local Unix socket whose
  dedicated parent directory is mode `0700`, contains only that socket, and
  whose socket is mode `0600`;
- no other containers, jobs, Docker clients, or users with daemon authority;
- an evaluator account and control/output parents owned by that account with
  mode `0700`; key and operator-assertion files use mode `0600`;
- scoring gold on separate storage that is unavailable to this host.

The fixed automatic floors are 8 host CPUs, 8 daemon CPUs, 16 GiB total host
RAM, 16 GiB total daemon RAM, and 6 GiB currently available host RAM. Storage
requires 100 GiB free on the output filesystem, 64 GiB free on the Docker data
filesystem, 32 GiB free on the scratch filesystem, 100,000 free output inodes,
and at least 200 GiB free in total after grouping output, scratch, and Docker
roles by filesystem identity. If two or three roles share one filesystem, its
free space is counted only once. The source-batch contract permits up to 16
GiB per split, so capacity planning should retain margin beyond those floors.

Use an external host control such as a single-purpose VM lifecycle, protected
systemd unit, hypervisor policy, or physical console procedure to enforce
exclusive access. A process cannot prove that no privileged operator or future
Docker client exists. The preflight therefore requires a separately pinned
operator assertion; it verifies the assertion's bytes and bindings, not the
truth of the real-world statements.

## 2. Filesystem layout

Keep implementation, inputs, controls, secrets, outputs, and scoring material
separate. A representative layout is:

```text
/opt/vulngym/implementation       read-only exact checkout
/srv/vulngym/benchmark            trusted public benchmark view
/srv/vulngym/inputs/test-sealed   0700
/srv/vulngym/inputs/test-replay   0700
/srv/vulngym/inputs/train-sealed  0700
/srv/vulngym/inputs/train-replay  0700
/srv/vulngym/control              0700
/srv/vulngym/control/secrets      0700
/srv/vulngym/scratch              0700, empty before preflight
/srv/vulngym/final-gates          0700, local POSIX filesystem
/srv/vulngym/docker               dedicated Docker data root
```

The implementation root, benchmark root, control root, scratch root, two sealed
roots, two replay roots, and new output must be mutually disjoint. The Docker
data root and canonical Unix socket must not overlap either direction with any
of those roots, including through bind-mount aliases. The preflight binds an
exact `/proc/self/mountinfo` snapshot and maps each path by device, mount root,
and relative path; any mount-table change is fail-closed. The Docker data root
and every ancestor must remain root-owned and not group/world-writable. The
socket's full ancestor chain is identity-bound around every Docker probe and
runtime command. The plan, both keys, and optional operator assertion must be
regular files below the control root; the Docker executable is separately
bound by its absolute path and content digest. The test and train keys must
have different paths, IDs, and bytes. Do not mount the implementation checkout,
benchmark root, the other split, control files, logs, or scoring material into
a worker.

The requested output must not exist. Preflight also refuses a leftover hidden
staging directory for the same output name. Do not delete an unfamiliar
staging directory automatically; investigate and reconcile its identity first.

## 3. Freeze the worker image

The worker `Containerfile` pins its Python base image by registry digest. That
base digest is not the final worker image ID. On the provisioned native-Linux
host, before disabling provisioning network access, check out the exact trusted
commit and build once:

```bash
docker pull python@sha256:00faa2debb87529f9f0764e9491d8ba400a3678976616c3bd7cb193745ac20d1
docker build --pull=false --network=none \
  --file containers/evaluator/Containerfile \
  --iidfile /srv/vulngym/control/worker-image-id \
  --tag vulngym-e3-worker:gate .
```

Read and validate the `sha256:<64 lowercase hex>` value from the owner-only
`worker-image-id` file. Record both the local image ID and an independently
retained image-inspect digest. If the image is transported through a registry,
also pin the registry manifest digest; after the final pull, use the local
Docker image `Id` in the final-gate plan and CLI. A registry digest and a local
image ID are different identities and are not interchangeable.

The module exposes normalization helpers for the three runtime observations:

```python
from vulngym_agent.native_linux_final_gate_preflight import (
    docker_info_identity_sha256_v1,
    docker_server_identity_sha256_v1,
    runtime_image_inspect_sha256_v1,
)
```

Feed those helpers the parsed objects from these exact, read-only observations:

```bash
docker --host=unix:///run/vulngym/docker.sock version --format '{{json .Server}}'
docker --host=unix:///run/vulngym/docker.sock info --format '{{json .}}'
docker --host=unix:///run/vulngym/docker.sock image inspect \
  "${RUNTIME_IMAGE_ID}" --format '{{json .}}'
sha256sum /usr/bin/docker
```

`docker_info_identity_sha256_v1` intentionally excludes volatile clock and
container/image counters while binding daemon ID, server/kernel versions,
cgroup, runc/containerd, security options, storage, host identity, CPU, and
memory. Retain the raw observations and their pins outside the evaluator host.

After all packages, image archives, benchmark inputs, and controls have been
loaded, disable host egress externally. Container `--network=none` is necessary
but does not prove that the trusted host itself is offline.

## 4. Close the 70 static inputs and plan

Prepare exactly 20 answer-free test tasks and 50 training tasks. Each split
needs a sealed-batch manifest pin, an ordered replay manifest semantic pin and
wire pin, and a distinct snapshot key ID. Build the final-gate plan only after
the final local worker image ID is known because that ID changes both the fixed
execution-policy digest and the plan digest.

The plan is an authorization artifact. Publish its canonical bytes plus its
semantic and exact-wire SHA-256 pins through a trusted control channel. The
preflight consumes but never synthesizes or repairs it. It uses the existing
strict readers to:

1. load the public answer-free test task order;
2. verify all 20 replay pairs and the complete sealed test batch;
3. derive and normalize the complete static test execution plan;
4. abort the static session and clear the test key buffer;
5. repeat the same sequence for all 50 training tasks.

No Docker command is reachable until both static split verifications, in that
order, have succeeded.

## 5. Bind the external operator assertion

Run preflight once without the final two assertion arguments. It must return
`status="not_ready"` with
`operator_external_isolation_assertion.code="operator_assertion_required"`.
All preceding checks must be `ready`. The report's `bindings` object supplies
the exact host, socket, CLI, daemon, image, policy, and plan identities for the
operator record.

Create an owner-only canonical one-line JSON document with exactly these
fields. Replace digest placeholders with the observed values; every Boolean
must remain `true`:

```json
{"contract_version":2,"daemon_endpoint_sha256":"<sha256>","daemon_info_sha256":"<sha256>","docker_executable_sha256":"<sha256>","docker_socket_identity_sha256":"<sha256>","exclusive_docker_daemon":true,"exclusive_native_linux_host":true,"final_gate_plan_sha256":"<sha256>","final_gate_plan_wire_sha256":"<sha256>","host_egress_disabled_for_gate":true,"host_identity_sha256":"<sha256>","kind":"vulngym.native-linux-final-gate-operator-assertion.v2","no_concurrent_docker_clients":true,"runtime_image_id":"sha256:<64 lowercase hex>","runtime_image_inspect_sha256":"<sha256>","scoring_gold_physically_isolated":true,"server_observation_sha256":"<sha256>"}
```

The line must have UTF-8 encoding, lexicographically sorted keys, no extra
whitespace, and one trailing newline. Store its exact SHA-256 outside this host,
then supply both the file and external wire pin to the second preflight. A file
and hash generated solely by the same possibly compromised host are not an
independent assertion.

## 6. Run preflight

Run from the exact read-only implementation checkout. Redirect stdout only to
an owner-only control location. The only transient write performed by the
preflight process itself is its Docker CLI configuration below the explicit
scratch root; it never falls back to `TMPDIR` for that data:

```bash
umask 077
python -B -m vulngym_agent.native_linux_final_gate_preflight \
  --benchmark-root /srv/vulngym/benchmark \
  --control-root /srv/vulngym/control \
  --implementation-root /opt/vulngym/implementation \
  --scratch-root /srv/vulngym/scratch \
  --output-root /srv/vulngym/final-gates/gate-001 \
  --docker-executable /usr/bin/docker \
  --docker-host unix:///run/vulngym/docker.sock \
  --runtime-image-id "${RUNTIME_IMAGE_ID}" \
  --expected-docker-cli-sha256 "${DOCKER_CLI_SHA256}" \
  --expected-docker-server-sha256 "${DOCKER_SERVER_SHA256}" \
  --expected-docker-info-sha256 "${DOCKER_INFO_SHA256}" \
  --expected-runtime-image-inspect-sha256 "${IMAGE_INSPECT_SHA256}" \
  --plan-file /srv/vulngym/control/final-gate-plan.json \
  --expected-plan-sha256 "${PLAN_SHA256}" \
  --expected-plan-wire-sha256 "${PLAN_WIRE_SHA256}" \
  --test-sealed-batch-root /srv/vulngym/inputs/test-sealed \
  --test-replay-config-root /srv/vulngym/inputs/test-replay \
  --train-sealed-batch-root /srv/vulngym/inputs/train-sealed \
  --train-replay-config-root /srv/vulngym/inputs/train-replay \
  --test-key-file /srv/vulngym/control/secrets/test.key \
  --train-key-file /srv/vulngym/control/secrets/train.key \
  --operator-assertion-file /srv/vulngym/control/operator-assertion.json \
  --expected-operator-assertion-wire-sha256 "${OPERATOR_ASSERTION_WIRE_SHA256}" \
  > /srv/vulngym/control/readiness-report.json
```

Exit status `0` means every mechanical check and the exact external assertion
are bound and the canonical report says `ready`. Exit status `1` means
`not_ready`; remaining checks are marked `not_checked` after the first failure.
Malformed CLI input also emits a canonical `not_ready` report. Treat any other
status or missing/truncated stdout as failure.

The report is a point-in-time readiness observation, not an acceptance receipt.
Keep the host lock continuously held between preflight and the real gate. The
real runner independently rechecks the Docker CLI, daemon, base image, sealed
inputs, replay inputs, and final output.

Retain both readiness pins outside the host. The semantic pin is the report's
embedded `report_sha256`; the exact-wire pin is `sha256sum` over the complete
canonical one-line file, including its trailing newline. These double pins do
not constitute a signature. The final-gate command must receive both pins and
the same explicit Docker endpoint; it will not infer authority from an ambient
Docker context.

## 7. Execute and verify the real gate

Allow at least 35 hours for the fixed serial worst case of 70 tasks at 1800
seconds per task, plus static verification, materialization, projection,
readback, and cleanup. Do not use the existing 20-minute single-task CI job.

With the same pins, paths, keys, socket, host lock, and local worker image ID,
run:

```bash
python -B -m vulngym_agent.final_gate_cli run \
  --benchmark-root /srv/vulngym/benchmark \
  --output-root /srv/vulngym/final-gates/gate-001 \
  --docker-executable /usr/bin/docker \
  --docker-host unix:///run/vulngym/docker.sock \
  --runtime-image-id "${RUNTIME_IMAGE_ID}" \
  --readiness-file /srv/vulngym/control/readiness-report.json \
  --expected-readiness-sha256 "${READINESS_SHA256}" \
  --expected-readiness-wire-sha256 "${READINESS_WIRE_SHA256}" \
  --plan-file /srv/vulngym/control/final-gate-plan.json \
  --expected-plan-sha256 "${PLAN_SHA256}" \
  --expected-plan-wire-sha256 "${PLAN_WIRE_SHA256}" \
  --test-sealed-batch-root /srv/vulngym/inputs/test-sealed \
  --test-replay-config-root /srv/vulngym/inputs/test-replay \
  --train-sealed-batch-root /srv/vulngym/inputs/train-sealed \
  --train-replay-config-root /srv/vulngym/inputs/train-replay \
  --test-key-file /srv/vulngym/control/secrets/test.key \
  --train-key-file /srv/vulngym/control/secrets/train.key
```

The runner compares the readiness-bound endpoint, CLI bytes, Unix socket
identity, server observation, stable Docker `info` identity, image ID, and
image-inspect identity before execution and again at its existing per-task
reverification points. A changed ambient `DOCKER_HOST` or Docker context cannot
silently redirect the gate because the endpoint is an explicit argument to
every Docker probe; TCP and SSH endpoints are rejected.

The static preflight also requires each task's fixed D2/D3 replay pair to have
the same task/runtime identity and a non-empty transcript on both sides. During
the formal run and independent readback, every one of the 70 task projections
must be `finalized` and must contain at least one accepted finding. These are
only mechanical completeness conditions for this known-vulnerability corpus.
They do not establish that a finding is correct and do not replace the separate
precision/recall threshold computed against trusted gold.

On success, transfer the path-free receipt semantic and wire pins to the
independent verifier channel and run:

```bash
python -B -m vulngym_agent.final_gate_cli verify-output \
  --output-root /srv/vulngym/final-gates/gate-001 \
  --benchmark-root /srv/vulngym/benchmark \
  --expected-receipt-sha256 "${RECEIPT_SHA256}" \
  --expected-wire-sha256 "${RECEIPT_WIRE_SHA256}"
```

Also require zero remaining containers and zero images carrying the
`vulngym.e3.execution` label. Preserve and externally sign the implementation
commit, host/image observations, plan pins, readiness report pin, final receipt
pins, and independent verification result. Rotate both snapshot keys and
destroy or reimage the evaluator host after evidence export.

## 8. CI boundary

Do not attach these materials to a pull-request or ordinary push workflow. If
GitHub Actions coordinates the run, use a separate protected
`workflow_dispatch` workflow with an approved self-hosted native-Linux runner,
immutable action commit pins, one concurrency group, no fork execution, and no
secret values in logs or uploaded artifacts. Prefer running the long-lived gate
as a protected systemd service on the dedicated host and using CI only for
approval, dispatch, and receipt-pin readback.

The existing `ubuntu-latest` single-task integration remains useful as an E3
smoke test. It is not the 70-task acceptance gate and must not be relabeled as
one.
