# Sealed snapshot Git-symlink representation (v2)

The v2 sealed-snapshot contract accepts a Git tree entry with mode `120000`
only when the referenced object is a blob. The blob is a Git symlink target in
repository semantics, but the evaluator treats its bytes as opaque source data:

- it never calls a host symlink API and never resolves the target;
- it writes the raw blob bytes at the manifest path as a newly created ordinary
  file; on POSIX the creation mode is fixed to `0600`;
- it retains `git_mode: "120000"`, the original blob object ID, size, SHA-256,
  and content-root binding in the authenticated manifest; and
- the policy records
  `git_symlink_representation: "regular-file-raw-target-bytes"`.

Consequently, target bytes such as `/etc/passwd`, `C:\outside`, or
`../../outside/source.py` have no path meaning during preparation, verification,
sealed-tree access, or worker access. They are readable only as the contents of
the ordinary file at the Git entry's safe, portable manifest path.

## Verification boundary

The representation does not relax filesystem checks. The verifier inventories
the exact manifest tree with `lstat`, rejects symlinks, reparse points,
hardlinks, non-regular nodes, extras, and missing files, and opens files with
no-follow semantics where the platform provides them. It recomputes the Git
blob ID and SHA-256 over the materialized raw bytes. Sealed-tree and worker
readers independently require the mounted node to remain a regular,
single-link, no-follow file.

`0600` is a POSIX mode statement, not a portable Windows ACL claim. On Windows,
the sealed root and its files rely on the already validated owner-private
parent ACL, while reparse points, alternate data streams, hardlinks, and other
non-regular representations remain rejected. The implementation does not
pretend that POSIX mode bits can prove a Windows DACL.

Gitlinks (`160000` or commit objects) remain rejected. Git LFS pointer blobs
remain rejected for every accepted blob mode, including `120000`. File, tree,
path, manifest, and aggregate byte limits apply to materialized Git-symlink
blobs exactly as they apply to other source blobs.

## Version and migration rule

This is an incompatible snapshot representation change. The following bindings
are v2:

- `vulngym.sealed-source-snapshot.v2`;
- `vulngym.portable-source-tree.v2`;
- `VulnGym sealed source content root v2\0`; and
- `VulnGym sealed source attestation v2\0`.

The exact-wire batch, snapshot-policy, sealed-tree access, worker handoff,
discovery batch plan/receipt, and E4 batch-success envelopes that embed or bind
this representation are likewise v2. V1 is retained only where a reader is
genuinely compatible with unchanged v1 wire semantics; no v1 name aliases the
new materialization behavior.

V1 manifests and attestations do not verify under the v2 implementation. Batch
and worker artifacts that bind a snapshot policy, manifest digest, or content
root must be regenerated from the v2 preparer; changing a version label or hash
in place is not a migration.

This representation prevents a Git symlink from becoming a host filesystem
capability. It does not assert that an application will never choose to parse
the ordinary file's bytes as a path, so downstream tools must continue to treat
source contents as untrusted input.
