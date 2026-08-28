# Sealed snapshot gitlink representation v3

Snapshot v3 represents a Git tree entry whose mode is exactly `160000` and
whose object type is exactly `commit` as authenticated metadata. It does not
checkout, fetch, recurse into, or read the child repository.

The manifest uses a distinct `record_type: "gitlink"` record with the original
portable path, `git_mode: "160000"`, the 40-character
`target_commit_oid`, the fixed representation
`regular-file-gitlink-commit-oid-lf`, size 49, and the SHA-256 of the
materialized marker. `blob_oid` remains exclusive to ordinary file records.

The tree contains a regular mode-0600 file at the gitlink path. Its exact bytes
are `gitlink `, followed by the lower-case target commit OID and one LF byte.
The marker is not a checkout and grants no host or network capability.

Consequently, child-submodule source is not sealed and must not be treated as
available to the agent. A benchmark task using this representation is valid
only when the vulnerability and its gold evidence are wholly within the
superproject. For the task motivating v3, all confirmed gold paths are under
`src/**`; the unrelated `Peekaboo` gitlink is metadata only.

Issue #60 only establishes acquisition, snapshot, batch-evidence, and closure-
receipt support for this metadata record. Worker and sealed-tree consumption is
deferred: current worker handoff construction and direct sealed-tree binding
fail closed when a verified snapshot contains a gitlink. Tasks without gitlinks
retain the existing worker/access wire contracts and behavior.
