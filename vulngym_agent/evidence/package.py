"""Safe local advisory, reference, and patch package loading.

The package boundary is intentionally smaller than the eventual T1/T2
semantic layer.  It proves only that explicitly named local text files can be
read inside an authorised root.  It never follows repository metadata,
executes target code, opens a network connection, or infers vulnerability
semantics from a successfully decoded document.
"""

from __future__ import annotations

from dataclasses import dataclass
import errno
from hashlib import sha256
import ntpath
import os
from pathlib import Path, PurePosixPath
import stat
from typing import Any, BinaryIO, Final, Mapping


DEFAULT_MAX_FILE_BYTES: Final[int] = 8 * 1024 * 1024
DEFAULT_MAX_PACKAGE_BYTES: Final[int] = 32 * 1024 * 1024
DEFAULT_MAX_PACKAGE_FILES: Final[int] = 64
HARD_MAX_PACKAGE_FILES: Final[int] = 256
_SPEC_FIELDS: Final[frozenset[str]] = frozenset(
    {"advisory", "references", "patches"}
)
_PACKAGE_STATUSES: Final[frozenset[str]] = frozenset(
    {"correct", "incorrect", "uncertain"}
)
_FILE_KINDS: Final[frozenset[str]] = frozenset(
    {"advisory", "reference", "patch"}
)


@dataclass(frozen=True, slots=True)
class PackageIssue:
    """One machine-readable package contract or local-read failure."""

    status: str
    code: str
    field: str
    message: str
    relative_path: str | None = None

    def __post_init__(self) -> None:
        if self.status not in {"incorrect", "uncertain"}:
            raise ValueError("package issue status must be incorrect or uncertain")
        if not self.code or not self.field or not self.message:
            raise ValueError("package issue code, field, and message must be non-empty")

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "status": self.status,
            "code": self.code,
            "field": self.field,
            "message": self.message,
        }
        if self.relative_path is not None:
            value["relative_path"] = self.relative_path
        return value


def _path_issue(field: str, code: str, message: str, value: Any) -> PackageIssue:
    return PackageIssue(
        status="incorrect",
        code=code,
        field=field,
        message=message,
        relative_path=value if isinstance(value, str) else None,
    )


def _validate_relative_posix_path(value: Any, field: str) -> PackageIssue | None:
    if not isinstance(value, str):
        return _path_issue(
            field,
            "package_field_type",
            "evidence path must be a string",
            value,
        )
    if not value:
        return _path_issue(field, "path_empty", "evidence path must not be empty", value)
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        return _path_issue(
            field,
            "path_control_character",
            "evidence path must not contain control characters",
            value,
        )
    if "\\" in value:
        return _path_issue(
            field,
            "path_not_posix",
            "evidence path must use POSIX forward slashes",
            value,
        )
    drive, _ = ntpath.splitdrive(value)
    if drive:
        return _path_issue(
            field,
            "path_drive",
            "evidence path must not contain a Windows drive or UNC share",
            value,
        )
    if PurePosixPath(value).is_absolute() or value.startswith("/"):
        return _path_issue(
            field,
            "path_absolute",
            "evidence path must be relative to --package-root",
            value,
        )
    components = value.split("/")
    if ".." in components:
        return _path_issue(
            field,
            "path_traversal",
            "evidence path must not contain '..'",
            value,
        )
    if any(component in {"", "."} for component in components):
        return _path_issue(
            field,
            "path_not_canonical",
            "evidence path must not contain empty or '.' components",
            value,
        )
    # Colons are legal in a POSIX filename, but rejecting them gives the same
    # package contract on every platform and prevents Windows ADS access.
    if any(":" in component for component in components):
        return _path_issue(
            field,
            "path_invalid_character",
            "evidence path components must not contain ':'",
            value,
        )
    return None


@dataclass(frozen=True, slots=True)
class PackageSpec:
    """The untrusted relative paths declared by one input JSONL row.

    Canonical wrapper form::

        {"package": {
          "advisory": "advisory/GHSA-....json",
          "references": ["references/pr-123.md"],
          "patches": ["patches/fix.patch"]
        }, "entry": {...}}

    Repository paths deliberately do not belong here.  The candidate Entry's
    exact ``repo_url`` remains the sole key into the existing ``--repo-map``.
    """

    advisory: str
    references: tuple[str, ...] = ()
    patches: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.references, (list, tuple)):
            raise ValueError("references must be a list or tuple of path strings")
        if not isinstance(self.patches, (list, tuple)):
            raise ValueError("patches must be a list or tuple of path strings")
        object.__setattr__(self, "references", tuple(self.references))
        object.__setattr__(self, "patches", tuple(self.patches))
        issues = _validate_spec_paths(self)
        if issues:
            raise ValueError(issues[0].message)

    def to_dict(self) -> dict[str, Any]:
        return {
            "advisory": self.advisory,
            "references": list(self.references),
            "patches": list(self.patches),
        }


@dataclass(frozen=True, slots=True)
class LoadedEvidenceFile:
    """One bounded UTF-8 document, with a raw-byte digest for replay."""

    kind: str
    relative_path: str
    text: str
    byte_size: int
    sha256: str

    def __post_init__(self) -> None:
        if self.kind not in _FILE_KINDS:
            raise ValueError("unsupported local evidence file kind")
        if self.byte_size < 0:
            raise ValueError("byte_size must be non-negative")

    def to_dict(self, *, include_text: bool = False) -> dict[str, Any]:
        value: dict[str, Any] = {
            "kind": self.kind,
            "relative_path": self.relative_path,
            "byte_size": self.byte_size,
            "sha256": self.sha256,
        }
        if include_text:
            value["text"] = self.text
        return value


@dataclass(frozen=True, slots=True)
class LocalEvidencePackage:
    """Successfully parsed package plus every document that could be loaded."""

    root: Path
    spec: PackageSpec
    advisory: LoadedEvidenceFile | None
    references: tuple[LoadedEvidenceFile, ...] = ()
    patches: tuple[LoadedEvidenceFile, ...] = ()

    @property
    def documents(self) -> tuple[LoadedEvidenceFile, ...]:
        advisory = (self.advisory,) if self.advisory is not None else ()
        return advisory + self.references + self.patches

    @property
    def total_bytes(self) -> int:
        return sum(document.byte_size for document in self.documents)

    @property
    def usable(self) -> bool:
        """An advisory is the minimum material required by semantic stages."""

        return self.advisory is not None

    def to_dict(self, *, include_text: bool = False) -> dict[str, Any]:
        # Do not serialize the absolute root: manifests and logs should retain
        # portable relative paths without leaking a workstation directory.
        return {
            "spec": self.spec.to_dict(),
            "advisory": (
                self.advisory.to_dict(include_text=include_text)
                if self.advisory is not None
                else None
            ),
            "references": [
                document.to_dict(include_text=include_text)
                for document in self.references
            ],
            "patches": [
                document.to_dict(include_text=include_text)
                for document in self.patches
            ],
            "total_bytes": self.total_bytes,
        }

    @classmethod
    def load(
        cls,
        package_root: str | os.PathLike[str],
        spec: PackageSpec | Mapping[str, Any] | Any,
        **kwargs: Any,
    ) -> "PackageLoadResult":
        return load_evidence_package(package_root, spec, **kwargs)


@dataclass(frozen=True, slots=True)
class PackageLoadResult:
    """Non-throwing per-input package result with three-state classification."""

    status: str
    package: LocalEvidencePackage | None
    issues: tuple[PackageIssue, ...] = ()
    input_line: int | None = None
    entry_id: str | None = None
    report_id: str | None = None

    def __post_init__(self) -> None:
        if self.status not in _PACKAGE_STATUSES:
            raise ValueError("invalid package load status")
        if self.input_line is not None and (
            isinstance(self.input_line, bool)
            or not isinstance(self.input_line, int)
            or self.input_line < 1
        ):
            raise ValueError("input_line must be a positive integer or None")

    @property
    def complete(self) -> bool:
        return self.status == "correct" and self.package is not None

    @property
    def usable(self) -> bool:
        return self.package is not None and self.package.usable

    def to_dict(self, *, include_text: bool = False) -> dict[str, Any]:
        return {
            "input_line": self.input_line,
            "entry_id": self.entry_id,
            "report_id": self.report_id,
            "status": self.status,
            "package": (
                self.package.to_dict(include_text=include_text)
                if self.package is not None
                else None
            ),
            "issues": [issue.to_dict() for issue in self.issues],
        }


def _validate_spec_paths(spec: PackageSpec) -> tuple[PackageIssue, ...]:
    issues: list[PackageIssue] = []
    values: list[tuple[str, str]] = [("$.package.advisory", spec.advisory)]
    values.extend(
        (f"$.package.references[{index}]", value)
        for index, value in enumerate(spec.references)
    )
    values.extend(
        (f"$.package.patches[{index}]", value)
        for index, value in enumerate(spec.patches)
    )
    seen: dict[str, str] = {}
    for field, value in values:
        issue = _validate_relative_posix_path(value, field)
        if issue is not None:
            issues.append(issue)
            continue
        previous = seen.setdefault(value, field)
        if previous != field:
            issues.append(
                PackageIssue(
                    status="incorrect",
                    code="package_duplicate_path",
                    field=field,
                    relative_path=value,
                    message=f"evidence path duplicates {previous}",
                )
            )
    return tuple(issues)


def _parse_spec(value: Any) -> tuple[PackageSpec | None, tuple[PackageIssue, ...]]:
    if isinstance(value, PackageSpec):
        return value, ()
    if not isinstance(value, Mapping):
        return None, (
            PackageIssue(
                "incorrect",
                "package_spec_type",
                "$.package",
                "package must be a JSON object",
            ),
        )

    issues: list[PackageIssue] = []
    raw_fields = list(value.keys())
    if any(not isinstance(field, str) for field in raw_fields):
        issues.append(
            PackageIssue(
                "incorrect",
                "package_field_name",
                "$.package",
                "package field names must be strings",
            )
        )
    for field in sorted(
        (field for field in raw_fields if field not in _SPEC_FIELDS), key=str
    ):
        issues.append(
            PackageIssue(
                "incorrect",
                "package_extra_field",
                f"$.package.{field}",
                "package contains an unsupported field",
            )
        )
    if "advisory" not in value:
        issues.append(
            PackageIssue(
                "incorrect",
                "package_missing_advisory",
                "$.package.advisory",
                "package advisory path is required",
            )
        )

    advisory = value.get("advisory")
    references = value.get("references", [])
    patches = value.get("patches", [])
    if not isinstance(advisory, str):
        if "advisory" in value:
            issues.append(
                PackageIssue(
                    "incorrect",
                    "package_field_type",
                    "$.package.advisory",
                    "advisory must be a path string",
                )
            )
    for name, items in (("references", references), ("patches", patches)):
        if not isinstance(items, list):
            issues.append(
                PackageIssue(
                    "incorrect",
                    "package_field_type",
                    f"$.package.{name}",
                    f"{name} must be a JSON array of path strings",
                )
            )
        elif any(not isinstance(item, str) for item in items):
            for index, item in enumerate(items):
                if not isinstance(item, str):
                    issues.append(
                        PackageIssue(
                            "incorrect",
                            "package_field_type",
                            f"$.package.{name}[{index}]",
                            "evidence path must be a string",
                        )
                    )

    if issues:
        return None, tuple(issues)
    assert isinstance(advisory, str)
    assert isinstance(references, list)
    assert isinstance(patches, list)
    provisional = object.__new__(PackageSpec)
    object.__setattr__(provisional, "advisory", advisory)
    object.__setattr__(provisional, "references", tuple(references))
    object.__setattr__(provisional, "patches", tuple(patches))
    path_issues = _validate_spec_paths(provisional)
    if path_issues:
        return None, path_issues
    return provisional, ()


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _is_link_or_reparse(path: Path, file_stat: os.stat_result) -> bool:
    if stat.S_ISLNK(file_stat.st_mode) or path.is_symlink():
        return True
    is_junction = getattr(os.path, "isjunction", None)
    if is_junction is not None:
        try:
            if is_junction(path):
                return True
        except OSError:
            return True
    attributes = getattr(file_stat, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(reparse_flag and attributes & reparse_flag)


@dataclass(frozen=True, slots=True)
class _ValidatedPackageFile:
    """A point-in-time identity snapshot for every component of one path."""

    root: Path
    path: Path
    resolved: Path
    relative_path: str
    chain: tuple[os.stat_result, ...]


def _stat_identity(file_stat: os.stat_result) -> tuple[int, int, int, int]:
    """Return stable object/type identity, including Windows reparse state."""

    return (
        file_stat.st_dev,
        file_stat.st_ino,
        stat.S_IFMT(file_stat.st_mode),
        getattr(file_stat, "st_file_attributes", 0),
    )


def _same_file_identity(
    expected: os.stat_result, observed: os.stat_result
) -> bool:
    return _stat_identity(expected) == _stat_identity(observed)


def _file_changed_issue(field: str, relative_path: str, message: str) -> PackageIssue:
    return PackageIssue(
        "uncertain",
        "file_changed",
        field,
        message,
        relative_path,
    )


def _resolve_package_file(
    root: Path, relative_path: str, field: str
) -> tuple[_ValidatedPackageFile | None, PackageIssue | None]:
    candidate = root.joinpath(*relative_path.split("/"))
    current = root
    chain: list[os.stat_result] = []
    try:
        root_stat = root.lstat()
        if _is_link_or_reparse(root, root_stat):
            return None, PackageIssue(
                "incorrect",
                "path_link_disallowed",
                field,
                "the authorised package root must not be a symlink, junction, or reparse point",
                relative_path,
            )
        if not stat.S_ISDIR(root_stat.st_mode):
            return None, PackageIssue(
                "uncertain",
                "file_stat_error",
                field,
                "the authorised package root is no longer a directory",
                relative_path,
            )
        chain.append(root_stat)
        for component in relative_path.split("/"):
            current = current / component
            file_stat = current.lstat()
            if _is_link_or_reparse(current, file_stat):
                return None, PackageIssue(
                    "incorrect",
                    "path_link_disallowed",
                    field,
                    "evidence paths must not traverse a symlink, junction, or reparse point",
                    relative_path,
                )
            chain.append(file_stat)
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError:
        return None, PackageIssue(
            "uncertain",
            "file_missing",
            field,
            "declared local evidence file does not exist",
            relative_path,
        )
    except (OSError, RuntimeError) as error:
        return None, PackageIssue(
            "uncertain",
            "file_stat_error",
            field,
            f"local evidence path could not be inspected: {error}",
            relative_path,
        )
    if not _is_within(resolved, root):
        return None, PackageIssue(
            "incorrect",
            "path_escape",
            field,
            "resolved evidence path escapes the authorised package root",
            relative_path,
        )
    if not stat.S_ISREG(chain[-1].st_mode):
        return None, PackageIssue(
            "incorrect",
            "not_regular_file",
            field,
            "declared evidence path is not a regular file",
            relative_path,
        )
    for ancestor in chain[:-1]:
        if not stat.S_ISDIR(ancestor.st_mode):
            return None, PackageIssue(
                "incorrect",
                "not_regular_file",
                field,
                "an evidence path ancestor is not a directory",
                relative_path,
            )
    return (
        _ValidatedPackageFile(
            root=root,
            path=candidate,
            resolved=resolved,
            relative_path=relative_path,
            chain=tuple(chain),
        ),
        None,
    )


def _supports_atomic_relative_open() -> bool:
    """Whether the runtime can hold and traverse directory handles safely."""

    return (
        os.name != "nt"
        and os.open in os.supports_dir_fd
        and hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NOFOLLOW")
    )


def _open_relative_no_follow(
    validated: _ValidatedPackageFile,
    *,
    field: str,
) -> tuple[BinaryIO | None, os.stat_result | None, PackageIssue | None]:
    """Open from a held root descriptor without following any path component."""

    directory_fds: list[int] = []
    file_fd: int | None = None
    components = validated.relative_path.split("/")
    directory_flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )
    file_flags = (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_BINARY", 0)
    )
    try:
        root_fd = os.open(validated.root, directory_flags)
        directory_fds.append(root_fd)
        opened_root = os.fstat(root_fd)
        if (
            not stat.S_ISDIR(opened_root.st_mode)
            or not _same_file_identity(validated.chain[0], opened_root)
        ):
            return None, None, _file_changed_issue(
                field,
                validated.relative_path,
                "the authorised package root changed before the evidence file was opened",
            )

        parent_fd = root_fd
        for index, component in enumerate(components[:-1], start=1):
            child_fd = os.open(component, directory_flags, dir_fd=parent_fd)
            directory_fds.append(child_fd)
            opened_directory = os.fstat(child_fd)
            if (
                not stat.S_ISDIR(opened_directory.st_mode)
                or not _same_file_identity(validated.chain[index], opened_directory)
            ):
                return None, None, _file_changed_issue(
                    field,
                    validated.relative_path,
                    "an evidence path ancestor changed before the file was opened",
                )
            parent_fd = child_fd

        file_fd = os.open(components[-1], file_flags, dir_fd=parent_fd)
        opened_file = os.fstat(file_fd)
        if (
            not stat.S_ISREG(opened_file.st_mode)
            or not _same_file_identity(validated.chain[-1], opened_file)
            or validated.chain[-1].st_size != opened_file.st_size
        ):
            return None, None, _file_changed_issue(
                field,
                validated.relative_path,
                "the evidence file changed between validation and opening",
            )
        stream = os.fdopen(file_fd, "rb")
        file_fd = None
        return stream, opened_file, None
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.ENOTDIR, errno.ENOENT}:
            return None, None, _file_changed_issue(
                field,
                validated.relative_path,
                "the evidence path changed or became a link before it could be opened safely",
            )
        return None, None, PackageIssue(
            "uncertain",
            "file_read_error",
            field,
            f"local evidence file could not be opened safely: {error}",
            validated.relative_path,
        )
    finally:
        if file_fd is not None:
            os.close(file_fd)
        for directory_fd in reversed(directory_fds):
            os.close(directory_fd)


def _windows_final_path_from_fd(file_descriptor: int) -> Path:
    """Return the kernel-resolved DOS path for an already-open Windows handle."""

    import ctypes
    from ctypes import wintypes
    import msvcrt

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_final_path = kernel32.GetFinalPathNameByHandleW
    get_final_path.argtypes = (
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    )
    get_final_path.restype = wintypes.DWORD
    handle = msvcrt.get_osfhandle(file_descriptor)
    size = 512
    while True:
        buffer = ctypes.create_unicode_buffer(size)
        length = get_final_path(handle, buffer, size, 0)
        if length == 0:
            error_code = ctypes.get_last_error()
            raise OSError(error_code, "GetFinalPathNameByHandleW failed")
        if length < size:
            value = buffer.value
            break
        size = length + 1
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return Path(value)


def _windows_path_is_within(path: Path, root: Path) -> bool:
    normal_path = ntpath.normcase(ntpath.normpath(str(path)))
    normal_root = ntpath.normcase(ntpath.normpath(str(root)))
    try:
        return ntpath.commonpath((normal_path, normal_root)) == normal_root
    except ValueError:
        return False


def _open_with_chain_revalidation(
    validated: _ValidatedPackageFile,
    *,
    field: str,
) -> tuple[BinaryIO | None, os.stat_result | None, PackageIssue | None]:
    """Fallback open and full-chain revalidation before reading any bytes."""

    try:
        stream = validated.path.open("rb")
    except OSError as error:
        return None, None, PackageIssue(
            "uncertain",
            "file_read_error",
            field,
            f"local evidence file could not be read: {error}",
            validated.relative_path,
        )

    try:
        opened = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(opened.st_mode)
            or not _same_file_identity(validated.chain[-1], opened)
            or validated.chain[-1].st_size != opened.st_size
        ):
            stream.close()
            return None, None, _file_changed_issue(
                field,
                validated.relative_path,
                "the evidence file changed between validation and opening",
            )

        if os.name == "nt":
            try:
                opened_path = _windows_final_path_from_fd(stream.fileno())
            except OSError as error:
                stream.close()
                return None, None, PackageIssue(
                    "uncertain",
                    "file_stat_error",
                    field,
                    f"the opened evidence handle could not be resolved safely: {error}",
                    validated.relative_path,
                )
            if not _windows_path_is_within(opened_path, validated.root):
                stream.close()
                return None, None, _file_changed_issue(
                    field,
                    validated.relative_path,
                    "the opened evidence handle resolves outside the authorised package root",
                )

        after, issue = _resolve_package_file(
            validated.root, validated.relative_path, field
        )
        if issue is not None:
            stream.close()
            return None, None, issue
        assert after is not None
        if (
            len(after.chain) != len(validated.chain)
            or any(
                not _same_file_identity(expected, observed)
                for expected, observed in zip(validated.chain, after.chain)
            )
            or after.resolved != validated.resolved
        ):
            stream.close()
            return None, None, _file_changed_issue(
                field,
                validated.relative_path,
                "the evidence path or one of its ancestors changed while the file was opened",
            )
        return stream, opened, None
    except OSError as error:
        stream.close()
        return None, None, PackageIssue(
            "uncertain",
            "file_read_error",
            field,
            f"local evidence file could not be inspected after opening: {error}",
            validated.relative_path,
        )


def _read_document(
    validated: _ValidatedPackageFile,
    *,
    kind: str,
    relative_path: str,
    field: str,
    max_file_bytes: int,
    remaining_package_bytes: int,
) -> tuple[LoadedEvidenceFile | None, PackageIssue | None]:
    before = validated.chain[-1]
    size = before.st_size
    if size > max_file_bytes:
        return None, PackageIssue(
            "uncertain",
            "file_too_large",
            field,
            f"evidence file is {size} bytes; per-file limit is {max_file_bytes}",
            relative_path,
        )
    if size > remaining_package_bytes:
        return None, PackageIssue(
            "uncertain",
            "package_too_large",
            field,
            "reading this file would exceed the package byte limit",
            relative_path,
        )

    read_limit = min(max_file_bytes, remaining_package_bytes) + 1
    if _supports_atomic_relative_open():
        stream, _, issue = _open_relative_no_follow(validated, field=field)
    else:
        stream, _, issue = _open_with_chain_revalidation(validated, field=field)
    if issue is not None:
        return None, issue
    assert stream is not None
    try:
        with stream:
            data = stream.read(read_limit)
    except OSError as error:
        return None, PackageIssue(
            "uncertain",
            "file_read_error",
            field,
            f"local evidence file could not be read: {error}",
            relative_path,
        )
    if len(data) > max_file_bytes:
        return None, PackageIssue(
            "uncertain",
            "file_too_large",
            field,
            f"evidence file grew beyond the per-file limit of {max_file_bytes}",
            relative_path,
        )
    if len(data) > remaining_package_bytes:
        return None, PackageIssue(
            "uncertain",
            "package_too_large",
            field,
            "evidence file grew beyond the remaining package byte budget",
            relative_path,
        )
    try:
        text = data.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError as error:
        return None, PackageIssue(
            "uncertain",
            "file_not_utf8",
            field,
            f"local evidence file is not valid UTF-8: {error}",
            relative_path,
        )
    return (
        LoadedEvidenceFile(
            kind=kind,
            relative_path=relative_path,
            text=text,
            byte_size=len(data),
            sha256=sha256(data).hexdigest(),
        ),
        None,
    )


def _result_status(issues: list[PackageIssue]) -> str:
    if any(issue.status == "incorrect" for issue in issues):
        return "incorrect"
    if issues:
        return "uncertain"
    return "correct"


def load_evidence_package(
    package_root: str | os.PathLike[str],
    spec: PackageSpec | Mapping[str, Any] | Any,
    *,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_package_bytes: int = DEFAULT_MAX_PACKAGE_BYTES,
    max_package_files: int = DEFAULT_MAX_PACKAGE_FILES,
    input_line: int | None = None,
    entry_id: str | None = None,
    report_id: str | None = None,
) -> PackageLoadResult:
    """Load one entry's local materials without propagating expected failures.

    ``correct`` means only that every declared file was safely read.  Missing,
    oversized, undecodable, or inaccessible material is ``uncertain``.  A
    malformed package contract or unsafe path is ``incorrect``.  The caller's
    input correlation is copied to every outcome, including failures.
    """

    if (
        isinstance(max_file_bytes, bool)
        or not isinstance(max_file_bytes, int)
        or max_file_bytes < 0
    ):
        raise ValueError("max_file_bytes must be a non-negative integer")
    if (
        isinstance(max_package_bytes, bool)
        or not isinstance(max_package_bytes, int)
        or max_package_bytes < 0
    ):
        raise ValueError("max_package_bytes must be a non-negative integer")
    if (
        isinstance(max_package_files, bool)
        or not isinstance(max_package_files, int)
        or not 1 <= max_package_files <= HARD_MAX_PACKAGE_FILES
    ):
        raise ValueError(
            "max_package_files must be an integer between 1 and "
            f"{HARD_MAX_PACKAGE_FILES}"
        )
    if input_line is not None and (
        isinstance(input_line, bool)
        or not isinstance(input_line, int)
        or input_line < 1
    ):
        raise ValueError("input_line must be a positive integer or None")

    parsed, spec_issues = _parse_spec(spec)
    if parsed is None:
        return PackageLoadResult(
            "incorrect",
            None,
            spec_issues,
            input_line,
            entry_id,
            report_id,
        )

    declared_file_count = 1 + len(parsed.references) + len(parsed.patches)
    if declared_file_count > max_package_files:
        issue = PackageIssue(
            "incorrect",
            "package_file_limit_exceeded",
            "$.package",
            (
                f"package declares {declared_file_count} evidence files; "
                f"configured maximum is {max_package_files}"
            ),
        )
        return PackageLoadResult(
            "incorrect", None, (issue,), input_line, entry_id, report_id
        )

    try:
        root = Path(package_root).expanduser().resolve(strict=True)
        if not root.is_dir():
            raise NotADirectoryError(f"package root is not a directory: {root}")
    except (OSError, RuntimeError, TypeError) as error:
        issue = PackageIssue(
            "uncertain",
            "package_root_unavailable",
            "$.package",
            f"package root cannot be inspected: {error}",
        )
        return PackageLoadResult(
            "uncertain", None, (issue,), input_line, entry_id, report_id
        )

    declarations: list[tuple[str, str, str]] = [
        ("advisory", "$.package.advisory", parsed.advisory)
    ]
    declarations.extend(
        ("reference", f"$.package.references[{index}]", value)
        for index, value in enumerate(parsed.references)
    )
    declarations.extend(
        ("patch", f"$.package.patches[{index}]", value)
        for index, value in enumerate(parsed.patches)
    )

    loaded: list[LoadedEvidenceFile] = []
    issues: list[PackageIssue] = []
    consumed_bytes = 0
    for kind, field, relative_path in declarations:
        path, issue = _resolve_package_file(root, relative_path, field)
        if issue is not None:
            issues.append(issue)
            continue
        assert path is not None
        document, issue = _read_document(
            path,
            kind=kind,
            relative_path=relative_path,
            field=field,
            max_file_bytes=max_file_bytes,
            remaining_package_bytes=max_package_bytes - consumed_bytes,
        )
        if issue is not None:
            issues.append(issue)
            continue
        assert document is not None
        consumed_bytes += document.byte_size
        loaded.append(document)

    advisory = next(
        (document for document in loaded if document.kind == "advisory"), None
    )
    package = LocalEvidencePackage(
        root=root,
        spec=parsed,
        advisory=advisory,
        references=tuple(
            document for document in loaded if document.kind == "reference"
        ),
        patches=tuple(document for document in loaded if document.kind == "patch"),
    )
    return PackageLoadResult(
        _result_status(issues),
        package,
        tuple(issues),
        input_line,
        entry_id,
        report_id,
    )
