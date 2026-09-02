"""Safely provision the fixed replay-authoring Ed25519 trust registry.

The command has three deliberately narrow operations:

* ``generate-slot`` creates one independent private key and its public
  registration;
* ``assemble-registry`` combines exactly six registrations in the protocol's
  fixed slot order; and
* ``verify-slot`` checks one private key against an externally double-pinned
  registry.

Private key bytes are never serialized as JSON or written to a terminal.
"""

from __future__ import annotations

import argparse
from contextlib import AbstractContextManager, ExitStack
import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any, Final, Literal, Sequence, cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vulngym_agent.replay_authoring_receipt import (
    ReplayAuthoringReceiptError,
    ReplayTrustKeyRegistrationV2,
    ReplayTrustRegistryV2,
    _DirectoryGuard,
    _WindowsDirectoryLocks,
    _assert_directory_guard,
    _file_binding_identity,
    _file_identity,
    _guard_directory_chain,
    _is_reparse,
    read_pinned_trust_registry_v2,
    replay_ed25519_public_key_from_private_v2,
)
from vulngym_agent.trusted_inputs import zero_secret_buffer_v1


REPLAY_TRUST_REGISTRY_CLI_VERSION: Final[str] = (
    "replay-trust-registry-cli-v2"
)
EXIT_SUCCESS: Final[int] = 0
EXIT_REJECTED: Final[int] = 2
EXIT_COMMITTED_UNCERTAIN: Final[int] = 11
EXIT_INTERRUPTED: Final[int] = 130

Purpose = Literal[
    "actor-approval", "readback-attestation", "authoring-index"
]
Role = Literal["author", "critic", "reviewer", "test", "train", "global"]

TRUST_KEY_SLOTS: Final[tuple[tuple[Purpose, Role], ...]] = (
    ("actor-approval", "author"),
    ("actor-approval", "critic"),
    ("actor-approval", "reviewer"),
    ("readback-attestation", "test"),
    ("readback-attestation", "train"),
    ("authoring-index", "global"),
)
_PURPOSES: Final[tuple[str, ...]] = tuple(
    dict.fromkeys(purpose for purpose, _role in TRUST_KEY_SLOTS)
)
_ROLES: Final[tuple[str, ...]] = tuple(
    dict.fromkeys(role for _purpose, role in TRUST_KEY_SLOTS)
)
_ED25519_PRIVATE_KEY_BYTES: Final[int] = 32
_MAX_REGISTRATION_BYTES: Final[int] = 4 * 1024
_MAX_REGISTRY_BYTES: Final[int] = 64 * 1024
_SHA256_HEX: Final[frozenset[str]] = frozenset("0123456789abcdef")


class ReplayTrustRegistryCliError(RuntimeError):
    """Stable, path-free provisioning rejection."""

    def __init__(
        self, code: str, message: str, *, committed: bool = False
    ) -> None:
        self.code = code if type(code) is str and code else "provisioning_failed"
        self.committed = bool(committed)
        super().__init__(message)


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        _ = message
        self.exit(EXIT_REJECTED, "error: trust registry arguments rejected\n")


def _sha256(value: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in _SHA256_HEX for character in value)
    ):
        raise argparse.ArgumentTypeError(
            "digest must be 64 lower-case hexadecimal characters"
        )
    return value


def _add_slot_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--purpose", choices=_PURPOSES, required=True)
    parser.add_argument("--role", choices=_ROLES, required=True)
    parser.add_argument("--key-id", required=True)


def _add_registry_pin_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--trust-registry-file", type=Path, required=True)
    parser.add_argument(
        "--expected-trust-registry-sha256", type=_sha256, required=True
    )
    parser.add_argument(
        "--expected-trust-registry-wire-sha256", type=_sha256, required=True
    )


def _parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(
        prog="python -m vulngym_agent.replay_trust_registry_cli",
        description=(
            "Provision and verify the six fixed Ed25519 trust-registry slots."
        ),
        allow_abbrev=False,
    )
    commands = parser.add_subparsers(dest="command", required=True)

    generate = commands.add_parser(
        "generate-slot",
        help="generate one private key and one separate public registration",
        allow_abbrev=False,
    )
    _add_slot_arguments(generate)
    generate.add_argument("--private-key-file", type=Path, required=True)
    generate.add_argument("--registration-file", type=Path, required=True)

    assemble = commands.add_parser(
        "assemble-registry",
        help="assemble six ordered public registrations without replacement",
        allow_abbrev=False,
    )
    assemble.add_argument(
        "--registration-file",
        dest="registration_files",
        action="append",
        type=Path,
        required=True,
        help=(
            "repeat exactly six times in author, critic, reviewer, test, "
            "train, global slot order"
        ),
    )
    assemble.add_argument("--registry-file", type=Path, required=True)

    verify = commands.add_parser(
        "verify-slot",
        help="match one private key to one requested slot in a pinned registry",
        allow_abbrev=False,
    )
    _add_slot_arguments(verify)
    verify.add_argument("--private-key-file", type=Path, required=True)
    _add_registry_pin_arguments(verify)
    return parser


def _canonical_line(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
    except (RecursionError, TypeError, UnicodeError, ValueError):
        raise ReplayTrustRegistryCliError(
            "noncanonical_json", "provisioning value is not canonical JSON"
        ) from None


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise ReplayTrustRegistryCliError(
                "noncanonical_json", "registration repeats an object key"
            )
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ReplayTrustRegistryCliError(
        "noncanonical_json", "registration contains a non-finite number"
    )


def _parse_registration(payload: bytes) -> ReplayTrustKeyRegistrationV2:
    if (
        type(payload) is not bytes
        or not payload
        or len(payload) > _MAX_REGISTRATION_BYTES
        or not payload.endswith(b"\n")
        or payload.count(b"\n") != 1
    ):
        raise ReplayTrustRegistryCliError(
            "noncanonical_json", "registration must be one bounded JSON line"
        )
    try:
        raw = json.loads(
            payload[:-1].decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except ReplayTrustRegistryCliError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise ReplayTrustRegistryCliError(
            "noncanonical_json", "registration is not strict JSON"
        ) from None
    if type(raw) is not dict or _canonical_line(raw) != payload:
        raise ReplayTrustRegistryCliError(
            "noncanonical_json", "registration is not canonical"
        )
    return ReplayTrustKeyRegistrationV2.from_dict(raw)


def _absolute_file_path(path: Path) -> Path:
    if not isinstance(path, Path):
        raise ReplayTrustRegistryCliError(
            "invalid_argument", "provisioning path type is invalid"
        )
    result = Path(os.path.abspath(os.fspath(path)))
    if not result.name or result.name in {".", ".."}:
        raise ReplayTrustRegistryCliError(
            "invalid_argument", "provisioning file path is invalid"
        )
    return result


def _path_identity(path: Path) -> str:
    return os.path.normcase(os.path.normpath(os.path.abspath(os.fspath(path))))


def _directory_handle_identity(value: os.stat_result) -> tuple[int, int, int]:
    return (value.st_dev, value.st_ino, value.st_mode)


class _SafeParent(AbstractContextManager["_SafeParent"]):
    """Pin a non-reparse output/input parent for one bounded operation."""

    def __init__(self, path: Path, *, private: bool) -> None:
        self.path = _absolute_file_path(path / "placeholder").parent
        self.private = private
        self.guard: _DirectoryGuard | None = None
        self.descriptor: int | None = None
        self.windows_locks = _WindowsDirectoryLocks(self.path)

    def _check_private_parent(self) -> None:
        if not self.private or os.name != "posix":
            return
        try:
            state = os.lstat(self.path)
        except OSError:
            raise ReplayTrustRegistryCliError(
                "input_unavailable", "private key directory is unavailable"
            ) from None
        if (
            state.st_uid != os.geteuid()
            or stat.S_IMODE(state.st_mode) & 0o077
        ):
            raise ReplayTrustRegistryCliError(
                "unsafe_path", "private key directory is not owner-only"
            )

    def __enter__(self) -> "_SafeParent":
        try:
            self.windows_locks.acquire()
            self.guard = _guard_directory_chain(
                self.path, final_private=self.private
            )
            self._check_private_parent()
            if os.name == "posix":
                flags = (
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0)
                )
                self.descriptor = os.open(self.path, flags)
                opened = os.fstat(self.descriptor)
                if (
                    self.guard is None
                    or _directory_handle_identity(opened)
                    != self.guard.chain[-1][1]
                ):
                    raise ReplayTrustRegistryCliError(
                        "input_changed", "provisioning directory changed"
                    )
            self.assert_stable()
            return self
        except BaseException:
            self.close()
            raise

    def assert_stable(self) -> None:
        if self.guard is None:
            raise ReplayTrustRegistryCliError(
                "invalid_argument", "provisioning directory is not guarded"
            )
        _assert_directory_guard(self.guard, final_private=self.private)
        self._check_private_parent()
        if self.descriptor is not None:
            opened = os.fstat(self.descriptor)
            if _directory_handle_identity(opened) != self.guard.chain[-1][1]:
                raise ReplayTrustRegistryCliError(
                    "input_changed", "provisioning directory changed"
                )

    def open(self, name: str, flags: int, mode: int | None = None) -> int:
        if type(name) is not str or not name or Path(name).name != name:
            raise ReplayTrustRegistryCliError(
                "invalid_argument", "provisioning filename is invalid"
            )
        try:
            if self.descriptor is not None:
                if mode is None:
                    return os.open(name, flags, dir_fd=self.descriptor)
                return os.open(name, flags, mode, dir_fd=self.descriptor)
            target = self.path / name
            if mode is None:
                return os.open(target, flags)
            return os.open(target, flags, mode)
        except FileExistsError:
            raise ReplayTrustRegistryCliError(
                "output_exists", "provisioning output already exists"
            ) from None
        except OSError:
            raise ReplayTrustRegistryCliError(
                "input_unavailable", "provisioning file could not be opened"
            ) from None

    def lstat(self, name: str) -> os.stat_result:
        try:
            if self.descriptor is not None:
                return os.stat(
                    name, dir_fd=self.descriptor, follow_symlinks=False
                )
            return os.lstat(self.path / name)
        except OSError:
            raise ReplayTrustRegistryCliError(
                "input_unavailable", "provisioning file is unavailable"
            ) from None

    def require_absent(self, name: str) -> None:
        try:
            if self.descriptor is not None:
                os.stat(name, dir_fd=self.descriptor, follow_symlinks=False)
            else:
                os.lstat(self.path / name)
        except FileNotFoundError:
            return
        except OSError:
            raise ReplayTrustRegistryCliError(
                "input_unavailable", "provisioning output could not be checked"
            ) from None
        raise ReplayTrustRegistryCliError(
            "output_exists", "provisioning output already exists"
        )

    def unlink(self, name: str) -> None:
        if self.descriptor is not None:
            os.unlink(name, dir_fd=self.descriptor)
        else:
            os.unlink(self.path / name)

    def fsync(self) -> None:
        if self.descriptor is not None:
            os.fsync(self.descriptor)

    def close(self) -> None:
        if self.descriptor is not None:
            os.close(self.descriptor)
            self.descriptor = None
        self.windows_locks.close()

    def __exit__(self, *exc: object) -> None:
        self.close()


def _same_object(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _validate_regular_file(
    state: os.stat_result,
    *,
    minimum_bytes: int,
    maximum_bytes: int,
    private: bool,
) -> None:
    if (
        not stat.S_ISREG(state.st_mode)
        or stat.S_ISLNK(state.st_mode)
        or _is_reparse(state)
        or state.st_nlink != 1
        or not minimum_bytes <= state.st_size <= maximum_bytes
    ):
        raise ReplayTrustRegistryCliError(
            "unsafe_path", "provisioning input is not a stable regular file"
        )
    if os.name == "posix" and (
        (private and state.st_uid != os.geteuid())
        or (private and stat.S_IMODE(state.st_mode) & 0o077)
        or (not private and stat.S_IMODE(state.st_mode) & 0o022)
    ):
        raise ReplayTrustRegistryCliError(
            "unsafe_path", "provisioning input permissions are unsafe"
        )


def _read_descriptor(descriptor: int, *, maximum_bytes: int) -> bytearray:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
    except OSError:
        raise ReplayTrustRegistryCliError(
            "input_unavailable", "provisioning input could not be positioned"
        ) from None
    result = bytearray()
    while True:
        remaining = maximum_bytes + 1 - len(result)
        if remaining <= 0:
            raise ReplayTrustRegistryCliError(
                "limit_exceeded", "provisioning input is too large"
            )
        try:
            chunk = os.read(descriptor, min(remaining, 4096))
        except OSError:
            zero_secret_buffer_v1(result)
            raise ReplayTrustRegistryCliError(
                "input_unavailable", "provisioning input could not be read"
            ) from None
        if not chunk:
            return result
        result.extend(chunk)


def _read_stable_regular(
    path: Path,
    *,
    minimum_bytes: int,
    maximum_bytes: int,
    private: bool,
) -> bytearray:
    target = _absolute_file_path(path)
    with _SafeParent(target.parent, private=private) as parent:
        before = parent.lstat(target.name)
        _validate_regular_file(
            before,
            minimum_bytes=minimum_bytes,
            maximum_bytes=maximum_bytes,
            private=private,
        )
        descriptor = parent.open(
            target.name,
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        payload: bytearray | None = None
        try:
            opened = os.fstat(descriptor)
            _validate_regular_file(
                opened,
                minimum_bytes=minimum_bytes,
                maximum_bytes=maximum_bytes,
                private=private,
            )
            if _file_binding_identity(opened) != _file_binding_identity(before):
                raise ReplayTrustRegistryCliError(
                    "input_changed", "provisioning input changed while opening"
                )
            payload = _read_descriptor(descriptor, maximum_bytes=maximum_bytes)
            finished = os.fstat(descriptor)
            if (
                _file_identity(finished) != _file_identity(opened)
                or len(payload) != opened.st_size
            ):
                raise ReplayTrustRegistryCliError(
                    "input_changed", "provisioning input changed while reading"
                )
        except BaseException:
            zero_secret_buffer_v1(payload)
            try:
                os.close(descriptor)
            except BaseException:
                pass
            raise
        try:
            os.close(descriptor)
        except BaseException:
            zero_secret_buffer_v1(payload)
            raise
        try:
            parent.assert_stable()
            after = parent.lstat(target.name)
            if _file_identity(after) != _file_identity(before):
                raise ReplayTrustRegistryCliError(
                    "input_changed", "provisioning input changed after reading"
                )
        except BaseException:
            zero_secret_buffer_v1(payload)
            raise
        if payload is None:
            raise ReplayTrustRegistryCliError(
                "input_unavailable", "provisioning input was not read"
            )
        return payload


def _unlink_created(
    parent: _SafeParent, name: str, expected: os.stat_result
) -> None:
    try:
        observed = parent.lstat(name)
        if (
            not _same_object(observed, expected)
            or not stat.S_ISREG(observed.st_mode)
            or _is_reparse(observed)
            or observed.st_nlink != 1
        ):
            raise ReplayTrustRegistryCliError(
                "publication_uncertain",
                "created output identity is uncertain",
                committed=True,
            )
        parent.unlink(name)
        parent.fsync()
        parent.assert_stable()
    except ReplayTrustRegistryCliError:
        raise
    except OSError:
        raise ReplayTrustRegistryCliError(
            "publication_uncertain",
            "created output could not be removed",
            committed=True,
        ) from None


def _write_exclusive(
    parent: _SafeParent,
    target: Path,
    payload: bytes | bytearray,
    *,
    private: bool,
    mutation_state: list[bool] | None = None,
) -> os.stat_result:
    if type(payload) not in (bytes, bytearray) or not payload:
        raise ReplayTrustRegistryCliError(
            "invalid_argument", "provisioning payload is invalid"
        )
    parent.require_absent(target.name)
    descriptor = parent.open(
        target.name,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    created = os.fstat(descriptor)
    try:
        if (
            not stat.S_ISREG(created.st_mode)
            or _is_reparse(created)
            or created.st_nlink != 1
            or created.st_size != 0
        ):
            raise ReplayTrustRegistryCliError(
                "unsafe_path", "new provisioning output is unsafe"
            )
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        offset = 0
        with memoryview(payload) as view:
            while offset < len(view):
                try:
                    written = os.write(descriptor, view[offset:])
                except InterruptedError:
                    continue
                if written <= 0:
                    raise ReplayTrustRegistryCliError(
                        "output_failed", "provisioning output write failed"
                    )
                offset += written
        os.fsync(descriptor)
        finished = os.fstat(descriptor)
        _validate_regular_file(
            finished,
            minimum_bytes=len(payload),
            maximum_bytes=len(payload),
            private=private,
        )
        os.lseek(descriptor, 0, os.SEEK_SET)
        # O_WRONLY descriptors cannot be read back.  The named-file readback
        # below is performed after this descriptor is closed.
    except BaseException:
        try:
            os.close(descriptor)
        except BaseException:
            pass
        try:
            _unlink_created(parent, target.name, created)
        except ReplayTrustRegistryCliError as cleanup_error:
            raise cleanup_error from None
        raise
    try:
        os.close(descriptor)
    except BaseException:
        try:
            _unlink_created(parent, target.name, created)
        except ReplayTrustRegistryCliError as cleanup_error:
            raise cleanup_error from None
        raise
    try:
        parent.fsync()
        parent.assert_stable()
        named = parent.lstat(target.name)
        _validate_regular_file(
            named,
            minimum_bytes=len(payload),
            maximum_bytes=len(payload),
            private=private,
        )
        if not _same_object(named, finished):
            raise ReplayTrustRegistryCliError(
                "input_changed", "provisioning output changed after writing"
            )
        readback = _read_stable_regular(
            target,
            minimum_bytes=len(payload),
            maximum_bytes=len(payload),
            private=private,
        )
        try:
            if not hmac.compare_digest(readback, payload):
                raise ReplayTrustRegistryCliError(
                    "input_changed", "provisioning output readback differs"
                )
        finally:
            zero_secret_buffer_v1(readback)
        if mutation_state is not None:
            mutation_state[0] = True
        return named
    except BaseException:
        try:
            _unlink_created(parent, target.name, finished)
        except ReplayTrustRegistryCliError as cleanup_error:
            raise cleanup_error from None
        raise


def _checked_slot(purpose: str, role: str) -> tuple[Purpose, Role]:
    candidate = (purpose, role)
    if candidate not in TRUST_KEY_SLOTS:
        raise ReplayTrustRegistryCliError(
            "invalid_slot", "trust key purpose and role do not form a slot"
        )
    return cast(tuple[Purpose, Role], candidate)


def _registration_summary(
    registration: ReplayTrustKeyRegistrationV2, payload: bytes
) -> dict[str, str]:
    return {
        "public_key_fingerprint": registration.public_key_fingerprint,
        "registration_wire_sha256": hashlib.sha256(payload).hexdigest(),
    }


def _registry_summary(registry: ReplayTrustRegistryV2) -> dict[str, object]:
    return {
        "public_key_fingerprints": [
            item.public_key_fingerprint for item in registry.keys
        ],
        "registry_sha256": registry.registry_sha256,
        "registry_wire_sha256": registry.wire_sha256,
    }


def _run_generate(
    args: argparse.Namespace, *, mutation_state: list[bool] | None = None
) -> dict[str, str]:
    purpose, role = _checked_slot(args.purpose, args.role)
    private_path = _absolute_file_path(args.private_key_file)
    registration_path = _absolute_file_path(args.registration_file)
    if _path_identity(private_path) == _path_identity(registration_path):
        raise ReplayTrustRegistryCliError(
            "invalid_argument", "private and public outputs must be separate"
        )
    secret: bytearray | None = None
    generated: Ed25519PrivateKey | None = None
    with ExitStack() as stack:
        private_parent = stack.enter_context(
            _SafeParent(private_path.parent, private=True)
        )
        registration_parent = stack.enter_context(
            _SafeParent(registration_path.parent, private=False)
        )
        private_parent.require_absent(private_path.name)
        registration_parent.require_absent(registration_path.name)
        private_state: os.stat_result | None = None
        try:
            generated = Ed25519PrivateKey.generate()
            secret = bytearray(
                generated.private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                )
            )
            if len(secret) != _ED25519_PRIVATE_KEY_BYTES:
                raise ReplayTrustRegistryCliError(
                    "invalid_key", "generated Ed25519 key has invalid length"
                )
            public_key = generated.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            generated = None
            registration = ReplayTrustKeyRegistrationV2.from_public_key(
                purpose=purpose,
                role=role,
                key_id=args.key_id,
                public_key=public_key,
            )
            registration_payload = _canonical_line(registration.to_dict())
            summary = _registration_summary(registration, registration_payload)
            private_state = _write_exclusive(
                private_parent, private_path, secret, private=True
            )
            try:
                _write_exclusive(
                    registration_parent,
                    registration_path,
                    registration_payload,
                    private=False,
                    mutation_state=mutation_state,
                )
            except BaseException:
                if private_state is not None:
                    _unlink_created(
                        private_parent, private_path.name, private_state
                    )
                raise
            return summary
        finally:
            generated = None
            zero_secret_buffer_v1(secret)


def _run_assemble(
    args: argparse.Namespace, *, mutation_state: list[bool] | None = None
) -> dict[str, object]:
    if type(args.registration_files) is not list or len(args.registration_files) != 6:
        raise ReplayTrustRegistryCliError(
            "registration_set_mismatch",
            "exactly six ordered registration files are required",
        )
    registration_paths = tuple(
        _absolute_file_path(path) for path in args.registration_files
    )
    if len({_path_identity(path) for path in registration_paths}) != 6:
        raise ReplayTrustRegistryCliError(
            "registration_set_mismatch", "registration files must be distinct"
        )
    registry_path = _absolute_file_path(args.registry_file)
    if _path_identity(registry_path) in {
        _path_identity(path) for path in registration_paths
    }:
        raise ReplayTrustRegistryCliError(
            "invalid_argument", "registry output must be separate"
        )
    with _SafeParent(registry_path.parent, private=False) as output_parent:
        output_parent.require_absent(registry_path.name)
        registrations: list[ReplayTrustKeyRegistrationV2] = []
        for expected, path in zip(TRUST_KEY_SLOTS, registration_paths):
            payload = _read_stable_regular(
                path,
                minimum_bytes=1,
                maximum_bytes=_MAX_REGISTRATION_BYTES,
                private=False,
            )
            try:
                registration = _parse_registration(bytes(payload))
            finally:
                zero_secret_buffer_v1(payload)
            if (registration.purpose, registration.role) != expected:
                raise ReplayTrustRegistryCliError(
                    "slot_mismatch", "registration is in the wrong fixed slot"
                )
            registrations.append(registration)
        registry = ReplayTrustRegistryV2(keys=tuple(registrations))
        registry_payload = registry.to_bytes()
        if len(registry_payload) > _MAX_REGISTRY_BYTES:
            raise ReplayTrustRegistryCliError(
                "limit_exceeded", "trust registry is too large"
            )
        summary = _registry_summary(registry)
        _write_exclusive(
            output_parent,
            registry_path,
            registry_payload,
            private=False,
            mutation_state=mutation_state,
        )
    return summary


def _run_verify(args: argparse.Namespace) -> dict[str, object]:
    purpose, role = _checked_slot(args.purpose, args.role)
    registry = read_pinned_trust_registry_v2(
        args.trust_registry_file,
        expected_sha256=args.expected_trust_registry_sha256,
        expected_wire_sha256=args.expected_trust_registry_wire_sha256,
    )
    registration = registry.registration(purpose=purpose, role=role)
    if not hmac.compare_digest(registration.key_id, args.key_id):
        raise ReplayTrustRegistryCliError(
            "slot_mismatch", "requested key ID is not registered in the slot"
        )
    secret: bytearray | None = None
    try:
        secret = _read_stable_regular(
            args.private_key_file,
            minimum_bytes=1,
            maximum_bytes=_ED25519_PRIVATE_KEY_BYTES,
            private=True,
        )
        if len(secret) != _ED25519_PRIVATE_KEY_BYTES:
            raise ReplayTrustRegistryCliError(
                "invalid_key", "Ed25519 private key must contain exactly 32 bytes"
            )
        observed_public = replay_ed25519_public_key_from_private_v2(secret)
        if not hmac.compare_digest(
            observed_public, registration.public_key_bytes
        ):
            raise ReplayTrustRegistryCliError(
                "key_fingerprint_mismatch",
                "private key does not match the requested registered slot",
            )
        return _registry_summary(registry)
    finally:
        zero_secret_buffer_v1(secret)


def _write_stdout(value: dict[str, object] | dict[str, str]) -> None:
    payload = _canonical_line(value)
    binary = getattr(sys.stdout, "buffer", None)
    if binary is not None:
        binary.write(payload)
        binary.flush()
    else:
        sys.stdout.write(payload.decode("utf-8", errors="strict"))
        sys.stdout.flush()


def _write_error(code: str) -> None:
    try:
        sys.stderr.write(
            f"error[{code}]: trust registry provisioning failed\n"
        )
        sys.stderr.flush()
    except BaseException:
        pass


def main(argv: Sequence[str] | None = None) -> int:
    mutation_state = [False]
    try:
        args = _parser().parse_args(argv)
        if args.command == "generate-slot":
            result: dict[str, object] | dict[str, str] = _run_generate(
                args, mutation_state=mutation_state
            )
        elif args.command == "assemble-registry":
            result = _run_assemble(args, mutation_state=mutation_state)
        else:
            result = _run_verify(args)
        _write_stdout(result)
    except KeyboardInterrupt:
        if mutation_state[0]:
            _write_error("publication_uncertain")
            return EXIT_COMMITTED_UNCERTAIN
        _write_error("interrupted")
        return EXIT_INTERRUPTED
    except ReplayTrustRegistryCliError as error:
        if mutation_state[0] or error.committed:
            _write_error("publication_uncertain")
            return EXIT_COMMITTED_UNCERTAIN
        _write_error(error.code)
        return EXIT_REJECTED
    except ReplayAuthoringReceiptError as error:
        if mutation_state[0]:
            _write_error("publication_uncertain")
            return EXIT_COMMITTED_UNCERTAIN
        _write_error(error.code)
        return EXIT_REJECTED
    except Exception:
        if mutation_state[0]:
            _write_error("publication_uncertain")
            return EXIT_COMMITTED_UNCERTAIN
        _write_error("input_rejected")
        return EXIT_REJECTED
    except SystemExit:
        if mutation_state[0]:
            _write_error("publication_uncertain")
            return EXIT_COMMITTED_UNCERTAIN
        raise
    except BaseException:
        if mutation_state[0]:
            _write_error("publication_uncertain")
            return EXIT_COMMITTED_UNCERTAIN
        _write_error("interrupted")
        return EXIT_INTERRUPTED
    return EXIT_SUCCESS


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "EXIT_COMMITTED_UNCERTAIN",
    "EXIT_INTERRUPTED",
    "EXIT_REJECTED",
    "EXIT_SUCCESS",
    "REPLAY_TRUST_REGISTRY_CLI_VERSION",
    "ReplayTrustRegistryCliError",
    "TRUST_KEY_SLOTS",
    "main",
]
