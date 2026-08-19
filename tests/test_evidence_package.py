from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import vulngym_agent.evidence.package as evidence_package_module
from vulngym_agent.evidence import (
    DEFAULT_MAX_PACKAGE_FILES,
    HARD_MAX_PACKAGE_FILES,
    LocalEvidencePackage,
    PackageSpec,
    load_evidence_package,
)


class EvidencePackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_bytes(self, relative_path: str, data: bytes) -> Path:
        path = self.root.joinpath(*relative_path.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def test_loads_bounded_utf8_material_and_preserves_input_correlation(self) -> None:
        advisory = b"\xef\xbb\xbfGHSA body"
        self.write_bytes("advisory/item.md", advisory)
        self.write_bytes("references/pr.md", "参考".encode("utf-8"))
        self.write_bytes("patches/fix.patch", b"- unsafe\n+ safe\n")

        result = load_evidence_package(
            self.root,
            {
                "advisory": "advisory/item.md",
                "references": ["references/pr.md"],
                "patches": ["patches/fix.patch"],
            },
            max_package_files=3,
            input_line=7,
            entry_id="entry-00007",
            report_id="GHSA-1111-2222-3333",
        )

        self.assertEqual(result.status, "correct")
        self.assertTrue(result.complete)
        self.assertTrue(result.usable)
        self.assertEqual(result.input_line, 7)
        self.assertEqual(result.entry_id, "entry-00007")
        self.assertEqual(result.report_id, "GHSA-1111-2222-3333")
        assert result.package is not None
        assert result.package.advisory is not None
        self.assertEqual(result.package.advisory.text, "GHSA body")
        self.assertEqual(result.package.advisory.byte_size, len(advisory))
        self.assertEqual(result.package.advisory.sha256, sha256(advisory).hexdigest())
        self.assertEqual(len(result.package.references), 1)
        self.assertEqual(len(result.package.patches), 1)
        serialized = result.to_dict()
        self.assertNotIn(str(self.root), str(serialized))
        self.assertNotIn("text", serialized["package"]["advisory"])
        self.assertEqual(
            result.to_dict(include_text=True)["package"]["advisory"]["text"],
            "GHSA body",
        )

    def test_optional_arrays_may_be_omitted(self) -> None:
        self.write_bytes("advisory.md", b"body")

        result = LocalEvidencePackage.load(
            self.root, {"advisory": "advisory.md"}
        )

        self.assertEqual(result.status, "correct")
        assert result.package is not None
        self.assertEqual(result.package.spec.references, ())
        self.assertEqual(result.package.spec.patches, ())

    def test_package_file_limit_is_checked_before_any_filesystem_access(self) -> None:
        filesystem_access = AssertionError("package root must not be inspected")
        with (
            mock.patch.object(Path, "resolve", side_effect=filesystem_access),
            mock.patch.object(Path, "lstat", side_effect=filesystem_access),
            mock.patch.object(Path, "stat", side_effect=filesystem_access),
            mock.patch.object(Path, "open", side_effect=filesystem_access),
        ):
            result = load_evidence_package(
                self.root / "not-inspected",
                {
                    "advisory": "advisory.md",
                    "references": ["one.md", "two.md"],
                    "patches": ["one.patch", "two.patch"],
                },
                max_package_files=4,
                input_line=8,
                entry_id="entry-00008",
                report_id="GHSA-1111-2222-3333",
            )

        self.assertEqual(result.status, "incorrect")
        self.assertIsNone(result.package)
        self.assertEqual(result.input_line, 8)
        self.assertEqual(result.entry_id, "entry-00008")
        self.assertEqual(result.report_id, "GHSA-1111-2222-3333")
        self.assertEqual(result.issues[0].code, "package_file_limit_exceeded")
        self.assertIn("5 evidence files", result.issues[0].message)
        self.assertIn("maximum is 4", result.issues[0].message)

    def test_package_file_limit_parameter_is_positive_and_hard_bounded(self) -> None:
        for value in (True, 0, -1, HARD_MAX_PACKAGE_FILES + 1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                load_evidence_package(
                    self.root,
                    {"advisory": "advisory.md"},
                    max_package_files=value,
                )
        self.assertEqual(DEFAULT_MAX_PACKAGE_FILES, 64)
        self.assertEqual(HARD_MAX_PACKAGE_FILES, 256)

    def test_package_spec_constructor_enforces_the_path_contract(self) -> None:
        spec = PackageSpec(
            "advisory.md", ("references/one.md",), ("patches/fix.patch",)
        )
        self.assertEqual(spec.to_dict()["advisory"], "advisory.md")
        with self.assertRaises(ValueError):
            PackageSpec("../outside.md")
        with self.assertRaises(ValueError):
            PackageSpec("advisory.md", "references/not-an-array.md")

    def test_malformed_specs_are_structured_incorrect_results(self) -> None:
        cases = (
            (None, "package_spec_type"),
            ({}, "package_missing_advisory"),
            ({"advisory": 4}, "package_field_type"),
            ({"advisory": "a", "references": "r"}, "package_field_type"),
            ({"advisory": "a", "repo_path": "repo"}, "package_extra_field"),
            (
                {"advisory": "a", "patches": ["p", 2]},
                "package_field_type",
            ),
        )
        for value, code in cases:
            with self.subTest(value=value):
                result = load_evidence_package(self.root, value)
                self.assertEqual(result.status, "incorrect")
                self.assertIsNone(result.package)
                self.assertIn(code, {issue.code for issue in result.issues})

    def test_rejects_noncanonical_or_unsafe_relative_paths(self) -> None:
        paths_and_codes = (
            ("", "path_empty"),
            ("/absolute.md", "path_absolute"),
            ("C:/absolute.md", "path_drive"),
            ("../outside.md", "path_traversal"),
            ("refs/../outside.md", "path_traversal"),
            ("refs\\file.md", "path_not_posix"),
            ("refs//file.md", "path_not_canonical"),
            ("refs/./file.md", "path_not_canonical"),
            ("refs/file\x00.md", "path_control_character"),
            ("refs/file:stream", "path_invalid_character"),
        )
        for path, code in paths_and_codes:
            with self.subTest(path=repr(path)):
                result = load_evidence_package(self.root, {"advisory": path})
                self.assertEqual(result.status, "incorrect")
                self.assertEqual(result.issues[0].code, code)

    def test_duplicate_paths_are_rejected_before_reading(self) -> None:
        self.write_bytes("same.md", b"body")
        result = load_evidence_package(
            self.root,
            {"advisory": "same.md", "references": ["same.md"]},
        )
        self.assertEqual(result.status, "incorrect")
        self.assertEqual(result.issues[0].code, "package_duplicate_path")
        self.assertIsNone(result.package)

    def test_missing_required_advisory_is_uncertain_not_an_exception(self) -> None:
        result = load_evidence_package(
            self.root,
            {"advisory": "missing.md"},
            input_line=3,
        )
        self.assertEqual(result.status, "uncertain")
        self.assertFalse(result.usable)
        self.assertEqual(result.input_line, 3)
        self.assertEqual(result.issues[0].code, "file_missing")

    def test_missing_optional_file_keeps_loaded_advisory(self) -> None:
        self.write_bytes("advisory.md", b"body")
        result = load_evidence_package(
            self.root,
            {"advisory": "advisory.md", "patches": ["missing.patch"]},
        )
        self.assertEqual(result.status, "uncertain")
        self.assertTrue(result.usable)
        assert result.package is not None
        self.assertEqual(result.package.advisory.text, "body")
        self.assertEqual(result.issues[0].code, "file_missing")

    def test_directory_is_a_structured_contract_error(self) -> None:
        (self.root / "advisory").mkdir()
        result = load_evidence_package(
            self.root, {"advisory": "advisory"}
        )
        self.assertEqual(result.status, "incorrect")
        self.assertEqual(result.issues[0].code, "not_regular_file")

    def test_non_utf8_file_is_uncertain(self) -> None:
        self.write_bytes("advisory.md", b"\xff\xfe")
        result = load_evidence_package(
            self.root, {"advisory": "advisory.md"}
        )
        self.assertEqual(result.status, "uncertain")
        self.assertEqual(result.issues[0].code, "file_not_utf8")

    def test_per_file_limit_is_checked_before_content_read(self) -> None:
        path = self.write_bytes("advisory.md", b"12345")
        with mock.patch.object(Path, "open", side_effect=AssertionError("must not read")):
            result = load_evidence_package(
                self.root,
                {"advisory": "advisory.md"},
                max_file_bytes=4,
            )
        self.assertEqual(path.stat().st_size, 5)
        self.assertEqual(result.status, "uncertain")
        self.assertEqual(result.issues[0].code, "file_too_large")

    def test_total_limit_keeps_earlier_material_and_marks_later_file(self) -> None:
        self.write_bytes("advisory.md", b"1234")
        self.write_bytes("patch.patch", b"5678")
        result = load_evidence_package(
            self.root,
            {"advisory": "advisory.md", "patches": ["patch.patch"]},
            max_file_bytes=8,
            max_package_bytes=6,
        )
        self.assertEqual(result.status, "uncertain")
        self.assertTrue(result.usable)
        assert result.package is not None
        self.assertEqual(result.package.total_bytes, 4)
        self.assertEqual(result.issues[0].code, "package_too_large")

    def test_read_permission_or_io_failure_is_structured(self) -> None:
        self.write_bytes("advisory.md", b"body")
        with mock.patch.object(Path, "open", side_effect=PermissionError("denied")):
            result = load_evidence_package(
                self.root, {"advisory": "advisory.md"}
            )
        self.assertEqual(result.status, "uncertain")
        self.assertEqual(result.issues[0].code, "file_read_error")

    def test_file_swap_between_stat_and_open_is_not_read(self) -> None:
        self.write_bytes("advisory.md", b"body")
        real_fstat = os.fstat

        def changed_identity(file_descriptor: int) -> os.stat_result:
            value = list(real_fstat(file_descriptor))
            value[1] += 1
            return os.stat_result(value)

        with mock.patch("vulngym_agent.evidence.package.os.fstat", changed_identity):
            result = load_evidence_package(
                self.root, {"advisory": "advisory.md"}
            )
        self.assertEqual(result.status, "uncertain")
        self.assertEqual(result.issues[0].code, "file_changed")

    def test_ancestor_swap_after_validation_is_rejected_before_read(self) -> None:
        trusted_directory = self.root / "nested"
        trusted_directory.mkdir()
        trusted_file = trusted_directory / "advisory.md"
        trusted_file.write_bytes(b"trusted")
        replacement_directory = self.root / "replacement"
        replacement_directory.mkdir()
        try:
            os.link(trusted_file, replacement_directory / "advisory.md")
        except OSError:
            self.skipTest("hard-link creation is unavailable")
        parked_directory = self.root / "nested.original"
        swapped = False
        real_resolver = evidence_package_module._resolve_package_file
        real_path_open = Path.open

        def swap_after_validation(
            root: Path, relative_path: str, field: str
        ) -> tuple[object | None, object | None]:
            nonlocal swapped
            resolved = real_resolver(root, relative_path, field)
            if not swapped and resolved[0] is not None:
                trusted_directory.rename(parked_directory)
                replacement_directory.rename(trusted_directory)
                file_descriptor = os.open(
                    trusted_directory / "advisory.md",
                    os.O_WRONLY | os.O_TRUNC | getattr(os, "O_BINARY", 0),
                )
                try:
                    os.write(file_descriptor, b"hostile")
                finally:
                    os.close(file_descriptor)
                swapped = True
            return resolved

        test_case = self

        class ReadTrap:
            def __init__(self, stream: object) -> None:
                self.stream = stream

            def fileno(self) -> int:
                return self.stream.fileno()  # type: ignore[attr-defined,no-any-return]

            def close(self) -> None:
                self.stream.close()  # type: ignore[attr-defined]

            def __enter__(self) -> "ReadTrap":
                return self

            def __exit__(self, *args: object) -> None:
                self.close()

            def read(self, *args: object) -> bytes:
                test_case.fail("replacement content must not be read")

        def trap_path_read(path: Path, *args: object, **kwargs: object) -> object:
            stream = real_path_open(path, *args, **kwargs)
            if path == trusted_directory / "advisory.md":
                return ReadTrap(stream)
            return stream

        try:
            with (
                mock.patch.object(
                    evidence_package_module,
                    "_resolve_package_file",
                    side_effect=swap_after_validation,
                ),
                mock.patch.object(Path, "open", new=trap_path_read),
                mock.patch.object(
                    os,
                    "fdopen",
                    side_effect=AssertionError(
                        "replacement content must not be opened for reading"
                    ),
                ),
            ):
                result = load_evidence_package(
                    self.root, {"advisory": "nested/advisory.md"}
                )
        finally:
            if swapped:
                trusted_directory.rename(replacement_directory)
                parked_directory.rename(trusted_directory)

        self.assertEqual(result.status, "uncertain")
        self.assertFalse(result.usable)
        self.assertEqual(result.issues[0].code, "file_changed")

    def test_missing_package_root_is_structured(self) -> None:
        result = load_evidence_package(
            self.root / "missing-root", {"advisory": "advisory.md"}
        )
        self.assertEqual(result.status, "uncertain")
        self.assertIsNone(result.package)
        self.assertEqual(result.issues[0].code, "package_root_unavailable")

    def test_symlink_cannot_escape_package_root(self) -> None:
        outside_directory = tempfile.TemporaryDirectory()
        self.addCleanup(outside_directory.cleanup)
        outside = Path(outside_directory.name) / "outside.md"
        outside.write_bytes(b"outside")
        link = self.root / "advisory.md"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation is unavailable")

        result = load_evidence_package(
            self.root, {"advisory": "advisory.md"}
        )
        self.assertEqual(result.status, "incorrect")
        self.assertEqual(result.issues[0].code, "path_link_disallowed")

    def test_linked_directory_is_rejected_even_if_target_is_inside_root(self) -> None:
        real = self.root / "real"
        real.mkdir()
        (real / "advisory.md").write_bytes(b"body")
        link = self.root / "linked"
        try:
            link.symlink_to(real, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("directory symlink creation is unavailable")

        result = load_evidence_package(
            self.root, {"advisory": "linked/advisory.md"}
        )
        self.assertEqual(result.status, "incorrect")
        self.assertEqual(result.issues[0].code, "path_link_disallowed")

    def test_junction_or_reparse_point_is_rejected(self) -> None:
        self.write_bytes("advisory.md", b"body")
        with mock.patch.object(os.path, "isjunction", return_value=True):
            result = load_evidence_package(
                self.root, {"advisory": "advisory.md"}
            )
        self.assertEqual(result.status, "incorrect")
        self.assertEqual(result.issues[0].code, "path_link_disallowed")


if __name__ == "__main__":
    unittest.main()
