from __future__ import annotations

from hashlib import sha256
import unittest

from vulngym_agent.analyzers import (
    PatchFormatError,
    PatchLimitExceeded,
    UnsafePatchPath,
    analyze_patch,
    compare_patch_sources,
)
from vulngym_agent.evidence import LoadedEvidenceFile
from vulngym_agent.tools.git import TextFileDiff


MODIFIED_PATCH = """diff --git a/src/app.py b/src/app.py
index 1111111..2222222 100644
--- a/src/app.py
+++ b/src/app.py
@@ -10,3 +10,5 @@ def run(value):
-    return eval(value)
+    if not is_safe(value):
+        return None
+    return parse(value)
     # retained
     done()
"""

MULTI_FILE_PATCH = """diff --git a/old.txt b/new.txt
similarity index 95%
rename from old.txt
rename to new.txt
--- a/old.txt
+++ b/new.txt
@@ -1 +1 @@
-old
+new
diff --git a/gone.c b/gone.c
deleted file mode 100644
--- a/gone.c
+++ /dev/null
@@ -1,2 +0,0 @@
-strcpy(dst, src);
-return 1;
diff --git a/created.py b/created.py
new file mode 100644
--- /dev/null
+++ b/created.py
@@ -0,0 +1 @@
+assert allowed
"""


def local_patch(text: str, path: str = "patches/fix.patch") -> LoadedEvidenceFile:
    data = text.encode("utf-8")
    return LoadedEvidenceFile("patch", path, text, len(data), sha256(data).hexdigest())


def git_patch(
    text: str = MODIFIED_PATCH,
    *,
    path: str = "src/app.py",
    added: int = 3,
    removed: int = 1,
    before_exists: bool = True,
    after_exists: bool = True,
) -> TextFileDiff:
    return TextFileDiff(
        before_commit="1" * 40,
        after_commit="2" * 40,
        path=path,
        before_exists=before_exists,
        after_exists=after_exists,
        before_blob_id="3" * 40 if before_exists else None,
        after_blob_id="4" * 40 if after_exists else None,
        added_lines=added,
        deleted_lines=removed,
        unified_diff=text,
    )


class PatchAnalyzerTests(unittest.TestCase):
    def test_parses_lines_coordinates_and_conservative_candidates(self) -> None:
        result = analyze_patch(local_patch(MODIFIED_PATCH))

        self.assertEqual(result.source_kind, "local")
        self.assertFalse(result.semantic_verified)
        self.assertEqual(result.fact_status, "correct")
        self.assertEqual(result.semantic_status, "uncertain")
        self.assertEqual(len(result.files), 1)
        changed = result.files[0]
        self.assertEqual(changed.old_path, "src/app.py")
        self.assertEqual(changed.new_path, "src/app.py")
        self.assertEqual(changed.change_kind, "modified")
        self.assertEqual((changed.added_lines, changed.removed_lines), (3, 1))
        self.assertEqual(
            [line.old_line for line in changed.hunks[0].lines],
            [10, None, None, None, 11, 12],
        )
        self.assertEqual(
            [line.new_line for line in changed.hunks[0].lines],
            [None, 10, 11, 12, 13, 14],
        )
        self.assertEqual(len(result.guard_candidates), 3)
        self.assertEqual(len(result.early_return_candidates), 2)
        self.assertEqual(len(result.removed_dangerous_calls), 1)
        self.assertIn(
            ("guard", "removed", 10, "    return eval(value)"),
            {
                (
                    item.mode,
                    item.change_kind,
                    item.old_line,
                    item.code,
                )
                for item in result.guard_candidates
            },
        )
        self.assertIn(
            ("guard", "context", 11, "    # retained"),
            {
                (
                    item.mode,
                    item.change_kind,
                    item.old_line,
                    item.code,
                )
                for item in result.guard_candidates
            },
        )
        self.assertTrue(all(not item.semantic_verified for item in result.candidates))
        self.assertIn("semantic role unverified", result.removed_dangerous_calls[0].reason)

    def test_sanitizer_replacement_yields_old_side_guard_anchor(self) -> None:
        patch = """diff --git a/src/render.ts b/src/render.ts
index 1111111..2222222 100644
--- a/src/render.ts
+++ b/src/render.ts
@@ -20,3 +20,3 @@ export function render(text: string) {
-  const html = marked.parse(text)
+  const html = DOMPurify.sanitize(marked.parse(text))
   return html
 }
"""

        result = analyze_patch(local_patch(patch))

        self.assertIn(
            ("guard", "removed", 20),
            {
                (item.mode, item.change_kind, item.old_line)
                for item in result.guard_candidates
            },
        )
        self.assertTrue(
            all(
                item.change_kind != "added" or item.old_line is None
                for item in result.guard_candidates
            )
        )

    def test_assert_namespace_alias_yields_guard_context_anchor(self) -> None:
        patch = """diff --git a/src/form.ts b/src/form.ts
index 1111111..2222222 100644
--- a/src/form.ts
+++ b/src/form.ts
@@ -1,4 +1,6 @@
+import * as a from "node:assert";
 export function handle(req: Request) {
   const body = readBody(req)
+  a.ok(req.headers.get("content-type"))
   return body
 }
"""

        result = analyze_patch(local_patch(patch))

        self.assertIn(
            ("guard", "context", 2),
            {
                (item.mode, item.change_kind, item.old_line)
                for item in result.guard_candidates
            },
        )
        self.assertTrue(
            all(
                item.change_kind != "added" or item.old_line is None
                for item in result.guard_candidates
            )
        )

    def test_multifile_rename_add_delete_and_candidate_ids_are_stable(self) -> None:
        result = analyze_patch(local_patch(MULTI_FILE_PATCH))

        self.assertEqual(
            [(item.path, item.change_kind) for item in result.files],
            [("new.txt", "renamed"), ("gone.c", "deleted"), ("created.py", "added")],
        )
        self.assertEqual(
            [item.candidate_id for item in result.candidates],
            ["patch-candidate-000001", "patch-candidate-000002"],
        )
        self.assertEqual(
            [(item.mode, item.file) for item in result.candidates],
            [("dangerous_call", "gone.c"), ("guard", "created.py")],
        )

    def test_pure_rename_without_hunks(self) -> None:
        patch = """diff --git a/a.txt b/b.txt
similarity index 100%
rename from a.txt
rename to b.txt
"""
        changed = analyze_patch(local_patch(patch)).files[0]
        self.assertEqual(changed.change_kind, "renamed")
        self.assertEqual((changed.old_path, changed.new_path), ("a.txt", "b.txt"))
        self.assertEqual(changed.hunks, ())

    def test_binary_patch_is_explicitly_uncertain_and_not_scanned(self) -> None:
        patch = """diff --git a/image.png b/image.png
index 1111111..2222222 100644
Binary files a/image.png and b/image.png differ
"""
        result = analyze_patch(local_patch(patch))
        self.assertTrue(result.files[0].binary)
        self.assertEqual(result.files[0].change_kind, "binary")
        self.assertEqual(result.candidates, ())
        self.assertIn("binary_content_not_analyzed", {i.code for i in result.uncertainties})

    def test_git_binary_payload_is_bounded_but_not_interpreted_as_code(self) -> None:
        patch = """diff --git a/image.png b/image.png
GIT binary patch
literal 3
KcmZQzU|?Vb00001
"""
        result = analyze_patch(local_patch(patch))
        self.assertTrue(result.files[0].binary)
        self.assertFalse(result.candidates)

    def test_rejects_malformed_hunk_header_and_counts(self) -> None:
        bad_header = "--- a/x\n+++ b/x\n@@ nonsense @@\n"
        with self.assertRaises(PatchFormatError):
            analyze_patch(local_patch(bad_header))

        bad_count = "--- a/x\n+++ b/x\n@@ -1,2 +1,1 @@\n-old\n+new\n"
        with self.assertRaises(PatchFormatError):
            analyze_patch(local_patch(bad_count))

    def test_rejects_path_traversal_absolute_drive_and_option_paths(self) -> None:
        paths = (
            "../escape.py",
            "/absolute.py",
            "C:/windows.py",
            "-dangerous",
        )
        for path in paths:
            with self.subTest(path=path), self.assertRaises(UnsafePatchPath):
                analyze_patch(
                    local_patch(f"--- a/ok.py\n+++ b/{path}\n@@ -1 +1 @@\n-a\n+b\n")
                )
        with self.assertRaises(UnsafePatchPath):
            analyze_patch(
                local_patch('diff --git "a/src\\app.py" "b/src\\app.py"\n')
            )

    def test_all_limits_are_enforced(self) -> None:
        cases = (
            ({"max_chars": len(MODIFIED_PATCH) - 1}, MODIFIED_PATCH),
            ({"max_lines": 2}, MODIFIED_PATCH),
            ({"max_files": 0}, MODIFIED_PATCH),
            ({"max_hunks": 0}, MODIFIED_PATCH),
            ({"max_hunk_lines": 1}, MODIFIED_PATCH),
            ({"max_candidates": 0}, MODIFIED_PATCH),
        )
        for kwargs, patch in cases:
            with self.subTest(kwargs=kwargs), self.assertRaises(PatchLimitExceeded):
                analyze_patch(local_patch(patch), **kwargs)

    def test_invalid_bounds_and_non_patch_evidence_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            analyze_patch(local_patch(MODIFIED_PATCH), max_lines=-1)
        advisory = LoadedEvidenceFile("advisory", "a.json", "{}", 2, "0" * 64)
        with self.assertRaises(TypeError):
            analyze_patch(advisory)

    def test_git_text_diff_is_checked_against_its_structured_facts(self) -> None:
        result = analyze_patch(git_patch())
        self.assertEqual(result.source_kind, "git")
        self.assertFalse(result.conflicts)

        mismatch = analyze_patch(git_patch(path="other.py", added=99))
        self.assertEqual(mismatch.fact_status, "incorrect")
        self.assertEqual(
            {item.code for item in mismatch.conflicts},
            {"git_diff_path_disagrees", "git_diff_counts_disagree"},
        )
        self.assertEqual(result.fact_status, "correct")

    def test_difflib_single_file_shape_without_diff_git_is_supported(self) -> None:
        text = """--- a/src/app.py
+++ b/src/app.py
@@ -1 +1,2 @@
-return eval(value)
+if valid(value):
+    return parse(value)
"""
        result = analyze_patch(git_patch(text, added=2, removed=1))
        self.assertEqual(len(result.files), 1)
        self.assertEqual(result.files[0].path, "src/app.py")
        self.assertFalse(result.conflicts)
        self.assertEqual(
            {item.mode for item in result.candidates},
            {"dangerous_call", "guard", "early_return"},
        )

    def test_empty_unchanged_git_diff_is_explicitly_uncertain(self) -> None:
        source = TextFileDiff(
            before_commit="1" * 40,
            after_commit="2" * 40,
            path="src/app.py",
            before_exists=True,
            after_exists=True,
            before_blob_id="3" * 40,
            after_blob_id="3" * 40,
            added_lines=0,
            deleted_lines=0,
            unified_diff="",
        )
        result = analyze_patch(source)
        self.assertEqual(result.files, ())
        self.assertFalse(result.conflicts)
        self.assertEqual(
            {item.code for item in result.uncertainties},
            {"no_unified_diff", "unchanged_git_file"},
        )
        self.assertEqual(result.fact_status, "uncertain")

    def test_git_endpoints_must_agree_with_dev_null_headers(self) -> None:
        text = """--- /dev/null
+++ b/src/app.py
@@ -0,0 +1 @@
+safe = True
"""
        mismatch = analyze_patch(git_patch(text, added=1, removed=0))
        self.assertIn(
            "git_before_endpoint_disagrees",
            {item.code for item in mismatch.conflicts},
        )

    def test_identical_local_and_git_sources_are_corroborated_not_verified(self) -> None:
        result = compare_patch_sources(local_patch(MODIFIED_PATCH), git_patch())
        self.assertEqual(result.corroborated_files, ("src/app.py",))
        self.assertFalse(result.conflicts)
        self.assertFalse(result.semantic_verified)

    def test_local_and_git_source_disagreement_is_a_conflict(self) -> None:
        local = MODIFIED_PATCH.replace("parse(value)", "parse_strict(value)")
        result = analyze_patch(local_patch(local), git_diff=git_patch())
        self.assertIn("patch_sources_disagree", {item.code for item in result.conflicts})
        self.assertFalse(result.corroborated_files)

    def test_header_path_disagreement_is_preserved_as_conflict(self) -> None:
        patch = MODIFIED_PATCH.replace("+++ b/src/app.py", "+++ b/src/other.py")
        result = analyze_patch(local_patch(patch))
        self.assertIn("path_headers_disagree", {item.code for item in result.conflicts})

    def test_no_diff_is_uncertain_not_successful_semantic_evidence(self) -> None:
        result = analyze_patch(local_patch("mail preamble only\n"))
        self.assertEqual(result.files, ())
        self.assertEqual({i.code for i in result.uncertainties}, {"no_unified_diff"})
        self.assertFalse(result.semantic_verified)


if __name__ == "__main__":
    unittest.main()
