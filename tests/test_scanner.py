from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from kgov.policy import Policy
from kgov.scanner import scan


def snapshot(root: Path) -> dict:
    result = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        info = path.lstat()
        if path.is_symlink():
            result[relative] = {"link": os.readlink(path), "mode": stat.S_IMODE(info.st_mode)}
        elif path.is_file():
            result[relative] = {
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "mode": stat.S_IMODE(info.st_mode),
            }
    return result


class ScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.vault = self.base / "vault"
        self.out = self.base / "private-output"
        (self.vault / "notes").mkdir(parents=True)
        (self.vault / "assets").mkdir()
        (self.vault / "raw").mkdir()
        (self.vault / "runtime").mkdir()
        (self.vault / "assets" / "image.png").write_bytes(b"synthetic-image")
        (self.vault / "notes" / "Target.md").write_text(
            "---\ntags: [demo]\nowner: example\n---\n# Section\nSafe synthetic content.\n",
            encoding="utf-8",
        )
        (self.vault / "notes" / "Home.md").write_text(
            "---\ntags: [demo]\nowner: example\n---\n# Home\n"
            "[[Target#Section]]\n[[Missing]]\n![image](../assets/image.png)\n"
            "[outside](/private/company/file.md)\n"
            "`[[FakeInline]]`\n```text\n[[FakeFence]]\n```\n",
            encoding="utf-8",
        )
        duplicate = b"---\ntags: [demo]\nowner: example\n---\n# Duplicate\n"
        (self.vault / "notes" / "Dup-A.md").write_bytes(duplicate)
        (self.vault / "notes" / "Dup-B.md").write_bytes(duplicate)
        (self.vault / "raw" / "source.md").write_text("RAW_PRIVATE_SENTINEL [[NeverParsed]]", encoding="utf-8")
        (self.vault / "runtime" / "state.db").write_bytes(b"DATABASE_PRIVATE_SENTINEL")
        (self.vault / "api-secret.txt").write_text("SECRET_VALUE_SENTINEL", encoding="utf-8")
        self.policy = Policy(require_frontmatter=True, required_frontmatter_keys=("tags", "owner"))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_scan(self, suffix: str = "run") -> dict:
        return scan(self.vault, self.out / "cache.json", self.out / f"{suffix}.json", self.policy)

    def test_read_only_links_duplicates_and_privacy(self) -> None:
        before = snapshot(self.vault)
        report = self.run_scan()
        after = snapshot(self.vault)
        self.assertEqual(before, after)
        self.assertTrue(report["complete"])
        self.assertTrue(report["provenance"]["sourceWrites"] is False)
        self.assertTrue(report["provenance"]["bodyPersisted"] is False)
        statuses = report["summary"]["linkStatuses"]
        self.assertEqual(statuses["ok"], 2)
        self.assertEqual(statuses["missing"], 1)
        self.assertEqual(statuses["absolute_path_outside"], 1)
        self.assertEqual(report["summary"]["duplicateGroups"], 1)
        self.assertNotIn("runtime/state.db", report["files"])
        self.assertNotIn("api-secret.txt", report["files"])
        self.assertNotIn("markdown", report["files"]["raw/source.md"])
        persisted = (self.out / "run.json").read_text() + (self.out / "cache.json").read_text()
        for forbidden in ["RAW_PRIVATE_SENTINEL", "DATABASE_PRIVATE_SENTINEL", "SECRET_VALUE_SENTINEL", "FakeInline", "FakeFence"]:
            self.assertNotIn(forbidden, persisted)
        self.assertEqual(stat.S_IMODE((self.out / "run.json").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.out / "cache.json").stat().st_mode), 0o600)

    def test_incremental_cache_and_policy_binding(self) -> None:
        first = self.run_scan("first")
        second = self.run_scan("second")
        self.assertGreater(first["summary"]["hashedFiles"], 0)
        self.assertEqual(second["summary"]["hashedFiles"], 0)
        self.assertEqual(second["summary"]["cacheReusedFiles"], second["summary"]["files"])
        alternate = Policy(require_frontmatter=False)
        third = scan(self.vault, self.out / "cache.json", self.out / "third.json", alternate)
        self.assertFalse(third["provenance"]["cacheBindingMatched"])
        self.assertEqual(third["summary"]["cacheReusedFiles"], 0)

    def test_target_only_change_refreshes_link_resolution(self) -> None:
        first = self.run_scan("before-target")
        self.assertEqual(first["summary"]["linkStatuses"]["missing"], 1)
        (self.vault / "notes" / "Missing.md").write_text("---\ntags: [demo]\nowner: example\n---\n# Missing\n", encoding="utf-8")
        second = self.run_scan("after-target")
        self.assertEqual(second["summary"]["linkStatuses"].get("missing", 0), 0)
        self.assertGreaterEqual(second["summary"]["linkStatuses"]["ok"], 3)
        self.assertTrue(second["files"]["notes/Home.md"]["cacheReused"])

    def test_report_and_cache_inside_source_are_refused(self) -> None:
        with self.assertRaisesRegex(ValueError, "ARTIFACT_INSIDE_SOURCE_REFUSED"):
            scan(self.vault, self.vault / "cache.json", self.out / "report.json", self.policy)
        with self.assertRaisesRegex(ValueError, "ARTIFACT_INSIDE_SOURCE_REFUSED"):
            scan(self.vault, self.out / "cache.json", self.vault / "report.json", self.policy)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_symlink_is_not_followed(self) -> None:
        outside = self.base / "outside.md"
        outside.write_text("OUTSIDE_PRIVATE_SENTINEL", encoding="utf-8")
        (self.vault / "notes" / "outside-link.md").symlink_to(outside)
        report = self.run_scan("symlink")
        self.assertNotIn("notes/outside-link.md", report["files"])
        persisted = (self.out / "symlink.json").read_text()
        self.assertNotIn("OUTSIDE_PRIVATE_SENTINEL", persisted)
        self.assertTrue(any(item["reason"] == "symlink" for item in report["skips"]))


if __name__ == "__main__":
    unittest.main()

