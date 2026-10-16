import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import casedb                                         # noqa: E402


def insert_hash(case, evidence_id, part, node, sha256, name="f", path="/f"):
    case.db.execute(
        "INSERT INTO file_hashes (evidence_id, part, node, path, name, size, "
        "deleted, md5, sha1, sha256, read_bytes, computed_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (evidence_id, part, node, path, name, 10, 0, "0" * 32, "0" * 40,
         sha256, 10, "2026-01-01T00:00:00Z"))
    case.db.commit()


class DuplicateFiles(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.case = casedb.Case(os.path.join(self.tmp, "case.strata"),
                                name="t", examiner="ci")

    def tearDown(self):
        self.case.close()

    def test_a_digest_seen_in_two_items_is_reported(self):
        insert_hash(self.case, 1, 0, "5", "a" * 64, "evil.exe", "/evil.exe")
        insert_hash(self.case, 2, 0, "9", "a" * 64, "copy.exe", "/copy.exe")
        out = self.case.duplicate_files()
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["sha256"], "a" * 64)
        paths = {it["path"] for it in out[0]["items"]}
        self.assertEqual(paths, {"/evil.exe", "/copy.exe"})
        evidence_ids = {it["evidence_id"] for it in out[0]["items"]}
        self.assertEqual(evidence_ids, {1, 2})

    def test_a_digest_only_within_one_item_is_not_reported(self):
        insert_hash(self.case, 1, 0, "5", "b" * 64, path="/a")
        insert_hash(self.case, 1, 0, "6", "b" * 64, path="/b")
        self.assertEqual(self.case.duplicate_files(), [])

    def test_a_unique_digest_is_not_reported(self):
        insert_hash(self.case, 1, 0, "5", "c" * 64, path="/only")
        self.assertEqual(self.case.duplicate_files(), [])

    def test_largest_group_comes_first(self):
        insert_hash(self.case, 1, 0, "1", "d" * 64, path="/d1")
        insert_hash(self.case, 2, 0, "2", "d" * 64, path="/d2")
        insert_hash(self.case, 1, 0, "3", "e" * 64, path="/e1")
        insert_hash(self.case, 2, 0, "4", "e" * 64, path="/e2")
        insert_hash(self.case, 3, 0, "5", "e" * 64, path="/e3")
        out = self.case.duplicate_files()
        self.assertEqual(len(out), 2)
        self.assertEqual(out[0]["sha256"], "e" * 64)
        self.assertEqual(len(out[0]["items"]), 3)
        self.assertEqual(out[1]["sha256"], "d" * 64)
        self.assertEqual(len(out[1]["items"]), 2)

    def test_a_missing_or_empty_digest_is_never_grouped(self):
        insert_hash(self.case, 1, 0, "1", "", path="/nohash1")
        insert_hash(self.case, 2, 0, "2", "", path="/nohash2")
        self.assertEqual(self.case.duplicate_files(), [])


if __name__ == "__main__":
    unittest.main()
