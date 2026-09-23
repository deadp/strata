"""A caller that has only a filesystem handle -- not a full listdir() entry
-- must still get a correctly read, correctly recorded export. The bulk
"export tagged items" action in the UI is the one in-app case: a tagged
item is stored by handle (engine.casedb tagged_items), and the client used
to send only part/node/name/path, dropping deleted/modified/... on the way
back to engine.server._export_one.

Issue #85 (carried roadmap item): the export manifest's `modified` came out
blank for a node-only export. Following it further: engine.fs.fat.FatFS
(and ext4) read a *deleted* entry differently from a live one, so dropping
`deleted` the same way did not just leave a manifest field blank -- it read
a deleted, fragmented FAT file as if it were live, silently truncating it
to its first cluster.

Issue #94: exFAT's actual read-path branch is `contiguous`, not `deleted`
-- a NoFatChain stream is read by extent rather than by walking the FAT.
`tagged_items` never captured it, so a tagged deleted contiguous exFAT file
had the same silent-truncation problem even after #91.
"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import imagebuild_fat as build                                    # noqa: E402
from test_fs_fat import ImageFiles, by_name, open_first_volume     # noqa: E402
from engine import casedb, server                                  # noqa: E402


class FakeCase:
    """The two Case members _export_one touches, without a real case db."""
    examiner = "tester"

    def __init__(self):
        self.logged = []

    def log(self, action, detail=None):
        self.logged.append((action, detail))


class FakeSession:
    def __init__(self):
        self.case = FakeCase()


class ExportByNodeAlone(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.files = ImageFiles()
        cls.image = cls.files.open(build.build_fat(16))
        cls.layout, cls.part, cls.fs = open_first_volume(cls.image)
        cls.root = by_name(cls.fs.listdir(0))

    @classmethod
    def tearDownClass(cls):
        cls.files.close()

    def setUp(self):
        self.out_dir = tempfile.mkdtemp(prefix="strata-export-test-")
        self.addCleanup(shutil.rmtree, self.out_dir, ignore_errors=True)
        self.session = FakeSession()

    def test_entry_from_body_carries_metadata_through(self):
        e = self.root["_ELETED.TXT"]
        body = {"node": e["start_cluster"], "name": e["name"],
               "path": e["path"], "size": e["size"], "deleted": True,
               "modified": e["modified"], "accessed": e["accessed"],
               "created": e["created"]}
        got = server._entry_from_body(self.fs, body)
        self.assertEqual(got["start_cluster"], e["start_cluster"])
        self.assertEqual(got["size"], e["size"])
        self.assertTrue(got["deleted"])
        self.assertEqual(got["modified"], e["modified"])
        self.assertEqual(got["accessed"], e["accessed"])
        self.assertEqual(got["created"], e["created"])

    def test_deleted_flag_missing_reads_live_and_truncates(self):
        # What the bulk export used to send: no deleted flag at all. Kept as
        # a regression guard on _entry_from_body's default, not a defence of
        # this behaviour -- it silently truncates a deleted, fragmented FAT
        # file to its first cluster, exactly the bug #85 led to.
        e = self.root["_ELETED.TXT"]
        body = {"node": e["start_cluster"], "name": e["name"],
               "path": e["path"], "size": e["size"]}
        entry = server._entry_from_body(self.fs, body)
        self.assertFalse(entry["deleted"])
        rec, path, written = server._export_one(
            self.fs, entry, self.out_dir, self.session, manifest=False)
        self.assertLess(written, e["size"])
        self.assertIsNone(rec["modified"])

    def test_deleted_flag_forwarded_exports_full_content(self):
        e = self.root["_ELETED.TXT"]
        body = {"node": e["start_cluster"], "name": e["name"],
               "path": e["path"], "size": e["size"], "deleted": True,
               "modified": e["modified"]}
        entry = server._entry_from_body(self.fs, body)
        rec, path, written = server._export_one(
            self.fs, entry, self.out_dir, self.session, manifest=False)
        self.assertEqual(written, e["size"])
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(), self.fs.read_file(e))
        self.assertEqual(rec["modified"], e["modified"])
        self.assertTrue(rec["deleted"])


class ExfatContiguousByNodeAlone(unittest.TestCase):
    """exFAT's actual read-path branch is `contiguous`, not `deleted` --
    engine.fs.exfat.ExfatFS.runs() walks the FAT unless told the stream is
    NoFatChain. A NoFatChain stream's FAT entries are left zero by real
    drivers, so walking it stops after one cluster (issue #94)."""

    @classmethod
    def setUpClass(cls):
        cls.files = ImageFiles()
        cls.image = cls.files.open(build.build_exfat())
        cls.layout, cls.part, cls.fs = open_first_volume(cls.image)
        cls.root = by_name(cls.fs.listdir(0))

    @classmethod
    def tearDownClass(cls):
        cls.files.close()

    def setUp(self):
        self.out_dir = tempfile.mkdtemp(prefix="strata-export-test-")
        self.addCleanup(shutil.rmtree, self.out_dir, ignore_errors=True)
        self.session = FakeSession()

    def deleted_contiguous_entry(self):
        # Contiguous.dat is not itself deleted; a tagged deleted NoFatChain
        # stream reads identically once past directory metadata, so this
        # combination -- its real, multi-cluster, FAT-entries-left-zero
        # extent with `deleted` set -- is exactly issue #94's shape.
        return dict(self.root["Contiguous.dat"], deleted=True)

    def test_contiguous_flag_missing_reads_fat_walk_and_truncates(self):
        e = self.deleted_contiguous_entry()
        body = {"node": e["start_cluster"], "name": e["name"],
               "path": e["path"], "size": e["size"], "deleted": True}
        entry = server._entry_from_body(self.fs, body)
        self.assertFalse(entry["contiguous"])
        rec, path, written = server._export_one(
            self.fs, entry, self.out_dir, self.session, manifest=False)
        self.assertLess(written, e["size"])

    def test_contiguous_flag_forwarded_exports_full_content(self):
        e = self.deleted_contiguous_entry()
        body = {"node": e["start_cluster"], "name": e["name"],
               "path": e["path"], "size": e["size"], "deleted": True,
               "contiguous": True}
        entry = server._entry_from_body(self.fs, body)
        self.assertTrue(entry["contiguous"])
        rec, path, written = server._export_one(
            self.fs, entry, self.out_dir, self.session, manifest=False)
        self.assertEqual(written, e["size"])
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(), self.fs.read_file(e))


class TaggedItemsContiguousColumn(unittest.TestCase):
    """The other half of #94: tag_item() has to capture `contiguous` for
    there to be anything for the export path to forward."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="strata-tag-contiguous-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.case = casedb.Case(os.path.join(self.dir, "c.strata"),
                                examiner="tester")
        self.addCleanup(self.case.close)
        self.ev = self.case.add_evidence("/img.E01", {"kind": "image"})

    def test_contiguous_true_is_stored_and_returned(self):
        item = {"start_cluster": 10, "path": "/Contiguous.dat",
               "name": "Contiguous.dat", "size": 3000, "deleted": True,
               "contiguous": True}
        self.case.tag_item(self.ev, item, "reviewed")
        got = self.case.tagged(self.ev)
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["contiguous"], 1)

    def test_contiguous_absent_stores_null_not_false(self):
        # A FAT/NTFS/ext4 item never carries this key; storing it as False
        # rather than unknown would be its own quiet lie.
        item = {"mft": 5, "path": "/a.txt", "name": "a.txt", "size": 10}
        self.case.tag_item(self.ev, item, "reviewed")
        got = self.case.tagged(self.ev)
        self.assertIsNone(got[0]["contiguous"])

    def test_migration_adds_column_to_an_older_case(self):
        path = os.path.join(self.dir, "old.strata")
        case = casedb.Case(path, examiner="tester")
        case.db.execute("ALTER TABLE tagged_items DROP COLUMN contiguous")
        case.db.commit()
        case.close()

        reopened = casedb.Case(path, examiner="tester")
        self.addCleanup(reopened.close)
        cols = {r[1] for r in
               reopened.db.execute("PRAGMA table_info(tagged_items)")}
        self.assertIn("contiguous", cols)


if __name__ == "__main__":
    unittest.main()
