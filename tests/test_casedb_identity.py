"""A path is only treated as a case if it already is one (engine.casedb).

Opening or previewing something that is not a case must leave it exactly as it
was: what gets pointed at is often evidence. See issue #23.
"""

import hashlib
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import casedb                                         # noqa: E402
from engine.casedb import Case, NotACase, is_case                 # noqa: E402


def snapshot(folder):
    out = {}
    for root, dirs, files in os.walk(folder):
        for d in dirs:
            out[os.path.relpath(os.path.join(root, d), folder)] = "<dir>"
        for f in files:
            p = os.path.join(root, f)
            with open(p, "rb") as fh:
                out[os.path.relpath(p, folder)] = hashlib.sha256(
                    fh.read()).hexdigest()
    return out


def foreign_sqlite(path, wal=False):
    db = sqlite3.connect(path)
    if wal:
        db.execute("PRAGMA journal_mode=WAL")
    db.execute("CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT)")
    db.execute("INSERT INTO urls(url) VALUES ('https://example.org/')")
    db.commit()
    db.close()


class NotACaseIsLeftAlone(unittest.TestCase):
    """Every kind of non-case is refused and left byte-for-byte unchanged."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="strata-caseid-")
        self.addCleanup(lambda: shutil.rmtree(self.dir, ignore_errors=True))
        self.ev = os.path.join(self.dir, "evidence")
        os.makedirs(self.ev)

    def targets(self):
        empty = os.path.join(self.ev, "empty.bin")
        open(empty, "wb").close()

        history = os.path.join(self.ev, "History")
        foreign_sqlite(history)

        wal = os.path.join(self.ev, "History-wal-mode")
        foreign_sqlite(wal, wal=True)

        binary = os.path.join(self.ev, "disk.dd")
        with open(binary, "wb") as fh:
            fh.write(bytes(range(256)) * 256)

        named_like_case = os.path.join(self.ev, "looks-right.strata")
        foreign_sqlite(named_like_case)

        folder = os.path.join(self.ev, "folder-with-foreign-record")
        os.makedirs(folder)
        foreign_sqlite(os.path.join(folder, casedb.DB_NAME))

        return [empty, history, wal, binary, named_like_case, folder]

    def test_is_case_refuses_without_changing_anything(self):
        for target in self.targets():
            before = snapshot(self.ev)
            with self.subTest(target=os.path.basename(target)):
                self.assertFalse(is_case(target))
                self.assertEqual(snapshot(self.ev), before)

    def test_opening_refuses_without_changing_anything(self):
        for target in self.targets():
            before = snapshot(self.ev)
            with self.subTest(target=os.path.basename(target)):
                with self.assertRaises(NotACase):
                    Case(target, examiner="tester")
                self.assertEqual(snapshot(self.ev), before)

    def test_wal_database_gets_no_sibling_files(self):
        wal = os.path.join(self.ev, "History-wal-mode")
        foreign_sqlite(wal, wal=True)
        before = sorted(os.listdir(self.ev))
        self.assertFalse(is_case(wal))
        with self.assertRaises(NotACase):
            Case(wal)
        self.assertEqual(sorted(os.listdir(self.ev)), before)


class RealCasesStillWork(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="strata-caseid-")
        self.addCleanup(lambda: shutil.rmtree(self.dir, ignore_errors=True))

    def test_new_case_where_nothing_exists(self):
        path = os.path.join(self.dir, "new.strata")
        case = Case(path, name="New", examiner="tester")
        case.close()
        self.assertTrue(os.path.isfile(os.path.join(path, casedb.DB_NAME)))
        self.assertTrue(is_case(path))

    def test_new_case_in_an_existing_empty_folder(self):
        path = os.path.join(self.dir, "made-first")
        os.makedirs(path)
        Case(path, examiner="tester").close()
        self.assertTrue(is_case(path))

    def test_reopening_a_case_keeps_its_record(self):
        path = os.path.join(self.dir, "kept.strata")
        first = Case(path, name="Kept", examiner="tester")
        first.log("test.entry", {"n": 1})
        first.close()

        again = Case(path, examiner="tester")
        self.addCleanup(again.close)
        self.assertEqual(again.get("name"), "Kept")
        self.assertIn("test.entry", [r["action"] for r in again.audit()])
        self.assertTrue(again.verify_audit()["intact"])

    def test_a_folder_without_a_record_is_not_a_case(self):
        path = os.path.join(self.dir, "just-a-folder")
        os.makedirs(path)
        self.assertFalse(is_case(path))


class PreviewWritesNothing(unittest.TestCase):
    """A read-only preview serves the summary and writes nothing at all."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="strata-peekro-")
        self.addCleanup(lambda: shutil.rmtree(self.dir, ignore_errors=True))

    def build_case(self, name):
        path = os.path.join(self.dir, name)
        case = Case(path, name=name, examiner="tester")
        case.add_evidence("/images/laptop.E01",
                          {"kind": "image", "format": "E01", "size": 123},
                          label="laptop")
        case.log("test.entry", {"n": 1})
        case.close()
        return path

    def test_preview_changes_nothing(self):
        path = self.build_case("peeked.strata")
        # A case built today already has cache/ from its own rw open; strip
        # it to the legacy shape the roadmap item is about — a case folder
        # holding nothing but the record.
        shutil.rmtree(os.path.join(path, casedb.CACHE_DIR))
        before = snapshot(path)
        peek = Case(path, read_only=True)
        self.addCleanup(peek.close)
        out = peek.summary()
        self.assertEqual(out["name"], "peeked.strata")
        self.assertEqual([r["path"] for r in out["evidence"]],
                         ["/images/laptop.E01"])
        self.assertTrue(peek.verify_audit()["intact"])
        self.assertFalse(peek.fts)
        self.assertIsNone(peek.index_db)
        self.assertFalse(os.path.isdir(os.path.join(path, casedb.CACHE_DIR)))
        self.assertEqual(snapshot(path), before)

    def test_preview_does_not_upgrade_stale_schema(self):
        path = self.build_case("stale.strata")
        db = sqlite3.connect(os.path.join(path, casedb.DB_NAME))
        db.execute("ALTER TABLE evidence DROP COLUMN kind")
        db.commit()
        db.close()

        peek = Case(path, read_only=True)
        self.addCleanup(peek.close)
        self.assertEqual(len(peek.summary()["evidence"]), 1)
        peek.close()

        probe = sqlite3.connect(os.path.join(path, casedb.DB_NAME))
        peek_cols = {r[1] for r in probe.execute(
            "PRAGMA table_info(evidence)")}
        probe.close()
        self.assertNotIn("kind", peek_cols)

    def test_plain_open_still_migrates(self):
        path = self.build_case("regress.strata")
        db = sqlite3.connect(os.path.join(path, casedb.DB_NAME))
        db.execute("ALTER TABLE evidence DROP COLUMN kind")
        db.commit()
        db.close()

        case = Case(path, examiner="tester")
        self.addCleanup(case.close)
        cols = {r[1] for r in case.db.execute(
            "PRAGMA table_info(evidence)")}
        self.assertIn("kind", cols)
        self.assertEqual(case.summary()["evidence"][0]["kind"], "image")

    def test_preview_works_on_a_read_only_folder(self):
        path = self.build_case("locked.strata")
        before = snapshot(path)

        def restore():
            os.chmod(path, 0o755)
        self.addCleanup(restore)
        os.chmod(path, 0o555)

        peek = Case(path, read_only=True)
        out = peek.summary()
        self.assertTrue(peek.verify_audit()["intact"])
        peek.close()
        os.chmod(path, 0o755)
        self.assertEqual(snapshot(path), before)


if __name__ == "__main__":
    unittest.main()
