"""Unit tests for the case audit log hash chain (engine.casedb.Case)."""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.casedb import Case                                   # noqa: E402


class AuditChain(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="strata-audit-test-")
        self.addCleanup(lambda: shutil.rmtree(self._dir, ignore_errors=True))
        self.case = Case(os.path.join(self._dir, "case"), name="t",
                         examiner="tester")
        self.addCleanup(self.case.close)

    def test_new_case_starts_with_intact_chain(self):
        self.assertEqual(self.case.verify_audit(),
                         {"intact": True, "broken_at": None})

    def test_chained_entries_verify(self):
        h1 = self.case.log("test.one", {"n": 1})
        h2 = self.case.log("test.two", {"n": 2})
        h3 = self.case.log("test.three", None)
        self.assertTrue(all(hs) for hs in (h1, h2, h3))
        self.assertNotEqual(h1, h2)
        rows = list(reversed(self.case.audit(limit=10)))
        self.assertEqual([r["action"] for r in rows][-3:],
                         ["test.one", "test.two", "test.three"])
        self.assertEqual(rows[-1]["prev_hash"], rows[-2]["hash"])
        self.assertEqual(self.case.verify_audit(),
                         {"intact": True, "broken_at": None})

    def test_tampered_detail_is_detected(self):
        self.case.log("test.one", {"n": 1})
        self.case.log("test.two", {"n": 2})
        self.case.db.execute(
            "UPDATE audit SET detail=? WHERE seq=(SELECT MIN(seq) + 1 "
            "FROM audit)", ('{"tampered": true}',))
        self.case.db.commit()
        self.assertEqual(self.case.verify_audit(),
                         {"intact": False, "broken_at": 2})

    def test_tampered_last_entry_is_detected(self):
        self.case.log("test.one", {"n": 1})
        last = self.case.db.execute(
            "SELECT MAX(seq) FROM audit").fetchone()[0]
        self.case.db.execute(
            "UPDATE audit SET detail=? WHERE seq=?",
            ('{"evil": 1}', last))
        self.case.db.commit()
        self.assertEqual(self.case.verify_audit(),
                         {"intact": False, "broken_at": last})

    def test_deleted_middle_entry_breaks_chain(self):
        self.case.log("test.one", {"n": 1})
        self.case.log("test.two", {"n": 2})
        self.case.log("test.three", {"n": 3})
        self.case.db.execute(
            "DELETE FROM audit WHERE seq=(SELECT MIN(seq) + 1 FROM audit)")
        self.case.db.commit()
        result = self.case.verify_audit()
        self.assertFalse(result["intact"])


    def last_seq(self):
        return self.case.db.execute("SELECT MAX(seq) FROM audit").fetchone()[0]

    def test_entries_cut_from_the_end_are_detected(self):
        self.case.log("test.one", {"n": 1})
        self.case.log("test.two", {"n": 2})
        last = self.last_seq()
        self.case.db.execute("DELETE FROM audit WHERE seq=?", (last,))
        self.case.db.commit()
        got = self.case.verify_audit()
        self.assertFalse(got["intact"])
        self.assertEqual(got["broken_at"], last)
        self.assertIn("removed from the end", got["detail"])

    def test_truncation_stays_visible_after_more_entries(self):
        self.case.log("test.one", {"n": 1})
        self.case.log("test.two", {"n": 2})
        last = self.last_seq()
        self.case.db.execute("DELETE FROM audit WHERE seq=?", (last,))
        self.case.db.commit()
        self.case.log("test.three", {"n": 3})
        got = self.case.verify_audit()
        self.assertFalse(got["intact"])
        self.assertEqual(got["broken_at"], self.last_seq())

    def test_emptied_log_is_detected(self):
        self.case.log("test.one", {"n": 1})
        self.case.db.execute("DELETE FROM audit")
        self.case.db.commit()
        self.assertFalse(self.case.verify_audit()["intact"])

    def test_entries_appended_outside_strata_are_detected(self):
        self.case.log("test.one", {"n": 1})
        row = self.case.db.execute(
            "SELECT * FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        import hashlib
        at, ex, action, detail = "2030-01-01T00:00:00Z", "x", "forged", "{}"
        h = hashlib.sha256(("%s|%s|%s|%s|%s" % (row["hash"], at, ex, action,
                                                detail)).encode()).hexdigest()
        self.case.db.execute(
            "INSERT INTO audit (at, examiner, action, detail, prev_hash, "
            "hash) VALUES (?,?,?,?,?,?)", (at, ex, action, detail,
                                           row["hash"], h))
        self.case.db.commit()
        got = self.case.verify_audit()
        self.assertFalse(got["intact"])
        self.assertEqual(got["broken_at"], row["seq"] + 1)

    def test_case_without_a_recorded_head_still_verifies(self):
        # Cases written before the head was recorded.
        self.case.log("test.one", {"n": 1})
        self.case.db.execute("DELETE FROM meta WHERE key='audit_head'")
        self.case.db.commit()
        self.assertEqual(self.case.verify_audit(),
                         {"intact": True, "broken_at": None})
        self.case.log("test.two", {"n": 2})
        self.assertEqual(self.case.verify_audit(),
                         {"intact": True, "broken_at": None})


class KeyedAuditChain(unittest.TestCase):
    """The optional HMAC tags: forging needs the key."""

    OK = {"intact": True, "broken_at": None, "keyed": True}

    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="strata-audit-key-")
        self.addCleanup(lambda: shutil.rmtree(self._dir, ignore_errors=True))
        self.path = os.path.join(self._dir, "case")
        # Test-only filler bytes, not a real key.
        self.key = b"k" * 32
        self.case = self.open(self.key)
        self.case.log("test.one", {"n": 1})
        self.case.log("test.two", {"n": 2})
        self.case.log("test.three", {"n": 3})

    def open(self, key):
        c = Case(self.path, name="t", examiner="tester", audit_key=key)
        self.addCleanup(c.close)
        return c

    def seqs(self):
        return [r[0] for r in self.case.db.execute(
            "SELECT seq FROM audit ORDER BY seq")]

    def test_keyed_append_stores_a_tag_per_entry(self):
        n = self.case.db.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
        tags = [r[0] for r in self.case.db.execute(
            "SELECT tag FROM audit_mac")]
        self.assertEqual(len(tags), n)
        self.assertEqual(len(set(tags)), n)

    def test_keyed_verify_ok(self):
        self.assertEqual(self.case.verify_audit(), self.OK)

    def test_key_is_not_in_the_case_file(self):
        self.case.db.commit()
        with open(self.case.db_path, "rb") as fh:
            self.assertNotIn(self.key, fh.read())

    def test_tampered_entry_fails_at_that_entry(self):
        mid = self.seqs()[2]
        self.case.db.execute("UPDATE audit SET detail=? WHERE seq=?",
                             ('{"n": 99}', mid))
        self.case.db.commit()
        got = self.case.verify_audit()
        self.assertFalse(got["intact"])
        self.assertEqual(got["broken_at"], mid)

    def rebuild_unkeyed_chain(self):
        """What a forger without the key can do: redo every hash."""
        import hashlib
        prev = ""
        for r in self.case.db.execute(
                "SELECT * FROM audit ORDER BY seq").fetchall():
            h = hashlib.sha256(("%s|%s|%s|%s|%s" % (
                prev, r["at"], r["examiner"], r["action"], r["detail"])
            ).encode()).hexdigest()
            self.case.db.execute(
                "UPDATE audit SET prev_hash=?, hash=? WHERE seq=?",
                (prev, h, r["seq"]))
            prev = h
        last = self.seqs()[-1]
        self.case.db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)",
                             (Case.AUDIT_HEAD, "%d:%s" % (last, prev)))
        self.case.db.commit()

    def test_rebuilt_chain_with_edited_entry_fails(self):
        mid = self.seqs()[2]
        self.case.db.execute("UPDATE audit SET detail=? WHERE seq=?",
                             ('{"n": 99}', mid))
        self.rebuild_unkeyed_chain()
        self.assertTrue(self.case._verify_chain()["intact"])
        got = self.case.verify_audit()
        self.assertFalse(got["intact"])
        self.assertEqual(got["broken_at"], mid)

    def test_deleted_middle_entry_with_rebuilt_chain_fails(self):
        mid = self.seqs()[2]
        self.case.db.execute("DELETE FROM audit WHERE seq=?", (mid,))
        self.rebuild_unkeyed_chain()
        self.assertTrue(self.case._verify_chain()["intact"])
        got = self.case.verify_audit()
        self.assertFalse(got["intact"])
        self.assertEqual(got["broken_at"], mid + 1)

    def test_reordered_entries_fail(self):
        a, b = self.seqs()[2:4]
        self.case.db.execute("UPDATE audit_mac SET seq=-1 WHERE seq=?", (a,))
        self.case.db.execute("UPDATE audit_mac SET seq=? WHERE seq=?", (a, b))
        self.case.db.execute("UPDATE audit_mac SET seq=? WHERE seq=-1", (b,))
        self.case.db.commit()
        got = self.case.verify_audit()
        self.assertFalse(got["intact"])
        self.assertEqual(got["broken_at"], a)

    def test_stripped_early_tags_fail(self):
        first = self.seqs()[0]
        self.case.db.execute("DELETE FROM audit_mac WHERE seq<=?",
                             (first + 1,))
        self.case.db.commit()
        self.assertFalse(self.case.verify_audit()["intact"])

    def test_entry_without_a_tag_fails(self):
        last = self.seqs()[-1]
        self.case.db.execute("DELETE FROM audit_mac WHERE seq=?", (last,))
        self.case.db.commit()
        got = self.case.verify_audit()
        self.assertFalse(got["intact"])
        self.assertEqual(got["broken_at"], last)

    def test_wrong_key_fails(self):
        wrong = self.open(b"w" * 32)
        got = wrong.verify_audit()
        self.assertFalse(got["intact"])
        self.assertEqual(got["broken_at"], self.seqs()[0])
        self.assertNotIn("w" * 32, str(got))

    def test_missing_key_reports_key_needed(self):
        got = self.open(None).verify_audit()
        self.assertFalse(got["intact"])
        self.assertTrue(got["key_needed"])
        self.assertIsNone(got["broken_at"])
        self.assertIn("key needed", got["detail"])

    def test_missing_key_still_reports_a_broken_chain(self):
        mid = self.seqs()[2]
        self.case.db.execute("UPDATE audit SET detail=? WHERE seq=?",
                             ("{}", mid))
        self.case.db.commit()
        self.assertEqual(self.open(None).verify_audit()["broken_at"], mid)

    def test_logging_to_a_keyed_case_needs_the_key(self):
        from engine.casedb import AuditKeyNeeded
        with self.assertRaises(AuditKeyNeeded):
            self.open(None).log("test.four", None)

    def test_key_from_file_and_environment(self):
        keyfile = os.path.join(self._dir, "audit.key")
        with open(keyfile, "wb") as fh:
            fh.write(self.key + b"\n")
        names = ("STRATA_AUDIT_KEY", "STRATA_AUDIT_KEY_FILE")
        saved = {k: os.environ.pop(k, None) for k in names}

        def restore():
            for k in names:
                os.environ.pop(k, None)
                if saved[k] is not None:
                    os.environ[k] = saved[k]
        self.addCleanup(restore)
        os.environ["STRATA_AUDIT_KEY_FILE"] = keyfile
        self.assertEqual(self.open(None).verify_audit(), self.OK)
        del os.environ["STRATA_AUDIT_KEY_FILE"]
        os.environ["STRATA_AUDIT_KEY"] = self.key.decode()
        self.assertEqual(self.open(None).verify_audit(), self.OK)

    def test_unkeyed_log_still_verifies_with_or_without_a_key(self):
        plain = Case(os.path.join(self._dir, "plain"), name="p",
                     examiner="tester")
        self.addCleanup(plain.close)
        plain.log("test.one", {"n": 1})
        want = {"intact": True, "broken_at": None}
        self.assertEqual(plain.verify_audit(), want)
        plain._audit_key = self.key
        self.assertEqual(plain.verify_audit(), want)

    def test_key_turned_on_later_keeps_older_entries_valid(self):
        c = Case(os.path.join(self._dir, "later"), name="l",
                 examiner="tester")
        self.addCleanup(c.close)
        c.log("test.old", None)
        c._audit_key = self.key
        c.log("test.new", None)
        self.assertEqual(c.verify_audit(), self.OK)


WRITER = r"""
import sys
sys.path.insert(0, sys.argv[1])
from engine.casedb import Case
c = Case(sys.argv[2], examiner=sys.argv[3])
for i in range(int(sys.argv[4])):
    c.log("concurrent.write", {"i": i})
c.close()
"""


class ConcurrentWriters(unittest.TestCase):
    """Two Strata processes on one case folder: the in-process lock does not
    reach across them, so the chain must not fork."""

    def test_two_processes_logging_at_once_keep_one_chain(self):
        import subprocess
        d = tempfile.mkdtemp(prefix="strata-audit-mp-")
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        path = os.path.join(d, "case")
        Case(path, name="t", examiner="setup").close()
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        procs = [subprocess.Popen([sys.executable, "-c", WRITER, root, path,
                                   who, "150"])
                 for who in ("a", "b", "c")]
        for p in procs:
            self.assertEqual(p.wait(timeout=120), 0)
        case = Case(path)
        self.addCleanup(case.close)
        n = case.db.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
        self.assertEqual(n, 1 + 3 * 150)
        self.assertEqual(case.verify_audit(),
                         {"intact": True, "broken_at": None})

if __name__ == "__main__":
    unittest.main()