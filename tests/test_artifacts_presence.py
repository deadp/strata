import unittest

from engine import artifacts


class FakeFs:

    def __init__(self, tree):
        self.tree = tree

    def listdir(self, node, path):
        return self.tree.get(node, [])


def d(node, name):
    return {"name": name, "is_dir": True, "mft": node}


def f(name):
    return {"name": name, "is_dir": False}


def build_fs():
    tree = {
        0: [d(1, "$Recycle.Bin"), d(2, "Windows"), d(3, "Users")],
        1: [d(4, "S-1-5-21-abc")],
        4: [f("$I1a2b3c"), f("$R1a2b3c"),   # a complete pair
            f("$Ideadbeef")],               # an orphaned $I with no $R
        2: [d(5, "Prefetch")],
        5: [f("CHROME.EXE-ABC123.pf"), f("NOTEPAD.EXE-XYZ.pf"),
            f("notes.txt"), d(99, "subdir")],
        3: [d(6, "Alice"), d(7, "Public"), d(8, "Default")],
        6: [d(9, "AppData")],
        9: [d(10, "Local"), d(14, "Roaming")],
        10: [d(11, "Google")],
        11: [d(12, "Chrome")],
        12: [d(13, "User Data")],
        13: [],
        14: [d(15, "Mozilla")],
        15: [d(16, "Firefox")],
        16: [d(17, "Profiles")],
        17: [],
        7: [], 8: [],
    }
    return FakeFs(tree)


class RecycleBinPresence(unittest.TestCase):

    def test_counts_distinct_items_across_paired_and_orphaned_entries(self):
        r = artifacts.presence_recyclebin(build_fs(), 0)
        self.assertTrue(r["found"])
        self.assertEqual(r["count"], 2)  # 1a2b3c pair + deadbeef orphan

    def test_absent_when_there_is_no_recycle_bin_at_all(self):
        fs = FakeFs({0: [d(2, "Windows")], 2: []})
        r = artifacts.presence_recyclebin(fs, 0)
        self.assertEqual(r, {"found": False, "count": 0})

    def test_recognises_the_legacy_recycler_name(self):
        fs = FakeFs({0: [d(1, "RECYCLER")], 1: [d(2, "S-1-5-21-x")],
                    2: [f("$Ifoo"), f("$Rfoo")]})
        r = artifacts.presence_recyclebin(fs, 0)
        self.assertEqual(r, {"found": True, "count": 1})


class PrefetchPresence(unittest.TestCase):

    def test_counts_pf_files_and_ignores_other_entries(self):
        r = artifacts.presence_prefetch(build_fs(), 0)
        self.assertEqual(r, {"found": True, "count": 2})

    def test_absent_when_there_is_no_windows_prefetch_folder(self):
        fs = FakeFs({0: []})
        r = artifacts.presence_prefetch(fs, 0)
        self.assertEqual(r, {"found": False, "count": 0})

    def test_an_empty_prefetch_folder_is_not_found(self):
        fs = FakeFs({0: [d(1, "Windows")], 1: [d(2, "Prefetch")], 2: []})
        r = artifacts.presence_prefetch(fs, 0)
        self.assertEqual(r, {"found": False, "count": 0})


class BrowserPresence(unittest.TestCase):

    def test_finds_chrome_and_firefox_for_the_one_real_user(self):
        r = artifacts.presence_browser(build_fs(), 0)
        self.assertTrue(r["found"])
        browsers = {(p["user"], p["browser"]) for p in r["profiles"]}
        self.assertEqual(browsers, {("Alice", "Chrome"), ("Alice", "Firefox")})

    def test_public_and_default_are_not_treated_as_user_profiles(self):
        r = artifacts.presence_browser(build_fs(), 0)
        users = {p["user"] for p in r["profiles"]}
        self.assertNotIn("Public", users)
        self.assertNotIn("Default", users)

    def test_absent_when_there_is_no_users_folder(self):
        fs = FakeFs({0: []})
        r = artifacts.presence_browser(fs, 0)
        self.assertEqual(r, {"found": False, "profiles": []})

    def test_a_user_with_no_browser_data_contributes_nothing(self):
        fs = FakeFs({0: [d(1, "Users")], 1: [d(2, "Bob")], 2: [d(3, "AppData")],
                    3: []})
        r = artifacts.presence_browser(fs, 0)
        self.assertEqual(r, {"found": False, "profiles": []})


class Presence(unittest.TestCase):

    def test_combines_all_three_probes(self):
        r = artifacts.presence(build_fs(), 0)
        self.assertEqual(set(r), {"recyclebin", "prefetch", "browser"})
        self.assertTrue(r["recyclebin"]["found"])
        self.assertTrue(r["prefetch"]["found"])
        self.assertTrue(r["browser"]["found"])


if __name__ == "__main__":
    unittest.main()
