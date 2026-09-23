"""Unit tests for engine.appcompat: ShimCache/AppCompatCache parsing and,
since issue #63, the "examined, not run" caveat that used to live only in
a help string shown before collection, never with the results themselves.
"""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import appcompat                                      # noqa: E402


def win10_shimcache(entries):
    """A minimal Windows-10-format AppCompatCache buffer: `entries` is a
    list of (path, modified_filetime)."""
    header = bytearray(appcompat.WIN10_HEADER)          # padding to the header size
    struct.pack_into("<I", header, 0, appcompat.WIN10_HEADER)
    body = bytearray()
    for path, modified in entries:
        path_b = path.encode("utf-16-le")
        cell = struct.pack("<H", len(path_b)) + path_b \
            + struct.pack("<QI", modified, 0)
        body += appcompat.ENTRY_WIN10 + struct.pack("<I", 0) \
            + struct.pack("<I", len(cell) + 12) + cell
    return bytes(header) + bytes(body)


class ParseShimcache(unittest.TestCase):

    def test_windows10_entries_parsed(self):
        data = win10_shimcache([("C:\\Windows\\notepad.exe", 0)])
        got = appcompat.parse_shimcache(data)
        self.assertEqual(got["format"], "Windows 10")
        self.assertEqual([e["path"] for e in got["entries"]],
                         ["C:\\Windows\\notepad.exe"])
        # parse_shimcache() itself carries no caveat -- only the
        # shimcache_from_system() aggregate does (below), since an empty
        # or unparsed buffer should not carry one.
        self.assertEqual(got["findings"], [])

    def test_unrecognised_header_gives_a_finding_not_entries(self):
        got = appcompat.parse_shimcache(struct.pack("<I", 0xDEADBEEF) + b"\x00" * 8)
        self.assertEqual(got["entries"], [])
        self.assertTrue(got["findings"])

    def test_too_short_gives_nothing(self):
        got = appcompat.parse_shimcache(b"\x00\x00")
        self.assertEqual(got["entries"], [])
        self.assertEqual(got["findings"], [])


class FakeHive:
    """The three Hive methods shimcache_from_system() calls."""

    def __init__(self, control_sets):
        # control_sets: {control_set_name: raw_appcompatcache_bytes}
        self.control_sets = control_sets

    def open_path(self, path):
        for cs, raw in self.control_sets.items():
            if path.startswith(cs + "\\"):
                return {"control_set": cs}
        return None

    def values(self, key, inline=True):
        return [{"name": "AppCompatCache", "offset": key["control_set"]}]

    def value_bytes(self, vk_offset):
        return self.control_sets[vk_offset]


class ShimcacheFromSystem(unittest.TestCase):

    def test_caveat_present_when_entries_found(self):
        raw = win10_shimcache([("C:\\Windows\\notepad.exe", 0)])
        hive = FakeHive({"ControlSet001": raw})
        out = appcompat.shimcache_from_system(hive)
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0]["entries"])
        self.assertIn(appcompat.SHIMCACHE_CAVEAT, out[0]["findings"])

    def test_no_caveat_when_no_entries(self):
        raw = win10_shimcache([])
        hive = FakeHive({"ControlSet001": raw})
        out = appcompat.shimcache_from_system(hive)
        self.assertEqual(out[0]["entries"], [])
        self.assertNotIn(appcompat.SHIMCACHE_CAVEAT, out[0]["findings"])

    def test_no_caveat_added_to_an_unparsed_buffer(self):
        hive = FakeHive({"ControlSet001":
                        struct.pack("<I", 0xDEADBEEF) + b"\x00" * 8})
        out = appcompat.shimcache_from_system(hive)
        self.assertEqual(out[0]["entries"], [])
        self.assertNotIn(appcompat.SHIMCACHE_CAVEAT, out[0]["findings"])
        self.assertTrue(out[0]["findings"])   # still gets its own finding


if __name__ == "__main__":
    unittest.main()
