"""Unit tests for the registry hive parser (engine.registry) and transaction
log replay (engine.reglog), fed synthetic hives from imagebuild_registry."""

import os
import random
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import imagebuild_registry as build                              # noqa: E402
from engine import registry, reglog                              # noqa: E402


class HiveFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = build.build_hive()

    def setUp(self):
        self.hive = registry.open_hive(self.data, "SOFTWARE")
        self.assertIsNotNone(self.hive)

    def values(self, path="Software\\Strata"):
        key = self.hive.open_path(path)
        return {v["name"]: v for v in self.hive.values(key)}


class BaseBlock(HiveFixture):
    def test_info(self):
        info = self.hive.info()
        self.assertEqual(info["type"], "regf")
        self.assertEqual(info["name"], "SOFTWARE")
        self.assertEqual(info["embedded_name"], "\\??\\C:\\ROOT")
        self.assertEqual(info["version"], "1.5")
        self.assertEqual(info["sequence"], [1, 1])
        self.assertFalse(info["dirty"])
        self.assertEqual(info["modified"], "2022-06-18T04:26:40Z")
        self.assertEqual(info["findings"], [])

    def test_base_block_checksum(self):
        stored = struct.unpack_from("<I", self.data, 508)[0]
        self.assertEqual(reglog.base_checksum(self.data[:4096]), stored)

    def test_base_block_checksum_edge_values(self):
        self.assertEqual(reglog.base_checksum(bytes(512)), 1)
        blk = bytearray(512)
        struct.pack_into("<I", blk, 0, 0xFFFFFFFF)
        self.assertEqual(reglog.base_checksum(bytes(blk)), 0xFFFFFFFE)

    def test_dirty_hive_is_flagged(self):
        h = registry.open_hive(build.build_hive(seq1=3, seq2=2))
        self.assertTrue(h.dirty)
        self.assertTrue(h.findings)

    def test_classify_well_known(self):
        self.assertEqual(
            registry.classify("C:/Windows/System32/config/SOFTWARE")["label"],
            "SOFTWARE")
        self.assertIsNone(registry.classify("notes.txt"))


class Keys(HiveFixture):
    def test_root(self):
        root = self.hive.root()
        self.assertEqual(root["name"], "ROOT")
        self.assertTrue(root["root"])
        self.assertEqual(root["modified"], "2022-06-18T04:26:40Z")

    def test_lh_subkey_list(self):
        names = [k["name"] for k in self.hive.subkeys(self.hive.root())]
        self.assertEqual(names, ["Software", "System", u"\u00dcn\u00efcode"])

    def test_lf_subkey_list(self):
        sw = self.hive.open_path("Software")
        self.assertEqual([k["name"] for k in self.hive.subkeys(sw)],
                         ["Strata"])

    def test_ri_list_of_li_and_lf(self):
        sysk = self.hive.open_path("\\System")
        self.assertEqual([k["name"] for k in self.hive.subkeys(sysk)],
                         ["Alpha", "Beta"])

    def test_open_path_variants(self):
        self.assertEqual(self.hive.open_path("software/STRATA")["name"],
                         "Strata")
        self.assertEqual(self.hive.open_path("\\")["name"], "ROOT")
        self.assertIsNone(self.hive.open_path("Software\\Missing"))

    def test_parent_pointer(self):
        sw = self.hive.open_path("Software")
        self.assertEqual(self.hive.open_path("Software\\Strata")["parent"],
                         sw["offset"])


class Values(HiveFixture):
    def test_value_names(self):
        self.assertEqual(sorted(self.values()),
                         sorted(["(Default)", "Name", "Count", "Blob", "Tiny",
                                 "Paths", "Big"]))

    def test_reg_sz(self):
        v = self.values()["Name"]
        self.assertEqual(v["type"], "REG_SZ")
        self.assertEqual(v["value"], "Strata")
        self.assertFalse(v["resident"])
        self.assertEqual(self.values()["(Default)"]["value"], "default value")

    def test_reg_dword_resident(self):
        v = self.values()["Count"]
        self.assertEqual(v["type"], "REG_DWORD")
        self.assertEqual(v["value"], 42)
        self.assertTrue(v["resident"])
        self.assertIsNone(v["data_offset"])

    def test_reg_binary(self):
        v = self.values()["Blob"]
        self.assertEqual(v["type"], "REG_BINARY")
        self.assertEqual(v["size"], 16)
        self.assertEqual(self.hive.value_bytes(v["offset"]), bytes(range(16)))
        self.assertEqual(v["value"].split()[:3], ["00", "01", "02"])

    def test_resident_binary_shorter_than_four_bytes(self):
        v = self.values()["Tiny"]
        self.assertTrue(v["resident"])
        self.assertEqual(self.hive.value_bytes(v["offset"]), b"\x01\x02\x03")

    def test_reg_multi_sz(self):
        v = self.values()["Paths"]
        self.assertEqual(v["type"], "REG_MULTI_SZ")
        self.assertEqual(v["value"], ["C:\\a", "D:\\b"])

    def test_big_data(self):
        v = self.values()["Big"]
        self.assertEqual(v["size"], len(build.BIG_BLOB))
        self.assertTrue(v["truncated"])
        self.assertIsNone(v["value"])
        self.assertEqual(self.hive.value_bytes(v["offset"]), build.BIG_BLOB)

    # /api/registry/value (issue #79) fetches a value too large to inline by
    # re-reading it with inline=False, then decoding value_bytes() itself --
    # this is that sequence, run directly against a value large enough that
    # values() left it truncated.
    def test_truncated_value_can_be_fetched_in_full(self):
        v = self.values()["Big"]
        self.assertTrue(v["truncated"])
        full = self.hive.value(v["offset"], inline=False)
        self.assertEqual(full["offset"], v["offset"])
        self.assertEqual(full["type_id"], v["type_id"])
        self.assertEqual(full["size"], v["size"])
        raw = self.hive.value_bytes(full["offset"])
        full["value"] = self.hive.decode(full["type_id"], raw)
        self.assertEqual(
            full["value"],
            registry.Hive.decode(v["type_id"], build.BIG_BLOB))

    def test_fetching_an_unknown_offset_gives_nothing(self):
        self.assertIsNone(self.hive.value(0xFFFFFF, inline=False))

    def test_decode_other_types(self):
        self.assertEqual(registry.Hive.decode(5, b"\x00\x00\x01\x00"), 256)
        self.assertEqual(registry.Hive.decode(11, struct.pack("<Q", 2 ** 40)),
                         2 ** 40)
        self.assertEqual(registry.Hive.decode(2, "%x%\x00".encode("utf-16-le")),
                         "%x%")


class DeletedCells(HiveFixture):
    def test_carve_recovers_deleted_key_and_value(self):
        got = self.hive.carve_deleted()
        self.assertEqual([k["name"] for k in got["keys"]], ["Removed"])
        self.assertTrue(got["keys"][0]["deleted"])
        self.assertEqual(got["keys"][0]["parent"],
                         self.hive.open_path("Software")["offset"])
        self.assertEqual([(v["name"], v["value"]) for v in got["values"]],
                         [("OldValue", "gone")])
        self.assertTrue(got["values"][0]["deleted"])

    def test_deleted_records_not_in_live_tree(self):
        self.assertIsNone(self.hive.open_path("Software\\Removed"))


class Marvin32(unittest.TestCase):
    # Vectors from the .NET runtime's Marvin tests, seed 0x004FB61A001BDBCC.
    SEED = 0x004FB61A001BDBCC
    VECTORS = [
        (b"\xaf", 0x48E73FC77D75DDC1),
        (b"\xe7\x0f", 0xB5F6E1FC485DBFF8),
        (b"\x37\xf4\x95", 0xF0B07C789B8CF7E8),
        (b"\x15\x3f\xb7\x98\x26", 0xE6C08C6DA2AFA997),
        (b"\x09\x32\xe6\x24\x6c\x47", 0x6F04BF1A5EA24060),
        (b"\xab\x42\x7e\xa8\xd1\x0f\xc7", 0xE11847E4F0678C41),
    ]

    def test_known_vectors(self):
        for data, want in self.VECTORS:
            self.assertEqual(reglog.marvin32(data, self.SEED), want, data)

    def test_builder_agrees_with_engine(self):
        blob = bytes(range(256)) * 3
        for n in (0, 1, 2, 3, 4, 511, 512):
            self.assertEqual(build.marvin32(blob[:n]), reglog.marvin32(blob[:n]))


class TransactionLog(unittest.TestCase):
    def setUp(self):
        self.stale, self.log, self.fresh_bins = build.build_dirty_pair()

    def test_parse_log(self):
        got = reglog.parse_log(self.log)
        self.assertEqual(got["findings"], [])
        self.assertEqual(got["base_sequence"], 10)
        self.assertEqual(len(got["entries"]), 1)
        entry = got["entries"][0]
        self.assertEqual(entry["sequence"], 10)
        self.assertEqual(entry["hbins_size"], len(self.fresh_bins))
        self.assertEqual(entry["pages"][0][:2], (0, len(self.fresh_bins)))

    def test_hive_sequences(self):
        self.assertEqual(reglog.hive_sequences(self.stale),
                         (11, 10, len(self.fresh_bins)))
        self.assertIsNone(reglog.hive_sequences(b"regf"))

    def test_replay_applies_log(self):
        before = registry.open_hive(self.stale)
        self.assertEqual(
            {v["name"]: v["value"] for v in
             before.values(before.open_path("Software\\Strata"))}["Name"],
            "Strata")
        new, report = reglog.recover(self.stale, [self.log])
        self.assertTrue(report["dirty"])
        self.assertTrue(report["recovered"])
        self.assertEqual(report["applied"], [10])
        self.assertEqual(report["pages_written"], 1)
        self.assertEqual(report["bytes_written"], len(self.fresh_bins))
        self.assertIn("Recovered", reglog.summarise(report))

        self.assertEqual(new[4096:], self.fresh_bins)
        self.assertEqual(struct.unpack_from("<II", new, 4), (10, 10))
        self.assertEqual(struct.unpack_from("<I", new, 508)[0],
                         reglog.base_checksum(new[:508]))
        after = registry.open_hive(new)
        self.assertFalse(after.dirty)
        self.assertEqual(
            {v["name"]: v["value"] for v in
             after.values(after.open_path("Software\\Strata"))}["Name"],
            "Replay")

    def test_clean_hive_needs_no_replay(self):
        new, report = reglog.recover(build.build_hive(), [self.log])
        self.assertIsNone(new)
        self.assertFalse(report["dirty"])
        self.assertEqual(reglog.summarise(report),
                         "Cleanly unmounted; no replay needed.")

    def test_dirty_without_logs(self):
        new, report = reglog.recover(self.stale, [])
        self.assertIsNone(new)
        self.assertFalse(report["recovered"])
        self.assertTrue(report["findings"])
        self.assertIn("not recoverable", reglog.summarise(report))

    def test_corrupt_entry_data_is_refused(self):
        bad = bytearray(self.log)
        bad[512 + 40 + 8 + 100] ^= 0xFF
        new, report = reglog.recover(self.stale, [bytes(bad)])
        self.assertIsNone(new)
        self.assertTrue(any("data hash" in f for f in report["findings"]))

    def test_corrupt_entry_header_is_refused(self):
        bad = bytearray(self.log)
        bad[512 + 8] ^= 0x01                       # flags field
        got = reglog.parse_log(bytes(bad))
        self.assertEqual(got["entries"], [])
        self.assertTrue(any("header hash" in f for f in got["findings"]))

    def test_sequence_gap_is_not_replayed(self):
        entry = build.log_entry(12, len(self.fresh_bins),
                                [(0, self.fresh_bins)])
        new, report = reglog.recover(self.stale, [build.build_log([entry])])
        self.assertIsNone(new)
        self.assertEqual(report["log_sequences"], [12])
        self.assertTrue(any("overwritten" in f for f in report["findings"]))

    def test_entries_beyond_gap_are_reported(self):
        e10 = build.log_entry(10, len(self.fresh_bins), [(0, self.fresh_bins)])
        e12 = build.log_entry(12, len(self.fresh_bins), [(0, self.fresh_bins)])
        new, report = reglog.recover(self.stale, [build.build_log([e10, e12])])
        self.assertIsNotNone(new)
        self.assertEqual(report["applied"], [10])
        self.assertTrue(any("gap" in f for f in report["findings"]))

    def test_implausible_entry_size(self):
        bad = bytearray(self.log)
        struct.pack_into("<I", bad, 516, 1000)
        got = reglog.parse_log(bytes(bad))
        self.assertEqual(got["entries"], [])
        self.assertTrue(any("implausible" in f for f in got["findings"]))

    def test_truncated_log(self):
        got = reglog.parse_log(self.log[:100])
        self.assertEqual(got["entries"], [])
        self.assertTrue(got["findings"])
        got = reglog.parse_log(self.log[:5000])
        self.assertEqual(got["entries"], [])
        self.assertTrue(got["findings"])

    def test_not_a_hive(self):
        new, report = reglog.recover(b"garbage" * 1000, [self.log])
        self.assertIsNone(new)
        self.assertTrue(report["findings"])


class Robustness(unittest.TestCase):
    def test_garbage_is_not_a_hive(self):
        for data in (b"", b"garbage", bytes(8192), b"hbin" * 2048):
            self.assertIsNone(registry.open_hive(data))

    # A "regf" file cut short inside its 48 bytes of base-block fields.
    def test_truncated_base_block(self):
        for n in (4, 20, 40, 47, 48, 1000):
            try:
                h = registry.open_hive(build.build_hive()[:n])
            except struct.error as exc:
                self.fail("open_hive raised on %d bytes: %s" % (n, exc))
            self.assertIsNotNone(h)
            self.assertIsNone(h.root())
            self.assertEqual(h.carve_deleted(), {"keys": [], "values": []})
            self.assertTrue(any("cut short" in f for f in h.info()["findings"]))

    def test_base_block_only(self):
        h = registry.open_hive(build.build_hive()[:4096])
        self.assertIsNone(h.root())
        self.assertEqual(h.carve_deleted(), {"keys": [], "values": []})

    TRUNCATIONS = (4096 + 32, 4096 + 702, 4096 + 5000, 28672 - 100)

    def test_truncated_hive_bins_tree_walk(self):
        data = build.build_hive()
        for cut in self.TRUNCATIONS:
            h = registry.open_hive(data[:cut])
            root = h.root()
            if root:
                for k in h.subkeys(root):
                    h.values(k)

    # A hive cut short mid-bin (e.g. read with the MAX_HIVE cap): carving
    # stops at the end of the data rather than reading cell sizes past it.
    def test_truncated_hive_bins_carve(self):
        data = build.build_hive()
        for cut in self.TRUNCATIONS:
            try:
                registry.open_hive(data[:cut]).carve_deleted()
            except struct.error as exc:
                self.fail("carve_deleted raised at cut %d: %s" % (cut, exc))

    def test_self_referencing_ri_list_terminates(self):
        data = bytearray(build.build_hive())
        h = registry.open_hive(bytes(data))
        sysk = h.open_path("System")
        ri = 4096 + sysk["subkeys"]
        struct.pack_into("<I", data, ri + 4 + 4, sysk["subkeys"])
        h = registry.open_hive(bytes(data))
        names = [k["name"] for k in h.subkeys(h.open_path("System"))]
        self.assertEqual(names, ["Beta"])

    def test_random_corruption_never_raises(self):
        data = build.build_hive()
        rnd = random.Random(20260916)
        for _ in range(300):
            m = bytearray(data)
            for _ in range(rnd.randint(1, 16)):
                m[rnd.randrange(4096, 4096 + 2048)] = rnd.randrange(256)
            h = registry.open_hive(bytes(m))
            stack, seen = [h.root()], 0
            while stack and seen < 64:
                k = stack.pop()
                seen += 1
                if k:
                    h.values(k)
                    stack.extend(h.subkeys(k))
            h.carve_deleted()


if __name__ == "__main__":
    unittest.main()
