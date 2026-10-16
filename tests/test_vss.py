"""Unit tests for the Volume Shadow Service parser (engine/vss.py), the
overlay reader it builds, and the server's snapshot_fs integration.

Images come from tests/imagebuild_vss.py: a bare store (build_vss_image)
and an NTFS volume carrying one differential snapshot (build_vss_disk),
both encoded straight from the on-disk format.
"""

import os
import struct
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import imagebuild_vss as build                                    # noqa: E402
from test_fs_fat import BytesImage                                # noqa: E402
from engine import server                                         # noqa: E402
from engine import vss                                            # noqa: E402
from engine.fs import ntfs                                        # noqa: E402


class StoreParsing(unittest.TestCase):
    """read_store_header / read_block_list / read_store_bitmap against the
    synthetic store."""

    @classmethod
    def setUpClass(cls):
        cls.image = BytesImage(build.build_vss_image())

    def test_store_header_fields(self):
        hdr = vss.read_store_header(self.image, build.STORE_HEADER_OFFSET)
        self.assertIsNotNone(hdr)
        self.assertEqual(hdr["version"], 1)
        self.assertEqual(hdr["record_type"], vss.BLOCK_HEADER)
        self.assertEqual(hdr["context"], 0x1D)
        self.assertEqual(hdr["provider"], 0)
        self.assertEqual(hdr["attribute_flags"], 0x02000000)
        self.assertEqual(hdr["originating_machine"], build.ORIGINATING_MACHINE)
        self.assertEqual(hdr["service_machine"], build.SERVICE_MACHINE)
        self.assertEqual(hdr["copy_set_id"],
                         "00000000-0000-0000-0000-000000000000")

    def test_block_list_descriptor(self):
        entries = vss.read_block_list(self.image, build.BLOCK_LIST_OFFSET)
        self.assertEqual(len(entries), 1)
        e = entries[0]
        self.assertEqual(e["original_offset"],
                         build.REDIRECT_VOLUME_OFFSET & ~0x3FFF)
        self.assertEqual(e["flags"], vss.DESC_OVERLAY)
        # Chunk 16 of the block maps back to DIFF_AREA_OFFSET.
        self.assertEqual(e["store_data_offset"] + 16 * vss.STORE_CHUNK,
                         build.DIFF_AREA_OFFSET)
        self.assertEqual(e["allocation_bitmap"], 0b11 << 16)

    def test_block_list_missing_chain_returns_empty(self):
        # Offset 0 terminates the chain immediately: no findings, no entries.
        self.assertEqual(vss.read_block_list(self.image, 0), [])

    def test_store_bitmap_words(self):
        words = vss.read_store_bitmap(self.image, build.BITMAP_OFFSET)
        # The chain covers the whole 16 KiB block: the first word carries
        # the descriptor's bitmap, everything behind it is zero padding.
        self.assertEqual(words[0], 0b11 << 16)
        self.assertEqual(set(words[1:]), {0})

    def test_empty_originating_machine_does_not_desync_service_machine(self):
        # Regression: _string16 returned None both for a genuinely-empty
        # string and for one that didn't fit, and the caller only advanced
        # past it in the non-None case -- so a real empty originating_machine
        # (still 2 real bytes on disk: a zero length prefix) left the next
        # read starting 2 bytes early, corrupting service_machine.
        import uuid as uuid_mod
        block = bytearray(vss.BLOCK_HEADER_SIZE + vss.STORE_HEADER_SIZE + 64)
        block[0:16] = uuid_mod.UUID(vss.VSS_GUID).bytes_le
        struct.pack_into("<II", block, 16, 1, vss.BLOCK_HEADER)
        pos = vss.BLOCK_HEADER_SIZE + vss.STORE_HEADER_SIZE
        struct.pack_into("<H", block, pos, 0)          # originating_machine: empty
        svc = "SNAPSRV".encode("utf-16-le") + b"\x00\x00"
        svc_at = pos + 2
        struct.pack_into("<H", block, svc_at, len(svc) // 2)
        block[svc_at + 2:svc_at + 2 + len(svc)] = svc

        info = vss.read_store_header(BytesImage(bytes(block)), 0)
        self.assertIsNotNone(info)
        self.assertIsNone(info["originating_machine"])
        self.assertEqual(info["service_machine"], "SNAPSRV")

    def test_truncated_store_header_flagged(self):
        findings = []
        hdr = vss.read_store_header(self.image, self.image.size - 16,
                                    findings)
        self.assertIsNone(hdr)
        self.assertEqual(len(findings), 1)
        self.assertIn("truncated", findings[0])


class SnapshotsEnrichment(unittest.TestCase):
    """snapshots() over the carrier disk: pairing, machine names, flags."""

    @classmethod
    def setUpClass(cls):
        cls.disk = build.build_vss_disk()
        cls.report = vss.snapshots(BytesImage(cls.disk))
        cls.snap = cls.report["snapshots"][0]

    def test_present_with_one_snapshot(self):
        self.assertTrue(self.report["present"])
        self.assertEqual(len(self.report["snapshots"]), 1)
        self.assertEqual(self.report["findings"], [])

    def test_catalog_pairing(self):
        self.assertEqual(self.snap["header_offset"], build.STORE_HEADER_OFFSET)
        self.assertEqual(self.snap["block_list_offset"], build.BLOCK_LIST_OFFSET)
        self.assertEqual(self.snap["block_range_offset"], 0)
        self.assertEqual(self.snap["bitmap_offset"], build.BITMAP_OFFSET)
        self.assertEqual(self.snap["volume_size"], build.VOLUME_SIZE)

    def test_context_named(self):
        self.assertEqual(self.snap["context"], "0x1D")
        self.assertEqual(self.snap["context_name"], "client accessible")

    def test_attribute_flags_named(self):
        self.assertEqual(self.snap["attribute_flags"], "0x2000000")
        self.assertEqual(self.snap["attribute_flag_names"], ["TXF recovery"])

    def test_machines(self):
        self.assertEqual(self.snap["originating_machine"],
                         build.ORIGINATING_MACHINE)
        self.assertEqual(self.snap["service_machine"],
                         build.SERVICE_MACHINE)

    def test_created_at_filetime(self):
        self.assertEqual(self.snap["created_at"],
                         "2023-06-17T00:14:59.374308Z")

    def test_store_records_listed(self):
        self.assertEqual(self.snap["store_records"],
                         ["block list", "bitmap"])

    def test_no_snapshot_copy_set_id(self):
        # A fresh snapshot is its own copy set until a newer store exists.
        self.assertEqual(self.snap["copy_set_id"],
                         "00000000-0000-0000-0000-000000000000")


class OverlayRedirect(unittest.TestCase):
    """VssOverlay: redirected bytes, transparency, seek/tell and the
    store-read finding path."""

    def setUp(self):
        self.disk = build.build_vss_disk()
        self.base = BytesImage(self.disk)
        self.report = vss.snapshots(self.base)
        self.findings = []
        self.ov = vss.VssOverlay(self.base,
                                  self.report["snapshots"][0],
                                  self.findings)

    def test_redirected_bytes_come_from_the_store(self):
        want = build.pattern(build.DIFF_SIZE, build.DIFF_SEED)
        got = self.ov.read_at(build.REDIRECT_VOLUME_OFFSET, len(want))
        self.assertEqual(got, want)
        self.assertNotEqual(got,
                            self.disk[build.REDIRECT_VOLUME_OFFSET:
                                      build.REDIRECT_VOLUME_OFFSET
                                      + len(want)])

    def test_unset_bitmap_bit_falls_through(self):
        # One byte past the two redirected chunks reads from the base.
        past = build.REDIRECT_VOLUME_OFFSET + build.DIFF_SIZE
        got = self.ov.read_at(past, 16)
        self.assertEqual(got, self.disk[past:past + 16])

    def test_read_spanning_an_allocated_and_unallocated_chunk_is_not_misattributed(self):
        # Regression: chunk 17 (redirected, within the descriptor's two-chunk
        # bitmap) ends 412 bytes after this offset; chunk 18 (not in the
        # bitmap) falls through to the base volume. A read spanning both
        # used to be served entirely from the store when it wasn't
        # chunk-aligned, since `take` wasn't capped to what was left in the
        # *current* chunk -- so the base-volume tail came back as leftover
        # store bytes instead.
        start = build.REDIRECT_VOLUME_OFFSET + 512 + 100  # 100 B into chunk 17
        got = self.ov.read_at(start, 500)
        want_redirected = build.pattern(build.DIFF_SIZE,
                                        build.DIFF_SEED)[612:1024]
        base_start = build.REDIRECT_VOLUME_OFFSET + build.DIFF_SIZE
        want_base = self.disk[base_start:base_start + 88]
        self.assertEqual(got, want_redirected + want_base)

    def test_outside_descriptor_is_transparent(self):
        self.assertEqual(self.ov.read_at(0, 64), self.disk[0:64])
        self.assertEqual(self.ov.read_at(0x1E00, 128),
                         self.disk[0x1E00:0x1E00 + 128])

    def test_size_and_bytes_per_sector_match_base(self):
        self.assertEqual(self.ov.size, len(self.disk))
        self.assertEqual(self.ov.bytes_per_sector, 512)

    def test_seek_tell_read(self):
        self.assertEqual(self.ov.tell(), 0)
        want = build.pattern(build.DIFF_SIZE, build.DIFF_SEED)
        self.ov.seek(build.REDIRECT_VOLUME_OFFSET)
        self.assertEqual(self.ov.tell(), build.REDIRECT_VOLUME_OFFSET)
        self.assertEqual(self.ov.read(len(want)), want)
        tail = build.REDIRECT_VOLUME_OFFSET + build.DIFF_SIZE - 4
        self.ov.seek(tail)
        self.assertEqual(self.ov.read(4), want[-4:])

    def test_snapshot_tree_opens_through_the_overlay(self):
        fs = ntfs.open_fs(self.ov)
        root = {e["name"]: e for e in fs.listdir()}
        self.assertIn("hello.txt", root)
        self.assertIn("big.bin", root)
        # hello.txt is resident: byte-identical to the base volume.
        self.assertEqual(fs.read_file(root["hello.txt"]), b"Hello, NTFS!\n")
        # big.bin starts at LCN 40 = volume offset 0xA000: the redirect.
        data = fs.read_range(root["big.bin"], 0, 32)
        self.assertEqual(data[:16], build.pattern(build.DIFF_SIZE,
                                                  build.DIFF_SEED)[:16])


class SnapshotFsIntegration(unittest.TestCase):
    """Session.snapshot_fs(): caching, error paths and end-to-end reads."""

    def _session_with_image(self, data):
        import tempfile
        from engine.server import Session
        dirpath = tempfile.mkdtemp(prefix="strata-vss-test-")
        path = os.path.join(dirpath, "vss.img")
        with open(path, "wb") as fh:
            fh.write(data)
        try:
            sess = Session()
            sess.open(path)
            return sess, dirpath
        except Exception:
            import shutil
            shutil.rmtree(dirpath, ignore_errors=True)
            raise

    def test_snapshot_fs_reads_redirected_bytes(self):
        from engine.server import Session
        import shutil
        import tempfile
        dirpath = tempfile.mkdtemp(prefix="strata-vss-test-")
        path = os.path.join(dirpath, "vss.img")
        with open(path, "wb") as fh:
            fh.write(build.build_vss_disk())
        try:
            sess = Session()
            sess.open(path)
            fs = sess.snapshot_fs(0, 0)
            root = {e["name"]: e for e in fs.listdir()}
            data = fs.read_range(root["big.bin"], 0, 16)
            self.assertEqual(data, build.pattern(build.DIFF_SIZE,
                                                 build.DIFF_SEED)[:16])
            # Cached: a second call returns the same object.
            self.assertIs(sess.snapshot_fs(0, 0), fs)
        finally:
            shutil.rmtree(dirpath, ignore_errors=True)

    def test_bad_index_raises(self):
        from engine.server import Session
        import shutil
        import tempfile
        dirpath = tempfile.mkdtemp(prefix="strata-vss-test-")
        path = os.path.join(dirpath, "vss.img")
        with open(path, "wb") as fh:
            fh.write(build.build_vss_disk())
        try:
            sess = Session()
            sess.open(path)
            with self.assertRaises(ValueError) as ctx:
                sess.snapshot_fs(0, 5)
            self.assertIn("No such shadow copy", str(ctx.exception))
        finally:
            shutil.rmtree(dirpath, ignore_errors=True)

    def test_volume_without_snapshots_raises(self):
        from engine.server import Session
        import shutil
        import tempfile
        dirpath = tempfile.mkdtemp(prefix="strata-vss-test-")
        path = os.path.join(dirpath, "plain.img")
        with open(path, "wb") as fh:
            fh.write(build.build_ntfs())
        try:
            sess = Session()
            sess.open(path)
            with self.assertRaises(ValueError) as ctx:
                sess.snapshot_fs(0, 0)
            self.assertIn("No shadow copies", str(ctx.exception))
        finally:
            shutil.rmtree(dirpath, ignore_errors=True)


class _ExportFakeHandler:
    """Just enough of engine.server.Handler to drive _api_post directly: a
    real Session (not a mock -- the whole point is exercising the real
    snapshot_fs() ValueError path) and a _send() that records what was
    sent instead of writing to a socket."""

    def __init__(self, session):
        self._sess = session
        self.sent = None

    def _session(self):
        return self._sess

    def _send(self, code, body, ctype="application/json"):
        self.sent = (code, body)
        return None


class ExportEndpointsSnapshotErrors(unittest.TestCase):
    """Regression: /api/export/file and /api/export/folder called
    snapshot_fs() unguarded, unlike every other snapshot-aware endpoint
    (/api/dir, /api/stat, /api/preview), so a bad snapshot index fell
    through to the generic top-level exception handler -- a 500 with a
    server-side traceback -- instead of the same clean 400 the rest of
    the feature gives."""

    def setUp(self):
        import shutil
        import tempfile
        from engine.server import Session
        self.dirpath = tempfile.mkdtemp(prefix="strata-vss-export-test-")
        self.addCleanup(shutil.rmtree, self.dirpath, ignore_errors=True)
        path = os.path.join(self.dirpath, "vss.img")
        with open(path, "wb") as fh:
            fh.write(build.build_vss_disk())
        self.sess = Session()
        self.sess.open(path)

    def test_export_file_with_a_bad_snapshot_index_is_a_clean_400(self):
        fh = _ExportFakeHandler(self.sess)
        server.Handler._api_post(fh, "/api/export/file",
                                 {"part": 0, "snap": 5, "entry": {}})
        self.assertEqual(fh.sent[0], 400)
        self.assertIn("No such shadow copy", fh.sent[1]["error"])

    def test_export_folder_with_a_bad_snapshot_index_is_a_clean_400(self):
        fh = _ExportFakeHandler(self.sess)
        server.Handler._api_post(
            fh, "/api/export/folder",
            {"part": 0, "snap": 5, "entry": {"is_dir": True, "path": "/x"}})
        self.assertEqual(fh.sent[0], 400)
        self.assertIn("No such shadow copy", fh.sent[1]["error"])


class FuzzLoop(unittest.TestCase):
    """Deterministic slice of tests/fuzz.py's vss target: mutated carrier
    disks must never escape the parser with anything but a clean error."""

    def test_mutated_disks_stay_clean(self):
        import random
        import fuzz
        clean = (ValueError, MemoryError)
        seed = build.build_vss_disk()
        for case in range(40):
            data = fuzz.mutate(seed, random.Random(case))
            try:
                fuzz.run_vss(data)
            except clean:
                pass


if __name__ == "__main__":
    unittest.main()