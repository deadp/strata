"""Unit tests for hosted sparse VMDK extents (engine.vmdk): monolithicSparse
and streamOptimized, fed images from imagebuild_vmdk. The flat extent's
confinement to its descriptor's folder is covered in test_vmdk_extent.py."""

import hashlib
import os
import struct
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import imagebuild_vmdk as build                                   # noqa: E402
from engine import ewf, vmdk                                      # noqa: E402

G = build.GRAIN
MEDIA = build.media()


class VmdkCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="strata-vmdk-test-")
        self.addCleanup(self._tmp.cleanup)

    def open(self, data, name="disk.vmdk"):
        path = os.path.join(self._tmp.name, name)
        with open(path, "wb") as fh:
            fh.write(data)
        img = ewf.open_image(path)
        self.addCleanup(img.close)
        return img

    def stream(self, mutator):
        return self.open(build.build_stream_optimized(mutator)[0])


class Sparse(VmdkCase):
    def setUp(self):
        super(Sparse, self).setUp()
        self.img = self.open(build.build_sparse())

    def test_opens_as_sparse_vmdk(self):
        self.assertIsInstance(self.img, vmdk.VmdkImage)
        info = self.img.info()
        self.assertEqual(info["format"], "VMware VMDK (sparse)")
        self.assertEqual(info["size"], len(MEDIA))
        self.assertEqual(info["chunk_size"], G)
        self.assertEqual(info["acquisition"]["create type"],
                         "monolithicSparse")
        self.assertEqual(info["acquisition"]["adapter"], "lsilogic")
        self.assertEqual(info["acquisition"]["grain tables present"],
                         "2 of 2")
        self.assertEqual(self.img.findings, [])

    def test_reads_back_with_unallocated_grains_as_zeros(self):
        self.assertEqual(self.img.read_at(0, len(MEDIA)), MEDIA)
        self.assertEqual(self.img.read_at(2 * G, G), bytes(G))

    def test_reads_across_grain_and_table_boundaries(self):
        for off, n in ((G - 7, 20), (4 * G - 100, 200), (3 * G, 3 * G),
                       (len(MEDIA) - 5, 50)):
            self.assertEqual(self.img.read_at(off, n), MEDIA[off:off + n])
        self.assertEqual(self.img.read_at(len(MEDIA), 10), b"")

    def test_verify_hashes_the_virtual_disk(self):
        got = self.img.verify()
        self.assertEqual(got["computed_md5"], hashlib.md5(MEDIA).hexdigest())
        self.assertIsNone(got["md5_match"])


class StreamOptimized(VmdkCase):
    def setUp(self):
        super(StreamOptimized, self).setUp()
        self.data, self.offsets = build.build_stream_optimized()
        self.img = self.open(self.data)

    def test_opens_from_the_footer(self):
        info = self.img.info()
        self.assertEqual(info["format"], "VMware VMDK (stream-optimized)")
        self.assertEqual(info["size"], len(MEDIA))
        self.assertEqual(info["acquisition"]["create type"], "streamOptimized")
        self.assertEqual(len(self.img.findings), 1)
        self.assertIn("footer", self.img.findings[0])

    def test_reads_back(self):
        self.assertEqual(self.img.read_at(0, len(MEDIA)), MEDIA)
        self.assertEqual(self.img.verify()["computed_md5"],
                         hashlib.md5(MEDIA).hexdigest())

    def test_cut_before_the_footer_is_refused(self):
        with self.assertRaises(ewf.UnsupportedContainer):
            self.open(self.data[:self.offsets[6]], "cut.vmdk")

    def test_grain_that_will_not_inflate_reads_as_zeros(self):
        def corrupt(g, comp):
            return comp if g != 1 else b"\x00" * len(comp)
        img = self.stream(corrupt)
        got = img.read_at(0, len(MEDIA))
        self.assertEqual(got[G:2 * G], bytes(G))
        self.assertEqual(got[:G] + got[2 * G:], MEDIA[:G] + MEDIA[2 * G:])
        self.assertTrue(any("would not inflate" in f for f in img.findings))

    # A grain whose compressed stream ends early is zero-padded past what
    # was recovered, and reported, rather than silently treated as zeros.
    def test_grain_whose_stream_ends_early_is_reported(self):
        img = self.stream(lambda g, comp: comp[:len(comp) // 2]
                          if g == 1 else comp)
        got = img.read_at(0, len(MEDIA))
        self.assertEqual(got[3 * G:], MEDIA[3 * G:])
        self.assertTrue(any("grain" in f.lower() and "incomplete" in f.lower()
                            for f in img.findings), img.findings)


class Damaged(VmdkCase):
    """Header and grain-table fields the fuzzer found unbounded
    (tests/fuzz.py, vmdk-sparse and vmdk-stream targets): each of these
    reproduced a MemoryError, OverflowError, ZeroDivisionError, OSError or
    a many-minute stall against engine/vmdk.py on main."""

    @staticmethod
    def patch(data, at, fmt, value):
        data = bytearray(data)
        struct.pack_into(fmt, data, at, value)
        return bytes(data)

    def assertRefused(self, data, *snippets):
        with self.assertRaises(ewf.UnsupportedContainer) as ctx:
            self.open(data, "damaged.vmdk")
        for s in snippets:
            self.assertIn(s, str(ctx.exception))

    def test_zero_grain_table_entries(self):
        self.assertRefused(self.patch(build.build_sparse(), 44, "<I", 0),
                           "grain table")

    def test_implausible_grain_table_entries(self):
        self.assertRefused(
            self.patch(build.build_sparse(), 44, "<I", 0xFFFFFFFF),
            "grain table")

    def test_huge_capacity_in_footer(self):
        data, _ = build.build_stream_optimized()
        footer = len(data) - 2 * build.SECTOR
        self.assertRefused(self.patch(data, footer + 12, "<Q", 1 << 62),
                           "grain")

    def test_huge_descriptor_size(self):
        # The declared size runs past the file; what is actually there
        # (starting with the real descriptor text) is read instead, with a
        # finding, rather than the read itself failing.
        img = self.open(self.patch(build.build_sparse(), 36, "<Q", 1 << 47),
                        "damaged.vmdk")
        self.assertEqual(img.descriptor["create_type"], "monolithicSparse")
        self.assertTrue(any("descriptor declares" in f
                            for f in img.findings), img.findings)

    def test_huge_descriptor_offset(self):
        # A descriptor offset past the end of the file reads nothing rather
        # than seeking somewhere invalid; the extent still opens.
        img = self.open(self.patch(build.build_sparse(), 28, "<Q", 1 << 40),
                        "damaged.vmdk")
        self.assertIsNone(img.descriptor["create_type"])
        self.assertTrue(any("descriptor declares" in f
                            for f in img.findings), img.findings)

    def test_huge_grain_size(self):
        self.assertRefused(
            self.patch(build.build_sparse(), 20, "<Q", 1 << 40 | 8),
            "grain size")

    def test_grain_table_entry_past_end_of_file(self):
        data = build.build_sparse()
        gd_off = struct.unpack_from("<Q", data, 56)[0]
        gt_off = struct.unpack_from("<I", data, gd_off * build.SECTOR)[0]
        img = self.open(self.patch(data, gt_off * build.SECTOR, "<I",
                                   1 << 24), "damaged.vmdk")
        self.assertEqual(img.read_at(0, G), bytes(G))
        self.assertTrue(any("past the end" in f for f in img.findings))

    def test_grain_declaring_implausible_compressed_size_stays_fast(self):
        data, offsets = build.build_stream_optimized()
        at = offsets[1] + 8                # the marker's csize field
        data = self.patch(data, at, "<I", 1 << 30)
        img = self.open(data, "damaged.vmdk")
        t0 = time.time()
        got = img.read_at(0, len(build.media()))
        self.assertLess(time.time() - t0, 5)
        self.assertEqual(got[3 * G:], build.media()[3 * G:])
        self.assertTrue(any("more than is plausible" in f
                            for f in img.findings), img.findings)


if __name__ == "__main__":
    unittest.main()
