"""Unit tests for AccessData logical images (engine.ad1, engine.fs.ad1fs),
fed a single-segment image from imagebuild_ad1."""

import hashlib
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import imagebuild_ad1 as build                                    # noqa: E402
from engine import ad1, ewf                                       # noqa: E402
from engine.fs import ad1fs, ntfs                                 # noqa: E402

CS = build.CHUNK_SIZE
BIG = build.CONTENT["Documents/big.bin"]


def by_name(entries):
    return {e["name"]: e for e in entries}


class Ad1Case(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="strata-ad1-test-")
        self.addCleanup(self._tmp.cleanup)

    def open(self, chunk_mutator=None):
        data, self.layout = build.build_ad1(chunk_mutator)
        path = os.path.join(self._tmp.name, "case.ad1")
        with open(path, "wb") as fh:
            fh.write(data)
        img = ewf.open_image(path)
        self.addCleanup(img.close)
        fs = ntfs.open_fs(img)
        source = fs.listdir(0)[0]
        top = by_name(fs.listdir(source["oid"], "/" + source["name"]))
        docs = by_name(fs.listdir(top["Documents"]["oid"],
                                  top["Documents"]["path"]))
        return img, fs, source, top, docs


class Container(Ad1Case):
    def test_opens_as_ad1(self):
        img, fs, _, _, _ = self.open()
        self.assertIsInstance(img, ad1.Ad1Image)
        self.assertIsInstance(fs, ad1fs.Ad1FS)
        info = img.info()
        self.assertEqual(info["format"], "AccessData logical image (AD1)")
        self.assertEqual(info["segments"], ["case.ad1"])
        self.assertTrue(info["logical"])
        self.assertEqual(info["chunk_size"], CS)
        self.assertEqual(info["acquisition"], {
            "description": build.IMAGE_NAME, "source_volume": "DATA",
            "volume_serial": "1A2B-3C4D", "source_os": "Windows 10"})
        self.assertTrue(any("logical image" in f for f in img.findings))

    def test_source_entry(self):
        _, _, source, _, _ = self.open()
        self.assertEqual(source["name"], build.SOURCE_NAME)
        self.assertEqual(source["tree_slot"], "AD1 1")
        self.assertEqual(source["filesystem"], "NTFS")
        self.assertEqual(source["source_size"], 16 << 20)
        self.assertTrue(source["is_dir"])

    def test_bad_segment_magic_is_refused(self):
        data, _ = build.build_ad1()
        with self.assertRaises(ad1.Ad1Error):
            ad1.Ad1(ewf.OffsetReader(_Bytes(b"X" + data[1:]), 0, len(data)))


class TruncatedHeaders(Ad1Case):
    """Found while fuzzing engine.ad1 after #88: a header that carries the
    right magic but is cut short before its own fields end raised
    struct.error -- not a clean exception the fuzz harness recognises as
    "this input is bad" -- instead of being refused."""

    def test_truncated_segment_header_is_refused(self):
        data, _ = build.build_ad1()
        # Past the 16-byte magic ad1.Ad1Segments checks, short of the 0x2C
        # bytes its fields need.
        path = os.path.join(self._tmp.name, "short.ad1")
        with open(path, "wb") as fh:
            fh.write(data[:32])
        with self.assertRaises(ewf.UnsupportedContainer):
            ewf.open_image(path)

    def test_truncated_logical_image_header_is_refused(self):
        data, _ = build.build_ad1()
        # The segment header (0x200 bytes) is intact; the logical image
        # header past it is cut short before its own fields end.
        path = os.path.join(self._tmp.name, "short2.ad1")
        with open(path, "wb") as fh:
            fh.write(data[:build.SEGMENT_HEADER + 32])
        with self.assertRaises(ewf.UnsupportedContainer):
            ewf.open_image(path)


class ChunkSize(Ad1Case):
    """chunk_size is an unbounded 32-bit field, read once and then used to
    size a zero-fill for every chunk that fails to decompress
    (Ad1._decompress_chunk). Found by fuzzing: an implausible value there is
    a multi-gigabyte allocation from one damaged chunk."""

    @staticmethod
    def patch_chunk_size(data, value):
        data = bytearray(data)
        struct.pack_into("<I", data, build.SEGMENT_HEADER + 0x18, value)
        return bytes(data)

    def test_huge_chunk_size_is_bounded(self):
        data, _ = build.build_ad1()
        data = self.patch_chunk_size(data, 0xFFFFFFFF)
        path = os.path.join(self._tmp.name, "huge.ad1")
        with open(path, "wb") as fh:
            fh.write(data)
        got = ewf.open_image(path)
        self.addCleanup(got.close)
        image = ad1.Ad1(got)
        self.assertLessEqual(image.chunk_size, 1 << 26)
        self.assertTrue(any("implausible" in f for f in image.findings))

    def test_zero_chunk_size_is_bounded(self):
        data, _ = build.build_ad1()
        data = self.patch_chunk_size(data, 0)
        path = os.path.join(self._tmp.name, "zero.ad1")
        with open(path, "wb") as fh:
            fh.write(data)
        got = ewf.open_image(path)
        self.addCleanup(got.close)
        image = ad1.Ad1(got)
        self.assertGreaterEqual(image.chunk_size, 1)


class Tree(Ad1Case):
    def setUp(self):
        super(Tree, self).setUp()
        self.img, self.fs, self.source, self.top, self.docs = self.open()

    def test_listing(self):
        self.assertEqual(sorted(self.top), ["Documents", "readme.txt"])
        self.assertTrue(self.top["Documents"]["is_dir"])
        self.assertEqual([e["name"] for e in self.fs.listdir(
            self.top["Documents"]["oid"])],
            ["big.bin", "empty.txt", "notes.txt"])

    def test_entry_metadata(self):
        e = self.docs["notes.txt"]
        data = build.CONTENT["Documents/notes.txt"]
        self.assertEqual(e["size"], len(data))
        self.assertEqual(e["created"], "2024-03-15T10:20:31.125Z")
        self.assertEqual(e["modified"], "2024-03-15T13:45:30.500Z")
        self.assertEqual(e["accessed"], "2024-03-16T00:00:00.000Z")
        self.assertEqual(e["md5"], hashlib.md5(data).hexdigest())
        self.assertEqual(e["sha1"], hashlib.sha1(data).hexdigest())
        self.assertFalse(e["deleted"])

    def test_file_content(self):
        for path, data in build.CONTENT.items():
            name = path.split("/")[-1]
            e = self.docs[name] if path.startswith("Documents/") \
                else self.top[name]
            with self.subTest(path):
                self.assertEqual(self.fs.read_file(e), data)
        self.assertEqual(self.fs.read_file(self.docs["big.bin"], 5000),
                         BIG[:5000])

    def test_read_range_across_chunks(self):
        e = self.docs["big.bin"]
        for off, n in ((0, 10), (CS - 5, 10), (CS + 1, 2 * CS),
                       (2 * CS + 100, 50), (len(BIG) - 3, 10)):
            with self.subTest(off=off):
                self.assertEqual(self.fs.read_range(e, off, n),
                                 BIG[off:off + n])
        self.assertEqual(self.fs.read_range(e, len(BIG), 10), b"")

    def test_stat_and_verify(self):
        e = self.docs["big.bin"]
        st = self.fs.stat(e)
        self.assertEqual(st["chunks"], build.BIG_CHUNKS)
        self.assertEqual(len(st["chunk_map"]), build.BIG_CHUNKS)
        self.assertEqual(st["stored_hashes"]["md5"], hashlib.md5(BIG).hexdigest())
        got = self.fs.verify(e)
        self.assertTrue(got["size_ok"])
        self.assertTrue(got["md5_ok"])
        self.assertTrue(got["sha1_ok"])


class DamagedChunks(Ad1Case):
    """A chunk of big.bin whose stored zlib stream is cut short or damaged.
    What was stored cannot come back, but it must be reported, and the
    chunks after it must stay at their own offsets."""

    @staticmethod
    def on_chunk(n, fn):
        def mutate(path, i, comp):
            return fn(comp) if (path, i) == ("Documents/big.bin", n) else comp
        return mutate

    def test_verify_notices_a_truncated_chunk(self):
        _, fs, _, _, docs = self.open(self.on_chunk(1, lambda c: c[:len(c) // 2]))
        got = fs.verify(docs["big.bin"])
        self.assertFalse(got["md5_ok"])

    def test_hash_object_keeps_later_chunks_in_place(self):
        # The same nominal-length padding read_object() and read_range() use,
        # so a truncated chunk changes only that chunk's hash contribution,
        # not every chunk after it.
        img, fs, _, _, docs = self.open(
            self.on_chunk(1, lambda c: c[:len(c) // 2]))
        total, digests = fs.img.hash_object(fs._object_for(docs["big.bin"]))
        self.assertEqual(total, len(BIG))
        want = docs["big.bin"]
        unaffected = fs.read_file(docs["notes.txt"])
        self.assertEqual(unaffected, build.CONTENT["Documents/notes.txt"])

    # Each chunk is padded to its own nominal length, so a chunk that
    # inflated short does not shift later chunks down.
    def test_truncated_chunk_keeps_later_chunks_in_place(self):
        img, fs, _, _, docs = self.open(
            self.on_chunk(1, lambda c: c[:len(c) // 2]))
        got = fs.read_file(docs["big.bin"])
        self.assertEqual(len(got), len(BIG))
        self.assertEqual(got[:CS], BIG[:CS])
        self.assertEqual(got[2 * CS:], BIG[2 * CS:])
        self.assertTrue(fs.img.findings)

    # A range spanning a short chunk stays aligned to the nominal chunk
    # boundaries rather than the actual (short) decompressed lengths.
    def test_range_across_a_truncated_chunk_stays_aligned(self):
        _, fs, _, _, docs = self.open(
            self.on_chunk(1, lambda c: c[:len(c) // 2]))
        e = docs["big.bin"]
        off = CS + 10
        got = fs.read_range(e, off, 2 * CS)
        self.assertEqual(len(got), min(2 * CS, len(BIG) - off))
        # Chunk 2 is unaffected by chunk 1's corruption and must still land
        # at its own nominal offset, not shifted by how short chunk 1
        # decompressed.
        self.assertEqual(got[CS - 10:], BIG[2 * CS:off + len(got)])

    # A chunk that will not inflate at all is zero-filled, not served as
    # its own compressed bytes.
    def test_chunk_that_will_not_inflate_is_not_served_raw(self):
        garbage = b"\x00not a zlib stream\x00" * 8
        _, fs, _, _, docs = self.open(self.on_chunk(1, lambda c: garbage))
        got = fs.read_file(docs["big.bin"])
        self.assertFalse(garbage[:16] in got,
                         "the chunk's raw bytes are served as content")
        self.assertEqual(got[CS:2 * CS], bytes(CS))
        self.assertEqual(got[2 * CS:], BIG[2 * CS:])
        self.assertTrue(fs.img.findings)


class _Bytes(object):
    bytes_per_sector = 512

    def __init__(self, data):
        self.data, self.size = data, len(data)

    def read_at(self, offset, length):
        if offset < 0 or length <= 0 or offset >= self.size:
            return b""
        return self.data[offset:offset + length]


if __name__ == "__main__":
    unittest.main()
