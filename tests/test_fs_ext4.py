"""Unit tests for the ext2/3/4 reader (engine.fs.ext4) and jbd2 journal
(engine.fs.jbd2), fed synthetic images from imagebuild_ext4."""

import os
import shutil
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import imagebuild_ext4 as build                                   # noqa: E402
from engine.ewf import OffsetReader, open_image, RawImage         # noqa: E402
from engine.fs import ext4                                        # noqa: E402
from engine.fs.ntfs import open_fs                                # noqa: E402


class MemImage(object):
    """The read_at/size surface an image object offers, over bytes."""

    bytes_per_sector = 512

    def __init__(self, data, read_budget=None):
        self.data = data
        self.size = len(data)
        self.reads = 0
        self.read_budget = read_budget

    def read_at(self, offset, length):
        self.reads += 1
        if self.read_budget is not None and self.reads > self.read_budget:
            raise RuntimeError("read budget exhausted (runaway traversal)")
        if offset < 0 or offset >= self.size:
            return b""
        return self.data[offset:offset + length]


def mount(data, offset=0, **kw):
    """Open a filesystem the way the server does: OffsetReader -> open_fs."""
    img = MemImage(data, **kw)
    return open_fs(OffsetReader(img, offset, img.size - offset))


class Ext4Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = build.build_ext4()

    def setUp(self):
        self.fs = mount(self.image)
        self.root = {e["name"]: e for e in self.fs.listdir(2, "/")}


class Superblock(Ext4Fixture):
    def test_open_fs_detects_ext4(self):
        self.assertIsInstance(self.fs, ext4.Ext4FS)
        self.assertEqual(self.fs.name, "ext4")

    def test_info_reports_superblock_fields(self):
        info = self.fs.info()
        self.assertEqual(info["type"], "ext4")
        self.assertEqual(info["label"], "strata-test")
        self.assertEqual(info["uuid"], build.UUID.hex())
        self.assertEqual(info["block_size"], 1024)
        self.assertEqual(info["blocks"], build.BLOCKS_COUNT)
        self.assertEqual(info["inodes"], build.INODES_PER_GROUP)
        self.assertEqual(info["inode_size"], 256)
        self.assertEqual(info["groups"], 1)
        self.assertEqual(info["first_inode"], 11)
        self.assertEqual(info["last_mounted"], "/mnt")
        self.assertTrue(info["clean"])
        self.assertEqual(info["journal_inode"], 8)
        for feat in ("extents", "inline_data", "filetype", "has_journal"):
            self.assertIn(feat, info["features"])

    def test_ext2_without_extents_or_journal(self):
        fs = mount(build.build_ext2_legacy())
        self.assertEqual(fs.name, "ext2")
        entries = fs.listdir(2)
        self.assertEqual([e["name"] for e in entries], ["hello.txt"])
        self.assertEqual(fs.read_file(entries[0]), b"hello from ext2\n")
        self.assertFalse(fs.journal_info()["present"])

    def test_through_open_image_on_disk(self):
        tmp = tempfile.mkdtemp(prefix="strata-ext4-test-")
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        path = os.path.join(tmp, "disk.dd")
        pad = bytes(4096)                  # filesystem starts at 4096
        with open(path, "wb") as fh:
            fh.write(pad + self.image)
        img = open_image(path)
        self.addCleanup(img.close)
        self.assertIsInstance(img, RawImage)
        fs = open_fs(OffsetReader(img, len(pad), img.size - len(pad)))
        entry = {e["name"]: e for e in fs.listdir(2)}["extent.txt"]
        self.assertEqual(fs.read_file(entry), build.CONTENT["extent.txt"])


class Inodes(Ext4Fixture):
    def test_inode_fields(self):
        ino = self.fs.inode(build.INO_EXTENT)
        self.assertEqual(ino.size, 1500)
        self.assertEqual(ino.uid, 1000)
        self.assertEqual(ino.links, 1)
        self.assertTrue(ino.uses_extents)
        self.assertFalse(ino.deleted)
        self.assertEqual(ino.mtime, "2023-11-14T22:13:20Z")
        self.assertEqual(ino.crtime, "2023-11-14T22:13:20Z")
        self.assertEqual(ino.table_offset, build.Ext4Image.inode_offset(12))

    def test_out_of_range_inode_is_none(self):
        self.assertIsNone(self.fs.inode(0))
        self.assertIsNone(self.fs.inode(build.INODES_PER_GROUP + 1))


class Directories(Ext4Fixture):
    def test_root_listing(self):
        self.assertEqual(
            sorted(self.root),
            sorted(["extent.txt", "deep.bin", "legacy.txt", "inline.txt",
                    "inline_long.txt", "link", "sub", "sparse.bin",
                    "deleted.txt", "inlinedir"]))
        self.assertNotIn(".", self.root)
        self.assertNotIn("..", self.root)

    def test_directories_sort_first(self):
        names = [e["name"] for e in self.fs.listdir(2)]
        dirs = [n for n in names if self.root[n]["is_dir"]]
        self.assertEqual(names[:len(dirs)], sorted(dirs))

    def test_entry_metadata(self):
        e = self.root["extent.txt"]
        self.assertEqual(e["path"], "/extent.txt")
        self.assertEqual(e["inode"], build.INO_EXTENT)
        self.assertEqual(e["size"], 1500)
        self.assertEqual(e["mode"], "-rw-r--r--")
        self.assertEqual(e["type"], "file")
        self.assertEqual(e["id"], "ext:12")
        self.assertFalse(e["deleted"])
        self.assertFalse(e["system"])
        self.assertTrue(self.root["sub"]["is_dir"])
        self.assertEqual(self.root["sub"]["mode"], "drwxr-xr-x")
        self.assertEqual(self.root["link"]["type"], "symlink")

    def test_subdirectory(self):
        entries = self.fs.listdir(build.INO_SUB, "/sub")
        self.assertEqual([e["name"] for e in entries], ["nested.txt"])
        self.assertEqual(entries[0]["path"], "/sub/nested.txt")
        self.assertEqual(self.fs.read_file(entries[0]),
                         build.CONTENT["sub/nested.txt"])

    def test_listdir_of_a_file_is_empty(self):
        self.assertEqual(self.fs.listdir(build.INO_EXTENT), [])

    # An inline directory's i_block opens with a 4-byte parent inode number.
    def test_inline_directory(self):
        entries = self.fs.listdir(build.INO_INLINEDIR, "/inlinedir")
        self.assertEqual([(e["name"], e["inode"]) for e in entries],
                         [("again.txt", build.INO_EXTENT)])

    def test_inline_directory_spilling_into_xattr(self):
        head = struct.pack("<I", build.INO_ROOT) + build.dir_block(
            [(build.INO_EXTENT, "again.txt", 1)], size=56)
        more = build.dir_block([(build.INO_LEGACY, "legacy.txt", 1),
                                (build.INO_INLINE, "inline.txt", 1)], size=40)
        raw = build.inode_bytes(
            build.S_IFDIR | 0o755, 60 + len(more), head, build.FL_INLINE_DATA,
            links=2, xattr=build.inline_data_xattr(more))
        ino = ext4.Inode(99, raw, self.fs)
        self.assertEqual([(n, i) for i, n, _ in self.fs._dir_entries(ino)],
                         [("again.txt", build.INO_EXTENT),
                          ("legacy.txt", build.INO_LEGACY),
                          ("inline.txt", build.INO_INLINE)])


class FileContent(Ext4Fixture):
    def read(self, name):
        return self.fs.read_file(self.root[name])

    def test_extent_depth0(self):
        self.assertEqual(self.read("extent.txt"), build.CONTENT["extent.txt"])
        self.assertEqual(self.fs.stat(self.root["extent.txt"])["mapping"],
                         "extent tree")

    def test_extent_depth1(self):
        self.assertEqual(self.read("deep.bin"), build.CONTENT["deep.bin"])
        runs = self.fs.runs(self.fs.inode(build.INO_DEEP))
        self.assertEqual([r["blocks"] for r in runs], [2, 1])
        self.assertEqual(runs[1]["block"] - runs[0]["block"], 3)

    def test_legacy_block_map_with_indirect_block(self):
        self.assertEqual(self.read("legacy.txt"), build.CONTENT["legacy.txt"])
        st = self.fs.stat(self.root["legacy.txt"])
        self.assertEqual(st["mapping"], "indirect blocks")
        self.assertEqual(sum(r["blocks"] for r in st["runs"]), 14)
        self.assertEqual(st["slack"]["length"], 1024 - 100)

    def test_inline_data_small(self):
        self.assertEqual(self.read("inline.txt"), build.CONTENT["inline.txt"])
        self.assertTrue(self.root["inline.txt"]["inline"])
        st = self.fs.stat(self.root["inline.txt"])
        self.assertEqual(st["mapping"], "inline")

    # Inline data past 60 bytes lives in the "system.data" xattr.
    def test_inline_data_spilling_into_xattr(self):
        self.assertEqual(self.read("inline_long.txt"),
                         build.CONTENT["inline_long.txt"])

    def test_damaged_inline_xattr_gives_nothing_past_i_block(self):
        long_ = build.CONTENT["inline_long.txt"]
        good = bytearray(build.inode_bytes(
            build.S_IFREG | 0o644, len(long_), long_[:60],
            build.FL_INLINE_DATA,
            xattr=build.inline_data_xattr(long_[60:])))

        def damaged(at, value):
            raw = bytearray(good)
            raw[at:at + len(value)] = value
            return bytes(raw)

        cases = {
            "no magic": damaged(160, b"\x00\x00\x00\x00"),
            "extra_isize past the inode": damaged(128, b"\xFF\xFF"),
            "other attribute name": damaged(180, b"dat!"),
            "value stored in another inode": damaged(168, b"\x0C\x00"),
            "name overrunning the inode": damaged(164, b"\xFF"),
        }
        for label, raw in cases.items():
            with self.subTest(label):
                ino = ext4.Inode(99, raw, self.fs)
                self.assertEqual(ino.inline_xattr(), b"")
                self.assertEqual(self.fs.read_inode_data(ino), long_[:60])
        value_past_end = damaged(166, b"\xF0\x00")
        ino = ext4.Inode(99, value_past_end, self.fs)
        self.assertEqual(ino.inline_xattr(), b"")

    def test_fast_symlink(self):
        self.assertEqual(self.read("link"), build.LINK_TARGET)

    def test_read_range(self):
        data = build.CONTENT["legacy.txt"]
        self.assertEqual(
            self.fs.read_range(self.root["legacy.txt"], 12000, 2000),
            data[12000:14000])
        self.assertEqual(
            self.fs.read_range(self.root["inline.txt"], 6, 4),
            build.CONTENT["inline.txt"][6:10])

    def test_max_bytes(self):
        self.assertEqual(self.fs.read_file(self.root["deep.bin"], 10),
                         build.CONTENT["deep.bin"][:10])

    def test_named_stream_unsupported(self):
        with self.assertRaises(ValueError):
            self.fs.read_file(self.root["extent.txt"], stream="ads")

    def test_sparse_extent_hole_reads_as_zeros(self):
        self.assertEqual(self.read("sparse.bin"), build.CONTENT["sparse.bin"])

    def test_range_read_after_a_hole(self):
        bs = self.fs.block_size
        self.assertEqual(
            self.fs.read_range(self.root["sparse.bin"], 2 * bs, bs),
            build.CONTENT["sparse.bin"][2 * bs:])

    def test_trailing_hole_reads_as_zeros_without_slack(self):
        # Grow the inode past its last extent: the extra block is a hole.
        bs = self.fs.block_size
        entry = self.root["sparse.bin"]
        ino = self.fs.inode(entry["inode"])
        size = len(build.CONTENT["sparse.bin"]) + bs + 10
        data = bytearray(self.image)
        struct.pack_into("<I", data, ino.table_offset + 4, size)
        fs = mount(bytes(data))
        grown = {e["name"]: e for e in fs.listdir(2)}["sparse.bin"]
        self.assertEqual(grown["size"], size)
        self.assertEqual(fs.read_file(grown),
                         build.CONTENT["sparse.bin"]
                         + bytes(size - len(build.CONTENT["sparse.bin"])))
        self.assertNotIn("slack", fs.stat(grown))


class Journal(Ext4Fixture):
    def test_journal_info(self):
        info = self.fs.journal_info()
        self.assertTrue(info["present"])
        self.assertEqual(info["blocks"], build.JOURNAL_BLOCKS)
        self.assertEqual(info["sequence"], build.JOURNAL_SEQUENCE)
        self.assertEqual(info["uuid"], build.UUID.hex())
        self.assertEqual(info["transactions"], 1)
        self.assertEqual(info["committed"], 1)
        self.assertEqual(info["blocks_journalled"], 1)
        self.assertEqual(info["findings"], [])

    def test_deleted_inode_is_flagged(self):
        e = self.root["deleted.txt"]
        self.assertTrue(e["deleted"])
        self.assertEqual(e["deleted_at"], "2023-11-14T22:21:40Z")
        self.assertEqual(e["size"], 0)

    def test_superseded_inode_version_found(self):
        versions = self.fs.journal.inode_versions(build.INO_DELETED)
        self.assertEqual(len(versions), 1)
        v = versions[0]
        self.assertEqual(v["sequence"], build.JOURNAL_SEQUENCE)
        self.assertTrue(v["committed"])
        self.assertFalse(v["deleted"])
        self.assertEqual(v["size"], len(build.CONTENT["deleted.txt"]))

    def test_stat_reports_journal_recovery(self):
        st = self.fs.stat(self.root["deleted.txt"])
        rec = st["journal_recovery"]
        self.assertEqual(rec["sequence"], build.JOURNAL_SEQUENCE)
        self.assertTrue(rec["committed"])
        self.assertEqual(st["recovered_size"],
                         len(build.CONTENT["deleted.txt"]))
        self.assertIn("journal", st["recovery"])

    def test_read_file_returns_recovered_content(self):
        self.assertEqual(self.fs.read_file(self.root["deleted.txt"]),
                         build.CONTENT["deleted.txt"])

    def test_no_recovery_for_inode_not_in_journal(self):
        self.assertIsNone(self.fs.journal.recover(build.INO_EXTENT))


class Robustness(unittest.TestCase):
    def test_garbage_is_rejected(self):
        with self.assertRaises(ValueError):
            ext4.Ext4FS(MemImage(bytes(range(256)) * 16))

    def test_empty_source(self):
        with self.assertRaises(ValueError):
            ext4.Ext4FS(MemImage(b""))

    def test_zero_group_sizing_is_rejected(self):
        data = bytearray(build.build_ext4())
        data[1024 + 32:1024 + 36] = bytes(4)          # blocks_per_group
        with self.assertRaises(ValueError):
            ext4.Ext4FS(MemImage(bytes(data)))

    def test_truncated_after_superblock(self):
        fs = ext4.Ext4FS(MemImage(build.build_ext4()[:2048]))
        self.assertEqual(fs.listdir(2), [])
        self.assertIsNone(fs.inode(12))
        self.assertFalse(fs.journal_info()["present"])

    def test_truncated_inside_inode_table(self):
        fs = ext4.Ext4FS(MemImage(build.build_ext4()[:7 * 1024]))
        self.assertEqual(fs.listdir(2), [])

    def test_directory_with_inflated_size_gets_no_holes(self):
        # Directories are read whole on every listing; a corrupt size must
        # not turn into gigabytes of hole to zero-fill.
        data = bytearray(build.build_ext4())
        ino = mount(bytes(data)).inode(2)
        struct.pack_into("<I", data, ino.table_offset + 4, 256 << 20)
        fs = mount(bytes(data))
        self.assertEqual(fs.inode(2).size, 256 << 20)
        self.assertFalse(any(r["sparse"] for r in fs.runs(fs.inode(2))))
        self.assertIn("extent.txt", [e["name"] for e in fs.listdir(2)])

    def test_corrupt_extent_magic_gives_no_runs(self):
        data = bytearray(build.build_ext4())
        off = build.Ext4Image.inode_offset(build.INO_EXTENT) + 40
        data[off:off + 2] = b"\x00\x00"
        fs = mount(bytes(data))
        self.assertEqual(fs.runs(fs.inode(build.INO_EXTENT)), [])

    def test_directory_with_zero_rec_len_terminates(self):
        data = bytearray(build.build_ext4())
        fs = mount(bytes(data))
        root_block = fs.runs(fs.inode(2))[0]["block"]
        data[root_block * 1024 + 4:root_block * 1024 + 6] = b"\x00\x00"
        self.assertEqual(mount(bytes(data)).listdir(2), [])

    # A self-referencing index node would cost 84 ** 7 reads if every
    # pointer were followed; each index block is read once instead.
    def test_self_referencing_extent_index_is_bounded(self):
        fs = mount(build.build_ext4_extent_loop(), read_budget=20000)
        self.assertEqual(fs.runs(fs.inode(12)), [
            {"offset": 0, "length": 4 * 1024, "block": 0, "blocks": 4,
             "logical": 0, "sparse": True, "initialised": True,
             "used": 4096}])

    def test_index_nodes_shared_across_a_wide_tree_are_read_once(self):
        # Depths are consistent, so only revisit tracking bounds this:
        # 4 * 84 * 84 paths all lead to one leaf holding one extent.
        img = build.Ext4Image(blocks=64)
        img.superblock(build.INCOMPAT_FILETYPE | build.INCOMPAT_EXTENTS, 0,
                       journal_inum=0)
        fan = (build.BLOCK_SIZE - 12) // 12
        a, b, leaf, data = img.alloc(), img.alloc(), img.alloc(), img.alloc()
        img.write_block(data, b"shared leaf data")
        img.write_block(leaf, build.extent_header(1, fan, 0)
                        + build.extent(0, 1, data))
        img.write_block(b, build.extent_header(fan, fan, 1)
                        + build.extent_index(0, leaf) * fan)
        img.write_block(a, build.extent_header(fan, fan, 2)
                        + build.extent_index(0, b) * fan)
        img.set_inode(12, build.inode_bytes(
            build.S_IFREG | 0o644, 16,
            build.extent_area([build.extent_index(0, a)] * 4, 3),
            build.FL_EXTENTS))
        fs = mount(img.to_bytes(), read_budget=20000)
        runs = fs.runs(fs.inode(12))
        self.assertEqual([(r["block"], r["blocks"]) for r in runs],
                         [(data, 1)])
        self.assertEqual(fs.read_file({"inode": 12}), b"shared leaf data")

    def test_truncated_journal_is_reported_absent(self):
        fs = mount(build.build_ext4_truncated_journal())
        info = fs.journal_info()
        self.assertFalse(info["present"])
        self.assertTrue(info["findings"])
        self.assertIn("extent.txt", [e["name"] for e in fs.listdir(2)])

    def test_deleted_file_read_with_unreadable_journal(self):
        fs = mount(build.build_ext4_truncated_journal())
        entry = {e["name"]: e for e in fs.listdir(2)}["deleted.txt"]
        self.assertEqual(fs.read_file(entry), b"")

    def test_invalid_journal_answers_without_raising(self):
        # ext2 has no journal, so Journal._load() returns early and the
        # object is left invalid; its entry points must still answer.
        journal = mount(build.build_ext2_legacy()).journal
        self.assertFalse(journal.valid)
        self.assertEqual(journal.inode_versions(12), [])
        self.assertIsNone(journal.recover(12))
        self.assertEqual(journal.read_recovered(12), b"")


class ExtendedAttributes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = build.build_ext4_xattrs()

    def setUp(self):
        self.fs = mount(self.image)

    def test_in_inode_xattrs_are_listed_with_prefix_and_value(self):
        ino = self.fs.inode(build.INO_XATTR_INLINE)
        attrs = {a["name"]: a for a in ino.xattrs()}
        self.assertEqual(attrs["user.comment"]["value"], b"hello world")
        self.assertEqual(attrs["user.comment"]["size"], len(b"hello world"))
        self.assertFalse(attrs["user.comment"]["truncated"])
        self.assertEqual(attrs["security.selinux"]["value"], b"unconfined_u")

    def test_external_block_xattrs_are_read_via_i_file_acl(self):
        ino = self.fs.inode(build.INO_XATTR_BLOCK)
        attrs = {a["name"]: a for a in ino.xattrs()}
        self.assertEqual(attrs["trusted.origin"]["value"], b"remote-server")
        self.assertNotIn("user.comment", attrs)

    def test_a_file_with_no_xattr_area_reports_none(self):
        self.assertEqual(self.fs.inode(2).xattrs(), [])

    def test_a_value_over_the_cap_is_truncated(self):
        ino = self.fs.inode(build.INO_XATTR_INLINE)
        attrs = {a["name"]: a for a in ino.xattrs(max_value=5)}
        self.assertEqual(attrs["user.comment"]["value"], b"hello")
        self.assertEqual(attrs["user.comment"]["size"], len(b"hello world"))
        self.assertTrue(attrs["user.comment"]["truncated"])

    def test_system_data_is_not_listed_as_an_attribute(self):
        # system.data is inline file content in this same entry format,
        # not something an examiner asking for "attributes" wants to see
        # twice -- confirmed against the main fixture image, which
        # already has one (inline_long.txt).
        fs = mount(build.build_ext4())
        ino = fs.inode(build.INO_INLINE_LONG)
        names = {a["name"] for a in ino.xattrs()}
        self.assertNotIn("system.data", names)
        self.assertEqual(ino.inline_xattr(),
                         build.CONTENT["inline_long.txt"][60:])

    def test_stat_reports_xattrs_json_safely(self):
        # stat() feeds /api/stat directly; a raw bytes value would fail
        # to serialise cleanly to JSON (json.dumps's default=str fallback
        # would show a literal "b'...'" repr instead of the value).
        import base64
        entry = {"inode": build.INO_XATTR_INLINE}
        info = self.fs.stat(entry)
        attrs = {a["name"]: a for a in info["xattrs"]}
        self.assertEqual(base64.b64decode(attrs["user.comment"]["value"]),
                         b"hello world")
        self.assertEqual(attrs["user.comment"]["size"], len(b"hello world"))

    def test_stat_omits_xattrs_entirely_when_there_are_none(self):
        info = self.fs.stat({"inode": 2})
        self.assertNotIn("xattrs", info)


if __name__ == "__main__":
    unittest.main()
