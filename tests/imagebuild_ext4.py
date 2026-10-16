"""Build small synthetic ext2/3/4 filesystem images in memory.

Nothing here is a fixture file: every image is assembled byte by byte so the
tests stay reviewable and the builders can be reused as fuzzing seeds.

Layout of the image returned by build_ext4() (block size 1024, one group):

    block 0        boot block (zero)
    block 1        superblock (byte offset 1024)
    block 2        group descriptor table (32-byte descriptors)
    block 3        block bitmap
    block 4        inode bitmap
    blocks 5-12    inode table: 32 inodes x 256 bytes
    blocks 13+     data blocks, handed out in allocation order

Superblock features: incompat FILETYPE | EXTENTS | INLINE_DATA, compat
HAS_JOURNAL, rev 1, first_ino 11, journal inode 8.  Inodes (see the INO_*
constants for the numbers and CONTENT for expected file bytes):

    2   /                  directory, extent-mapped (depth 0)
    8   journal            jbd2 journal, 16 blocks, extent-mapped
    12  extent.txt         2 blocks in one depth-0 extent
    13  deep.bin           depth-1 extent tree: index -> leaf block -> 2 extents
    14  legacy.txt         block map: 12 direct pointers + 1 single-indirect block
    15  inline.txt         inline data, fits within i_block (<= 60 bytes)
    16  inline_long.txt    inline data, first 60 bytes in i_block, rest in the
                           in-inode "system.data" extended attribute
    17  link               fast symlink -> "extent.txt"
    18  sub/               directory; holds nested.txt (inode 19)
    19  sub/nested.txt     1-block extent file
    20  sparse.bin         extents at logical 0 and 2 with a hole at logical 1
    21  deleted.txt        unlinked (links 0, dtime set, size 0, empty extent
                           header); an earlier copy of its inode table block
                           survives in journal transaction 5
    22  inlinedir/         inline-data directory holding "again.txt" -> 12

Journal (inode 8, journal-relative block numbers):

    0   jbd2 superblock v2, blocksize 1024, maxlen 16, first 1, sequence 5
    1   descriptor block, sequence 5, one tag for the inode-table block that
        holds inode 21 (tag flags LAST_TAG, UUID follows the tag)
    2   the superseded copy of that inode-table block (inode 21 live: links 1,
        size len(CONTENT["deleted.txt"]), extent -> its old data block)
    3   commit block, sequence 5
"""

import struct

BLOCK_SIZE = 1024
INODE_SIZE = 256
INODES_PER_GROUP = 32
BLOCKS_COUNT = 160
INODE_TABLE = 5
INODE_TABLE_BLOCKS = INODES_PER_GROUP * INODE_SIZE // BLOCK_SIZE
FIRST_DATA = INODE_TABLE + INODE_TABLE_BLOCKS

S_IFDIR = 0x4000
S_IFREG = 0x8000
S_IFLNK = 0xA000
FL_EXTENTS = 0x00080000
FL_INLINE_DATA = 0x10000000

INCOMPAT_FILETYPE = 0x0002
INCOMPAT_EXTENTS = 0x0040
INCOMPAT_INLINE_DATA = 0x8000
COMPAT_HAS_JOURNAL = 0x0004

JBD2_MAGIC = 0xC03B3998

MTIME = 1700000000
DTIME = 1700000500
UUID = bytes(range(16))
LABEL = b"strata-test"

INO_ROOT = 2
INO_JOURNAL = 8
INO_EXTENT = 12
INO_DEEP = 13
INO_LEGACY = 14
INO_INLINE = 15
INO_INLINE_LONG = 16
INO_LINK = 17
INO_SUB = 18
INO_NESTED = 19
INO_SPARSE = 20
INO_DELETED = 21
INO_INLINEDIR = 22

JOURNAL_BLOCKS = 16
JOURNAL_SEQUENCE = 5


def _pattern(tag, length):
    """Distinct, position-dependent filler so misplaced bytes are visible."""
    out = bytearray()
    n = 0
    while len(out) < length:
        out += ("%s:%05d|" % (tag, n)).encode("ascii")
        n += 1
    return bytes(out[:length])


CONTENT = {
    "extent.txt": _pattern("extent", 1500),
    "deep.bin": _pattern("deep", 3000),
    "legacy.txt": _pattern("legacy", 13 * BLOCK_SIZE + 100),
    "inline.txt": b"small file stored inside its own inode\n",
    "inline_long.txt": _pattern("inl", 100),
    "sub/nested.txt": b"nested file content\n",
    "sparse.bin": (_pattern("sp0", BLOCK_SIZE) + bytes(BLOCK_SIZE)
                   + _pattern("sp2", BLOCK_SIZE)),
    "deleted.txt": b"this content was deleted but the journal remembers\n",
}
LINK_TARGET = b"extent.txt"


def extent_header(entries, max_entries, depth):
    """ext4_extent_header: magic 0xF30A, entries, max, depth, generation."""
    return struct.pack("<HHHHI", 0xF30A, entries, max_entries, depth, 0)


def extent(logical, length, physical):
    """ext4_extent: ee_block, ee_len, ee_start_hi, ee_start_lo."""
    return struct.pack("<IHHI", logical, length, physical >> 32,
                       physical & 0xFFFFFFFF)


def extent_index(logical, leaf):
    """ext4_extent_idx: ei_block, ei_leaf_lo, ei_leaf_hi, unused."""
    return struct.pack("<IIHH", logical, leaf & 0xFFFFFFFF, leaf >> 32, 0)


def extent_area(extents, depth=0):
    """A 60-byte i_block holding an extent (or index) node of up to 4."""
    body = extent_header(len(extents), 4, depth) + b"".join(extents)
    return body.ljust(60, b"\x00")


def dirent(inode, name, ftype, rec_len=None):
    """ext4_dir_entry_2: inode, rec_len, name_len, file_type, name (pad 4)."""
    name = name.encode("utf-8") if isinstance(name, str) else name
    need = (8 + len(name) + 3) // 4 * 4
    rec_len = rec_len or need
    return struct.pack("<IHBB", inode, rec_len, len(name), ftype) + \
        name + bytes(rec_len - 8 - len(name))


def dir_block(entries, size=BLOCK_SIZE):
    """Pack (inode, name, ftype) dirents; the last one pads to `size`."""
    out = bytearray()
    for i, (ino, name, ftype) in enumerate(entries):
        if i == len(entries) - 1:
            raw = dirent(ino, name, ftype)
            out += dirent(ino, name, ftype, size - len(out)) \
                if size - len(out) >= len(raw) else raw
        else:
            out += dirent(ino, name, ftype)
    return bytes(out)


def inode_bytes(mode, size, i_block=b"", flags=0, links=1, dtime=0,
                xattr=b""):
    """One 256-byte inode (ext4_inode) with i_extra_isize = 32.

    `xattr` is placed at byte 160 (128 + extra_isize), i.e. the in-inode
    extended attribute area, and must include its 0xEA020000 magic.
    """
    raw = bytearray(INODE_SIZE)
    struct.pack_into("<HHIIIIIHH", raw, 0, mode, 1000, size & 0xFFFFFFFF,
                     MTIME, MTIME, MTIME, dtime, 1000, links)
    struct.pack_into("<I", raw, 32, flags)
    raw[40:100] = i_block.ljust(60, b"\x00")[:60]
    struct.pack_into("<I", raw, 108, size >> 32)
    struct.pack_into("<H", raw, 128, 32)            # i_extra_isize
    struct.pack_into("<I", raw, 144, MTIME)         # i_crtime
    raw[160:160 + len(xattr)] = xattr
    return bytes(raw)


def inline_data_xattr(value):
    """In-inode xattr area carrying one "system.data" entry.

    ext4_xattr_ibody_header (magic) then ext4_xattr_entry: name_len 4,
    name_index 7 (system), value_offs (relative to the first entry),
    value_inum 0, value_size, hash 0, name "data"; a 4-byte zero terminator;
    the value itself sits right after, padded to 4.
    """
    entry_len = 16 + 4
    value_offs = entry_len + 4
    entry = struct.pack("<BBHIII", 4, 7, value_offs, 0, len(value), 0) + b"data"
    pad = bytes((4 - len(value) % 4) % 4)
    return struct.pack("<I", 0xEA020000) + entry + bytes(4) + value + pad


class Ext4Image(object):
    """Mutable single-group image; call to_bytes() when done."""

    def __init__(self, blocks=BLOCKS_COUNT):
        self.blocks = blocks
        self.data = bytearray(blocks * BLOCK_SIZE)
        self.next_block = FIRST_DATA

    def alloc(self, count=1):
        first = self.next_block
        self.next_block += count
        if self.next_block > self.blocks:
            raise ValueError("builder ran out of blocks")
        return first

    def write_block(self, block, payload):
        if len(payload) > BLOCK_SIZE:
            raise ValueError("payload larger than a block")
        off = block * BLOCK_SIZE
        self.data[off:off + BLOCK_SIZE] = payload.ljust(BLOCK_SIZE, b"\x00")

    def write_blocks(self, first, payload):
        for i in range(0, len(payload), BLOCK_SIZE):
            self.write_block(first + i // BLOCK_SIZE, payload[i:i + BLOCK_SIZE])

    @staticmethod
    def inode_offset(num):
        return INODE_TABLE * BLOCK_SIZE + (num - 1) * INODE_SIZE

    def set_inode(self, num, raw):
        off = self.inode_offset(num)
        self.data[off:off + INODE_SIZE] = raw

    def superblock(self, incompat, compat, journal_inum=INO_JOURNAL):
        sb = bytearray(1024)
        struct.pack_into("<IIIII", sb, 0, INODES_PER_GROUP, self.blocks, 0,
                         0, INODES_PER_GROUP)
        struct.pack_into("<I", sb, 20, 1)                   # first_data_block
        struct.pack_into("<I", sb, 24, 0)                   # log_block_size
        struct.pack_into("<I", sb, 32, 8192)                # blocks_per_group
        struct.pack_into("<I", sb, 40, INODES_PER_GROUP)    # inodes_per_group
        struct.pack_into("<II", sb, 44, MTIME, MTIME)       # mtime, wtime
        sb[56:58] = b"\x53\xEF"
        struct.pack_into("<H", sb, 58, 1)                   # state: clean
        struct.pack_into("<I", sb, 76, 1)                   # rev_level
        struct.pack_into("<I", sb, 84, 11)                  # first_ino
        struct.pack_into("<H", sb, 88, INODE_SIZE)
        struct.pack_into("<III", sb, 92, compat, incompat, 0)
        sb[104:120] = UUID
        sb[120:120 + len(LABEL)] = LABEL
        sb[136:141] = b"/mnt\x00"
        struct.pack_into("<I", sb, 224, journal_inum)
        self.data[1024:2048] = sb
        gd = struct.pack("<III", 3, 4, INODE_TABLE)
        self.write_block(2, gd)

    def to_bytes(self):
        return bytes(self.data)


def journal_superblock(maxlen=JOURNAL_BLOCKS, first=1, sequence=JOURNAL_SEQUENCE):
    """journal_superblock_t v2 (big-endian)."""
    sb = bytearray(BLOCK_SIZE)
    struct.pack_into(">III", sb, 0, JBD2_MAGIC, 4, 0)
    struct.pack_into(">IIIII", sb, 12, BLOCK_SIZE, maxlen, first, sequence,
                     first)
    sb[48:64] = UUID
    struct.pack_into(">I", sb, 64, 1)
    return bytes(sb)


def journal_descriptor(sequence, fs_blocks):
    """Descriptor block with classic 8-byte tags (no 64bit, no csum).

    Tag: t_blocknr (be32), t_checksum (be16), t_flags (be16).  The first tag
    carries the 16-byte UUID after it; later tags set SAME_UUID (0x2); the
    last sets LAST_TAG (0x8).
    """
    blk = bytearray(struct.pack(">III", JBD2_MAGIC, 1, sequence))
    for i, b in enumerate(fs_blocks):
        flags = 0x2 if i else 0
        if i == len(fs_blocks) - 1:
            flags |= 0x8
        blk += struct.pack(">IHH", b, 0, flags)
        if i == 0:
            blk += UUID
    return bytes(blk)


def journal_commit(sequence):
    return struct.pack(">III", JBD2_MAGIC, 2, sequence)


def build_ext4():
    """The full test filesystem described in the module docstring."""
    img = Ext4Image()
    img.superblock(INCOMPAT_FILETYPE | INCOMPAT_EXTENTS | INCOMPAT_INLINE_DATA,
                   COMPAT_HAS_JOURNAL)

    def reg_extents(num, data):
        n = (len(data) + BLOCK_SIZE - 1) // BLOCK_SIZE
        first = img.alloc(n)
        img.write_blocks(first, data)
        img.set_inode(num, inode_bytes(S_IFREG | 0o644, len(data),
                                       extent_area([extent(0, n, first)]),
                                       FL_EXTENTS))
        return first

    reg_extents(INO_EXTENT, CONTENT["extent.txt"])

    # deep.bin: depth-1 tree. Leaf block holds two extents whose physical
    # blocks are deliberately not adjacent.
    deep = CONTENT["deep.bin"]
    leaf = img.alloc()
    a = img.alloc(2)
    img.alloc()                                   # gap on disk
    b = img.alloc()
    img.write_blocks(a, deep[:2 * BLOCK_SIZE])
    img.write_blocks(b, deep[2 * BLOCK_SIZE:])
    leaf_node = extent_header(2, (BLOCK_SIZE - 12) // 12, 0) + \
        extent(0, 2, a) + extent(2, 1, b)
    img.write_block(leaf, leaf_node)
    img.set_inode(INO_DEEP, inode_bytes(
        S_IFREG | 0o644, len(deep),
        extent_area([extent_index(0, leaf)], depth=1), FL_EXTENTS))

    # legacy.txt: 14 data blocks -> 12 direct + 2 via the indirect block.
    legacy = CONTENT["legacy.txt"]
    n = (len(legacy) + BLOCK_SIZE - 1) // BLOCK_SIZE
    first = img.alloc(n)
    img.write_blocks(first, legacy)
    ind = img.alloc()
    img.write_block(ind, struct.pack("<%dI" % (n - 12),
                                     *range(first + 12, first + n)))
    ptrs = list(range(first, first + 12)) + [ind, 0, 0]
    img.set_inode(INO_LEGACY, inode_bytes(S_IFREG | 0o644, len(legacy),
                                          struct.pack("<15I", *ptrs)))

    small = CONTENT["inline.txt"]
    img.set_inode(INO_INLINE, inode_bytes(S_IFREG | 0o644, len(small), small,
                                          FL_INLINE_DATA))
    long_ = CONTENT["inline_long.txt"]
    img.set_inode(INO_INLINE_LONG, inode_bytes(
        S_IFREG | 0o644, len(long_), long_[:60], FL_INLINE_DATA,
        xattr=inline_data_xattr(long_[60:])))

    img.set_inode(INO_LINK, inode_bytes(S_IFLNK | 0o777, len(LINK_TARGET),
                                        LINK_TARGET))

    reg_extents(INO_NESTED, CONTENT["sub/nested.txt"])
    sub = img.alloc()
    img.write_block(sub, dir_block([(INO_SUB, ".", 2), (INO_ROOT, "..", 2),
                                    (INO_NESTED, "nested.txt", 1)]))
    img.set_inode(INO_SUB, inode_bytes(S_IFDIR | 0o755, BLOCK_SIZE,
                                       extent_area([extent(0, 1, sub)]),
                                       FL_EXTENTS, links=2))

    sparse = CONTENT["sparse.bin"]
    s0 = img.alloc()
    s2 = img.alloc()
    img.write_block(s0, sparse[:BLOCK_SIZE])
    img.write_block(s2, sparse[2 * BLOCK_SIZE:])
    img.set_inode(INO_SPARSE, inode_bytes(
        S_IFREG | 0o644, len(sparse),
        extent_area([extent(0, 1, s0), extent(2, 1, s2)]), FL_EXTENTS))

    # Inline directory: 4-byte parent inode, then dirents filling i_block.
    inline_dir = struct.pack("<I", INO_ROOT) + dir_block(
        [(INO_EXTENT, "again.txt", 1)], size=56)
    img.set_inode(INO_INLINEDIR, inode_bytes(S_IFDIR | 0o755, 60, inline_dir,
                                             FL_INLINE_DATA, links=2))

    # deleted.txt: the live inode is cleared; journal holds the old one.
    old = CONTENT["deleted.txt"]
    old_block = img.alloc()
    img.write_block(old_block, old)
    img.set_inode(INO_DELETED, inode_bytes(
        S_IFREG | 0o644, len(old), extent_area([extent(0, 1, old_block)]),
        FL_EXTENTS))
    itable_block = INODE_TABLE + (INO_DELETED - 1) * INODE_SIZE // BLOCK_SIZE
    off = itable_block * BLOCK_SIZE
    superseded = bytes(img.data[off:off + BLOCK_SIZE])
    img.set_inode(INO_DELETED, inode_bytes(
        S_IFREG | 0o644, 0, extent_header(0, 4, 0), FL_EXTENTS, links=0,
        dtime=DTIME))

    root = img.alloc()
    img.write_block(root, dir_block([
        (INO_ROOT, ".", 2), (INO_ROOT, "..", 2),
        (INO_EXTENT, "extent.txt", 1), (INO_DEEP, "deep.bin", 1),
        (INO_LEGACY, "legacy.txt", 1), (INO_INLINE, "inline.txt", 1),
        (INO_INLINE_LONG, "inline_long.txt", 1), (INO_LINK, "link", 7),
        (INO_SUB, "sub", 2), (INO_SPARSE, "sparse.bin", 1),
        (INO_DELETED, "deleted.txt", 1), (INO_INLINEDIR, "inlinedir", 2),
    ]))
    img.set_inode(INO_ROOT, inode_bytes(S_IFDIR | 0o755, BLOCK_SIZE,
                                        extent_area([extent(0, 1, root)]),
                                        FL_EXTENTS, links=4))
    # The journal is allocated last so it ends the used area of the image.
    jfirst = img.alloc(JOURNAL_BLOCKS)
    img.write_block(jfirst, journal_superblock())
    img.write_block(jfirst + 1, journal_descriptor(JOURNAL_SEQUENCE,
                                                   [itable_block]))
    img.write_block(jfirst + 2, superseded)
    img.write_block(jfirst + 3, journal_commit(JOURNAL_SEQUENCE))
    img.set_inode(INO_JOURNAL, inode_bytes(
        S_IFREG | 0o600, JOURNAL_BLOCKS * BLOCK_SIZE,
        extent_area([extent(0, JOURNAL_BLOCKS, jfirst)]), FL_EXTENTS))

    return img.to_bytes()


def build_ext4_truncated_journal():
    """build_ext4() with journal block 1 turned into a revoke block and the
    image cut 14 bytes into that block (an interrupted acquisition).  Every
    structure outside the journal is still intact."""
    data = bytearray(build_ext4())
    jfirst = journal_first_block(data)
    at = (jfirst + 1) * BLOCK_SIZE
    data[at:at + 16] = struct.pack(">IIII", JBD2_MAGIC, 5, JOURNAL_SEQUENCE, 20)
    return bytes(data[:at + 14])


def journal_first_block(image):
    """Physical block of journal block 0 (reads inode 8's single extent)."""
    off = Ext4Image.inode_offset(INO_JOURNAL) + 40 + 12
    return struct.unpack_from("<I", image, off + 8)[0]


def build_ext2_legacy():
    """An ext2 image (no extents, no journal): root dir and one file, both
    mapped by direct block pointers.  File is inode 12, "hello.txt"."""
    img = Ext4Image(blocks=64)
    img.superblock(INCOMPAT_FILETYPE, 0, journal_inum=0)
    data = b"hello from ext2\n"
    blk = img.alloc()
    img.write_block(blk, data)
    img.set_inode(12, inode_bytes(S_IFREG | 0o644, len(data),
                                  struct.pack("<15I", blk, *([0] * 14))))
    root = img.alloc()
    img.write_block(root, dir_block([(2, ".", 2), (2, "..", 2),
                                     (12, "hello.txt", 1)]))
    img.set_inode(2, inode_bytes(S_IFDIR | 0o755, BLOCK_SIZE,
                                 struct.pack("<15I", root, *([0] * 14)),
                                 links=2))
    return img.to_bytes()


def build_ext4_extent_loop():
    """Hostile image: inode 12 is a depth-1 extent tree whose index points at
    an index block that points (84 times) back at itself with depth 1."""
    img = Ext4Image(blocks=64)
    img.superblock(INCOMPAT_FILETYPE | INCOMPAT_EXTENTS, 0, journal_inum=0)
    loop = img.alloc()
    fan = (BLOCK_SIZE - 12) // 12
    img.write_block(loop, extent_header(fan, fan, 1)
                    + extent_index(0, loop) * fan)
    img.set_inode(12, inode_bytes(S_IFREG | 0o644, 4096,
                                  extent_area([extent_index(0, loop)], 1),
                                  FL_EXTENTS))
    return img.to_bytes()


def xattr_entries_area(entries, value_base):
    """The entry array + zero terminator + values for an
    ext4_xattr_entry list (see engine.fs.ext4._xattr_entries):
    `entries` is [(name_index, name_bytes, value_bytes), ...].
    `value_base` is what e_value_offs is measured from -- 0 for an
    in-inode list (offsets count from right after the ibody magic) or 32
    for an external block (offsets count from the start of the block,
    i.e. past its own 32-byte header)."""
    padded = [(index, name, value, (-(16 + len(name))) % 4)
              for index, name, value in entries]
    entries_len = sum(16 + len(name) + pad for _, name, _, pad in padded)
    cursor = value_base + entries_len + 4
    out_entries = bytearray()
    out_values = bytearray()
    for index, name, value, pad in padded:
        out_entries += struct.pack("<BBHIII", len(name), index, cursor, 0,
                                   len(value), 0) + name + bytes(pad)
        vpad = (-len(value)) % 4
        out_values += value + bytes(vpad)
        cursor += len(value) + vpad
    return bytes(out_entries) + bytes(4) + bytes(out_values)


def inline_xattr_multi(entries):
    """In-inode xattr area carrying several entries (see inline_data_xattr
    for the original single-entry version this generalises)."""
    return struct.pack("<I", 0xEA020000) + xattr_entries_area(entries, 0)


def xattr_block(entries):
    """A whole external xattr block (ext4_xattr_header + entries), for an
    inode whose i_file_acl points at it."""
    header = struct.pack("<IIII", 0xEA020000, 1, 1, 0) + bytes(16)
    return (header + xattr_entries_area(entries, 32)).ljust(BLOCK_SIZE,
                                                             b"\x00")


INO_XATTR_INLINE = 12
INO_XATTR_BLOCK = 13


def build_ext4_xattrs():
    """root dir, an inode with several in-inode extended attributes
    ("xattrs.txt", inode 12), and an inode whose attributes live in an
    external block via i_file_acl ("xattrs-ext.txt", inode 13, block
    xattr holding "trusted.origin")."""
    img = Ext4Image(blocks=64)
    img.superblock(INCOMPAT_FILETYPE | INCOMPAT_EXTENTS, 0, journal_inum=0)

    inline_raw = bytearray(inode_bytes(
        S_IFREG | 0o644, 0, b"", xattr=inline_xattr_multi([
            (1, b"comment", b"hello world"),
            (6, b"selinux", b"unconfined_u"),
        ])))
    img.set_inode(INO_XATTR_INLINE, bytes(inline_raw))

    block = img.alloc()
    img.write_block(block, xattr_block([(4, b"origin", b"remote-server")]))
    ext_raw = bytearray(inode_bytes(S_IFREG | 0o644, 0, b""))
    struct.pack_into("<I", ext_raw, 104, block)         # i_file_acl_lo
    img.set_inode(INO_XATTR_BLOCK, bytes(ext_raw))

    root = img.alloc()
    img.write_block(root, dir_block([
        (2, ".", 2), (2, "..", 2),
        (INO_XATTR_INLINE, "xattrs.txt", 1),
        (INO_XATTR_BLOCK, "xattrs-ext.txt", 1),
    ]))
    img.set_inode(2, inode_bytes(S_IFDIR | 0o755, BLOCK_SIZE,
                                 struct.pack("<15I", root, *([0] * 14)),
                                 links=2))
    return img.to_bytes()
