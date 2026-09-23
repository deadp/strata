"""Build a synthetic single-segment AccessData logical image (AD1) in memory.

Laid out as engine/ad1.py reads it. Offsets marked "rel" are relative to the
start of the logical image header, i.e. the segment header's length.

Segment header (0x200 bytes):

    0x00  "ADSEGMENTEDFILE\\0"     0x10  version (u32)
    0x18  segment index (u32, 1)  0x1C  segment count (u32)
    0x28  segment header length (u32, 0x200)

Logical image header (rel 0):

    0x00  "ADLOGICALIMAGE\\0\\0"    0x10  version (u32, 4)
    0x18  chunk size (u32)        0x24  first source record (u64, rel)
    0x2C  image name length (u32) 0x34  image name (u64, rel)

Source record: next (u64), root object (u64), metadata chain (u64),
reserved (0x10), kind (u32 @0x28), name length (u32 @0x2C), name (@0x30).
The name reads "image:Partition N [size]:volume [fs]".

Object: next sibling (u64), first child (u64), metadata chain (u64), chunk
table (u64), logical size (u64), type (u32 @0x28: 0 file, 5 folder), name
length (u32 @0x2C), name (@0x30). All offsets rel; 0 means none.

Chunk table: count (u64), then count + 1 offsets (u64, rel); chunk n is the
zlib stream from offset n to offset n + 1, inflating to at most the chunk
size.

Metadata record: next (u64), category (u32), key (u32), value length (u32),
value (UTF-8). Category 5 values are timestamps "YYYYMMDDThhmmss.fff".
Keys used: 0x0003 logical size, 0x0007/8/9 created/modified/accessed,
0x5001 MD5, 0x5002 SHA-1 (lower-case hex); on the source record 0x9005
volume name, 0x9006 serial, 0x900C source OS.

Tree built by build_ad1():

    source "disk.E01:Partition 1 [16MB]:DATA [NTFS]"
      Documents/                          folder
        notes.txt                         one chunk
        big.bin                           BIG_CHUNKS chunks, the last short
        empty.txt                         no chunks
      readme.txt                          one chunk
"""

import hashlib
import struct
import zlib

SEGMENT_HEADER = 0x200
CHUNK_SIZE = 4096
BIG_CHUNKS = 3
IMAGE_NAME = "synthetic logical image"
SOURCE_NAME = "disk.E01:Partition 1 [16MB]:DATA [NTFS]"

TYPE_FILE = 0
TYPE_DIR = 5

CREATED = "20240315T102031.125"
MODIFIED = "20240315T134530.500"
ACCESSED = "20240316T000000.000"


def big_content():
    out = bytearray()
    n = 0
    while len(out) < CHUNK_SIZE * (BIG_CHUNKS - 1) + 1234:
        out += ("big.bin block %05d " % n).encode("ascii")
        out += bytes((n * 13 + k * 7) & 0xFF for k in range(40))
        n += 1
    return bytes(out[:CHUNK_SIZE * (BIG_CHUNKS - 1) + 1234])


CONTENT = {
    "Documents/notes.txt": b"meeting notes\nsecond line\n",
    "Documents/big.bin": big_content(),
    "Documents/empty.txt": b"",
    "readme.txt": b"read me first\n",
}


class _Writer:
    """Appends records to the logical image; offsets are rel."""

    def __init__(self):
        self.buf = bytearray(0x200)          # logical image header area

    def at(self):
        return len(self.buf)

    def put(self, data):
        rel = len(self.buf)
        self.buf += data
        return rel

    def patch_u64(self, rel, value):
        struct.pack_into("<Q", self.buf, rel, value)


def _meta_chain(w, items):
    """items: [(category, key, text)] -> rel of the first record."""
    first = 0
    prev_next = None
    for category, key, text in items:
        value = text.encode("utf-8")
        rel = w.put(struct.pack("<QIII", 0, category, key, len(value)) + value)
        if prev_next is None:
            first = rel
        else:
            w.patch_u64(prev_next, rel)
        prev_next = rel
    return first


def _file_meta(w, data):
    return _meta_chain(w, [
        (1, 0x0003, str(len(data))),
        (5, 0x0007, CREATED), (5, 0x0008, MODIFIED), (5, 0x0009, ACCESSED),
        (1, 0x5001, hashlib.md5(data).hexdigest()),
        (1, 0x5002, hashlib.sha1(data).hexdigest()),
    ])


def _chunks(w, data, chunk_mutator, name):
    if not data:
        return 0
    comps = []
    for n, i in enumerate(range(0, len(data), CHUNK_SIZE)):
        comp = zlib.compress(data[i:i + CHUNK_SIZE], 6)
        if chunk_mutator:
            comp = chunk_mutator(name, n, comp)
        comps.append(comp)
    table = w.at()
    w.put(bytes(8 * (len(comps) + 2)))        # count + (count + 1) offsets
    offsets = []
    for comp in comps:
        offsets.append(w.put(comp))
    offsets.append(w.at())
    struct.pack_into("<Q", w.buf, table, len(comps))
    struct.pack_into("<%dQ" % len(offsets), w.buf, table + 8, *offsets)
    return table


def _object(w, kind, name, data=b"", chunk_mutator=None, path=""):
    meta = _file_meta(w, data) if kind == TYPE_FILE else \
        _meta_chain(w, [(5, 0x0007, CREATED), (5, 0x0008, MODIFIED)])
    table = _chunks(w, data, chunk_mutator, path) if kind == TYPE_FILE else 0
    raw = name.encode("utf-8")
    return w.put(struct.pack("<5QII", 0, 0, meta, table, len(data), kind,
                             len(raw)) + raw)


def _link_siblings(w, rels):
    for a, b in zip(rels, rels[1:]):
        w.patch_u64(a, b)


def build_ad1(chunk_mutator=None):
    """Single-segment AD1: (bytes, layout).

    `chunk_mutator(path, n, compressed) -> compressed` may alter a stored
    chunk; the chunk table records the altered length. layout maps each path
    to its object's rel offset, plus "chunk_size" and "base".
    """
    w = _Writer()
    layout = {"chunk_size": CHUNK_SIZE, "base": SEGMENT_HEADER}

    docs_children = []
    for name in ("notes.txt", "big.bin", "empty.txt"):
        path = "Documents/" + name
        rel = _object(w, TYPE_FILE, name, CONTENT[path], chunk_mutator, path)
        layout[path] = rel
        docs_children.append(rel)
    _link_siblings(w, docs_children)

    docs = _object(w, TYPE_DIR, "Documents")
    w.patch_u64(docs + 8, docs_children[0])
    layout["Documents"] = docs
    readme = _object(w, TYPE_FILE, "readme.txt", CONTENT["readme.txt"],
                     chunk_mutator, "readme.txt")
    layout["readme.txt"] = readme
    _link_siblings(w, [docs, readme])

    src_meta = _meta_chain(w, [(1, 0x9005, "DATA"), (1, 0x9006, "1A2B-3C4D"),
                               (1, 0x900C, "Windows 10")])
    raw = SOURCE_NAME.encode("utf-8")
    source = w.put(struct.pack("<3Q16xII", 0, docs, src_meta, 0, len(raw))
                   + raw)
    layout["source"] = source

    name = IMAGE_NAME.encode("utf-8")
    name_rel = w.put(name)
    h = w.buf
    h[0:16] = b"ADLOGICALIMAGE\x00\x00"
    struct.pack_into("<I", h, 0x10, 4)
    struct.pack_into("<I", h, 0x18, CHUNK_SIZE)
    struct.pack_into("<Q", h, 0x24, source)
    struct.pack_into("<I", h, 0x2C, len(name))
    struct.pack_into("<Q", h, 0x34, name_rel)

    seg = bytearray(SEGMENT_HEADER)
    seg[0:16] = b"ADSEGMENTEDFILE\x00"
    struct.pack_into("<I", seg, 0x10, 1)
    struct.pack_into("<II", seg, 0x18, 1, 1)
    struct.pack_into("<I", seg, 0x28, SEGMENT_HEADER)
    return bytes(seg) + bytes(w.buf), layout
