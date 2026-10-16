"""Build synthetic Windows registry hives (regf) and transaction logs.

Formats follow Maxim Suhanov's "Windows registry file format specification".

Hive file:

    0x0000  base block (4096 bytes): "regf", primary seq (4), secondary seq
            (4), last written FILETIME (8), major 1, minor 5, type 0,
            format 1, root cell offset (4, @36), hive bins data size (4, @40),
            clustering factor 1, file name (UTF-16LE, @48, 64 bytes),
            checksum (@508) = XOR of the 127 dwords before it (0 -> 1,
            0xFFFFFFFF -> 0xFFFFFFFE)
    0x1000  hive bins data: one "hbin" whose size is a multiple of 4096.
            32-byte header ("hbin", offset, size, reserved, timestamp, spare),
            then cells: int32 size (negative = allocated, positive = free),
            aligned to 8 bytes.  Cell offsets are relative to 0x1000.

build_hive() produces this key tree (root name "ROOT"):

    ROOT                       subkeys via an lh list
      Software                 subkeys via an lf list
        Strata                 values: see VALUES
      System                   subkeys via an ri list -> [li, lf]
        Alpha
        Beta
      Ünïcode                  name stored as UTF-16LE (no COMP_NAME flag)

plus a free (positive-size) nk cell "Removed" and a free vk cell
"OldValue" = REG_SZ "gone", as left behind by a deletion.

Transaction log (new format, .LOG1/.LOG2):

    0x000   512-byte log base block ("regf" + sequence numbers)
    0x200   log entries: "HvLE", size (multiple of 512), flags, sequence,
            hive bins data size, dirty page count, hash-1 (Marvin32 of the
            entry bytes from 40 to size), hash-2 (Marvin32 of the first 32
            entry bytes, hash-1 included); then (offset, size) page
            references and the page bytes.
"""

import struct

BASE_BLOCK = 4096
MARVIN_SEED = 0x82EF4D887A4E55C5
MASK = 0xFFFFFFFF
FILETIME = 133000000000000000          # 2022-06-18T04:26:40Z
BIG_DATA_SEGMENT = 16344

KEY_HIVE_ENTRY = 0x0004
KEY_NO_DELETE = 0x0008
KEY_COMP_NAME = 0x0020
VALUE_COMP_NAME = 0x0001

REG_SZ, REG_BINARY, REG_DWORD, REG_MULTI_SZ = 1, 3, 4, 7

BIG_BLOB = bytes((i * 7 + 3) & 0xFF for i in range(20000))

# name -> (type, raw data)
VALUES = [
    ("", REG_SZ, "default value\x00".encode("utf-16-le")),
    ("Name", REG_SZ, "Strata\x00".encode("utf-16-le")),
    ("Count", REG_DWORD, struct.pack("<I", 42)),
    ("Blob", REG_BINARY, bytes(range(16))),
    ("Tiny", REG_BINARY, b"\x01\x02\x03"),
    ("Paths", REG_MULTI_SZ, "C:\\a\x00D:\\b\x00\x00".encode("utf-16-le")),
    ("Big", REG_BINARY, BIG_BLOB),
]


def base_checksum(block):
    acc = 0
    for i in range(0, 508, 4):
        acc ^= struct.unpack_from("<I", block, i)[0]
    if acc == 0:
        return 1
    if acc == MASK:
        return MASK - 1
    return acc


def _rotl(v, n):
    return ((v << n) | (v >> (32 - n))) & MASK


def marvin32(data, seed=MARVIN_SEED):
    """Marvin32 (as used by Windows for registry log entry hashes)."""
    lo, hi = seed & MASK, (seed >> 32) & MASK

    def mix(lo, hi, v):
        lo = (lo + v) & MASK
        hi ^= lo
        lo = (_rotl(lo, 20) + hi) & MASK
        hi = _rotl(hi, 9) ^ lo
        lo = (_rotl(lo, 27) + hi) & MASK
        hi = _rotl(hi, 19)
        return lo, hi

    n = len(data) // 4 * 4
    for i in range(0, n, 4):
        lo, hi = mix(lo, hi, struct.unpack_from("<I", data, i)[0])
    tail = data[n:] + b"\x80"
    lo, hi = mix(lo, hi, struct.unpack("<I", tail.ljust(4, b"\x00"))[0])
    lo, hi = mix(lo, hi, 0)
    return (hi << 32) | lo


class HiveBuilder(object):
    """Appends cells into a single hbin; offsets returned are cell offsets."""

    def __init__(self):
        self.cells = bytearray(32)          # hbin header filled in at the end

    def cell(self, body, free=False):
        off = len(self.cells)
        size = (4 + len(body) + 7) // 8 * 8
        self.cells += struct.pack("<i", size if free else -size)
        self.cells += body + bytes(size - 4 - len(body))
        return off

    def nk(self, name, parent, subkeys=0, subkey_list=0xFFFFFFFF, values=0,
           value_list=0xFFFFFFFF, flags=0, free=False):
        try:
            raw = name.encode("ascii")
            flags |= KEY_COMP_NAME
        except UnicodeEncodeError:
            raw = name.encode("utf-16-le")
        body = struct.pack("<2sHQIIIIIIIIIIIIIIIHH", b"nk", flags, FILETIME,
                           0, parent, subkeys, 0, subkey_list, 0xFFFFFFFF,
                           values, value_list, 0xFFFFFFFF, 0xFFFFFFFF,
                           0, 0, 0, 0, 0, len(raw), 0)
        return self.cell(body + raw, free=free)

    def vk(self, name, vtype, data, free=False):
        raw = name.encode("ascii")
        if len(data) <= 4:
            size = len(data) | 0x80000000
            off = struct.unpack("<I", data.ljust(4, b"\x00"))[0]
        elif len(data) > BIG_DATA_SEGMENT:
            size, off = len(data), self.big_data(data)
        else:
            size, off = len(data), self.cell(data)
        body = struct.pack("<2sHIIIHH", b"vk", len(raw), size, off, vtype,
                           VALUE_COMP_NAME if raw else 0, 0)
        return self.cell(body + raw, free=free)

    def big_data(self, data):
        segs = [self.cell(data[i:i + BIG_DATA_SEGMENT])
                for i in range(0, len(data), BIG_DATA_SEGMENT)]
        seglist = self.cell(struct.pack("<%dI" % len(segs), *segs))
        return self.cell(struct.pack("<2sHI", b"db", len(segs), seglist))

    def hashed_list(self, sig, offsets):
        body = struct.pack("<2sH", sig, len(offsets))
        for o in offsets:
            body += struct.pack("<I4s", o, b"\x00\x00\x00\x00")
        return self.cell(body)

    def index_list(self, sig, offsets):
        return self.cell(struct.pack("<2sH%dI" % len(offsets), sig,
                                     len(offsets), *offsets))

    def hbins(self):
        size = (len(self.cells) + 16 + BASE_BLOCK - 1) // BASE_BLOCK * BASE_BLOCK
        out = bytearray(self.cells)
        remaining = size - len(out)
        out += struct.pack("<i", remaining) + bytes(remaining - 4)
        struct.pack_into("<4sIIIQI", out, 0, b"hbin", 0, size, 0, FILETIME, 0)
        return bytes(out)


def base_block(root_offset, hbins_size, seq1=1, seq2=1, name="ROOT"):
    blk = bytearray(BASE_BLOCK)
    struct.pack_into("<4sIIQIIIIIII", blk, 0, b"regf", seq1, seq2, FILETIME,
                     1, 5, 0, 1, root_offset, hbins_size, 1)
    fname = ("\\??\\C:\\" + name).encode("utf-16-le")[:64]
    blk[48:48 + len(fname)] = fname
    struct.pack_into("<I", blk, 508, base_checksum(blk))
    return blk


def build_hive(name_value="Strata", seq1=1, seq2=1):
    """The hive described in the module docstring.  `name_value` replaces
    the Software\\Strata "Name" string (keep its length to keep offsets)."""
    b = HiveBuilder()
    # Children are written before their parents, so parent offsets (and the
    # root's subkey list) are patched in once every offset is known.
    root = b.nk("ROOT", 0, flags=KEY_HIVE_ENTRY | KEY_NO_DELETE)

    vals = []
    for vname, vtype, data in VALUES:
        if vname == "Name":
            data = (name_value + "\x00").encode("utf-16-le")
        vals.append(b.vk(vname, vtype, data))
    vlist = b.cell(struct.pack("<%dI" % len(vals), *vals))

    strata = b.nk("Strata", 0, values=len(vals), value_list=vlist)
    software = b.nk("Software", root, subkeys=1,
                    subkey_list=b.hashed_list(b"lf", [strata]))
    alpha = b.nk("Alpha", 0)
    beta = b.nk("Beta", 0)
    ri = b.index_list(b"ri", [b.index_list(b"li", [alpha]),
                              b.hashed_list(b"lf", [beta])])
    system = b.nk("System", root, subkeys=2, subkey_list=ri)
    uni = b.nk(u"\u00dcn\u00efcode", root)
    root_list = b.hashed_list(b"lh", [software, system, uni])

    # Deleted leftovers: free cells that still hold records.
    b.nk("Removed", software, free=True)
    b.vk("OldValue", REG_SZ, "gone\x00".encode("utf-16-le"), free=True)

    # Patch parents and the root's subkey list now offsets are known.
    def patch_u32(cell_off, field_off, value):
        struct.pack_into("<I", b.cells, cell_off + 4 + field_off, value)

    for child, parent in ((strata, software), (alpha, system),
                          (beta, system)):
        patch_u32(child, 16, parent)
    patch_u32(root, 20, 3)
    patch_u32(root, 28, root_list)

    hbins = b.hbins()
    return bytes(base_block(root, len(hbins), seq1, seq2)) + hbins


def log_entry(sequence, hbins_size, pages):
    """One HvLE entry. `pages` is a list of (offset, bytes)."""
    refs = b"".join(struct.pack("<II", off, len(data)) for off, data in pages)
    body = refs + b"".join(data for _off, data in pages)
    size = (40 + len(body) + 511) // 512 * 512
    body = body + bytes(size - 40 - len(body))
    head = struct.pack("<4sIIIII", b"HvLE", size, 0, sequence, hbins_size,
                       len(pages))
    head += struct.pack("<Q", marvin32(body))
    return head + struct.pack("<Q", marvin32(head)) + body


def build_log(entries, sequence=1):
    """A transaction log: 512-byte base block then the given entries."""
    blk = bytearray(512)
    struct.pack_into("<4sII", blk, 0, b"regf", sequence, sequence)
    return bytes(blk) + b"".join(entries)


def build_dirty_pair():
    """(dirty hive, log, expected replayed hive bins).

    The on-disk hive is at primary 11 / secondary 10 and still says
    Name = "Strata"; the log holds entry 10 rewriting the whole hive bins
    area so that Name = "Replay".
    """
    stale = build_hive("Strata", seq1=11, seq2=10)
    fresh = build_hive("Replay")
    fresh_bins = fresh[BASE_BLOCK:]
    log = build_log([log_entry(10, len(fresh_bins), [(0, fresh_bins)])], 10)
    return stale, log, fresh_bins
