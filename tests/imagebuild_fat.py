"""Synthetic FAT12/16/32 and exFAT volume builders for the parser tests.

Everything here returns ``bytes``: a complete, minimal but valid volume (or a
disk wrapping one) built in code, because the repository carries no binary
fixtures. The layouts are fixed and described below so a test can assert
exact offsets, and so the same images can later seed a fuzzer.

Nothing in this module imports the engine; it only encodes the on-disk
formats (Microsoft FAT specification 1.03 and the exFAT file system
specification) so a builder mistake cannot be masked by an engine mistake.
"""

import datetime
import struct

SECTOR = 512

# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------


def pattern(length, seed):
    """Deterministic, non-repeating-looking filler so misplaced reads show."""
    return bytes(((i * 31 + seed * 7 + (i >> 8)) & 0xFF) for i in range(length))


def fill(length, text):
    """Repeat ``text`` to exactly ``length`` bytes (used to paint slack)."""
    reps = length // len(text) + 1
    return (text * reps)[:length]


def wrap_mbr(volume, start_sector=63, ptype=0x06, bootable=False):
    """A disk: classic MBR at sector 0, one primary partition holding ``volume``.

    Layout: sector 0 = MBR (partition entry 1 at 0x1BE, signature 55AA);
    sectors 1..start_sector-1 zero; ``volume`` from ``start_sector``; the
    disk is padded to a whole number of sectors.
    """
    count = (len(volume) + SECTOR - 1) // SECTOR
    mbr = bytearray(SECTOR)
    entry = struct.pack("<B3sB3sII", 0x80 if bootable else 0x00,
                        b"\xFE\xFF\xFF", ptype, b"\xFE\xFF\xFF",
                        start_sector, count)
    mbr[446:462] = entry
    mbr[510:512] = b"\x55\xAA"
    disk = bytearray(start_sector * SECTOR + count * SECTOR)
    disk[0:SECTOR] = mbr
    disk[start_sector * SECTOR:start_sector * SECTOR + len(volume)] = volume
    return bytes(disk)


# --------------------------------------------------------------------------
# FAT12 / FAT16 / FAT32
# --------------------------------------------------------------------------

FAT_CLUSTER = 512            # every FAT geometry below uses 1 sector/cluster

# bits -> (total_sectors, reserved, num_fats, fat_size_sectors, root_entries)
# Cluster counts land squarely inside each width's range (spec section 3.5):
#   FAT12: 2847 (< 4085)   FAT16: 8095 (< 65525)   FAT32: 66000 (>= 65525)
FAT_GEOMETRY = {
    12: (2880, 1, 2, 9, 224),
    16: (8192, 1, 2, 32, 512),
    32: (67064, 32, 2, 516, 0),
}

HELLO_TEXT = b"Hello, FAT!\n"
LONG_NAME = "Long file name.txt"
LONG_SHORT = b"LONGFI~1TXT"
LONG_SIZE = 2 * FAT_CLUSTER + 100
LONG_CLUSTERS = (4, 5, 9)                        # fragmented chain
NESTED_SIZE = 1000
DELETED_SIZE = FAT_CLUSTER + 188
DELETED_LFN_NAME = "Removed document.txt"
GONE_NAME = "Gone file.txt"                     # exactly 13 chars: one LFN part
GONE_TEXT = b"deleted, single-part LFN\n\x00\x00\x00\x00\x00"
SLACK_MARK = b"SLACK!"

# Where each item lives. Cluster numbers are identical across the three
# widths so the tests can share expectations.
FAT_LAYOUT = {
    "root_cluster_fat32": 2,
    "hello": {"cluster": 3, "size": len(HELLO_TEXT)},
    "long": {"clusters": LONG_CLUSTERS, "size": LONG_SIZE},
    "subdir": {"clusters": (6, 25)},             # two-cluster directory chain
    "nested": {"clusters": (26, 27), "size": NESTED_SIZE},
    "deleted": {"cluster": 12, "size": DELETED_SIZE},   # FAT entries freed
    "deleted_lfn": {"cluster": 15, "size": 50},
    "cycle": {"clusters": (17, 18), "size": 5000},      # 17 -> 18 -> 17
    "gone": {"cluster": 20, "size": 30},
    "subdir_fillers": 14,
}


def long_content():
    return pattern(LONG_SIZE, 1)


def nested_content():
    return pattern(NESTED_SIZE, 2)


def deleted_content():
    return pattern(DELETED_SIZE, 3)


def deleted_lfn_content():
    return pattern(50, 4)


def dos_datetime(dt):
    """(date, time) as packed by FAT: 7-bit year-1980, 4 month, 5 day /
    5 hour, 6 minute, 5 two-second."""
    date = ((dt.year - 1980) << 9) | (dt.month << 5) | dt.day
    time_ = (dt.hour << 11) | (dt.minute << 5) | (dt.second // 2)
    return date, time_


HELLO_CREATED = datetime.datetime(2024, 3, 15, 10, 20, 30)    # + 1.50 s
HELLO_MODIFIED = datetime.datetime(2024, 3, 15, 13, 45, 30)
HELLO_ACCESSED = datetime.date(2024, 3, 16)


def lfn_checksum(short11):
    s = 0
    for c in short11:
        s = (((s & 1) << 7) + (s >> 1) + c) & 0xFF
    return s


def lfn_entries(name, short11, deleted=False):
    """VFAT long-name entries in on-disk order (highest sequence first)."""
    units = name.encode("utf-16-le")
    chars = [units[i:i + 2] for i in range(0, len(units), 2)]
    parts = [chars[i:i + 13] for i in range(0, len(chars), 13)]
    last = parts[-1]
    if len(last) < 13:
        last.append(b"\x00\x00")
        while len(last) < 13:
            last.append(b"\xFF\xFF")
    csum = lfn_checksum(short11)
    out = []
    for seq, part in enumerate(parts, 1):
        raw = b"".join(part)
        e = bytearray(32)
        e[0] = seq | (0x40 if seq == len(parts) else 0)
        e[1:11] = raw[0:10]
        e[11] = 0x0F
        e[13] = csum
        e[14:26] = raw[10:22]
        e[28:32] = raw[22:26]
        if deleted:
            e[0] = 0xE5
        out.append(bytes(e))
    return list(reversed(out))


def short_entry(name11, attr, cluster, size, created=None, modified=None,
                accessed=None, tenths=0):
    e = bytearray(32)
    e[0:11] = name11
    e[11] = attr
    if created is not None:
        d, t = dos_datetime(created)
        e[13] = tenths
        struct.pack_into("<HH", e, 14, t, d)
    if accessed is not None:
        struct.pack_into("<H", e, 18, ((accessed.year - 1980) << 9)
                         | (accessed.month << 5) | accessed.day)
    struct.pack_into("<H", e, 20, (cluster >> 16) & 0xFFFF)
    if modified is not None:
        d, t = dos_datetime(modified)
        struct.pack_into("<HH", e, 22, t, d)
    struct.pack_into("<H", e, 26, cluster & 0xFFFF)
    struct.pack_into("<I", e, 28, size)
    return bytes(e)


def _fat_set(fat, bits, n, value):
    if bits == 12:
        i = n + n // 2
        value &= 0x0FFF
        if n & 1:
            fat[i] = (fat[i] & 0x0F) | ((value << 4) & 0xF0)
            fat[i + 1] = (value >> 4) & 0xFF
        else:
            fat[i] = value & 0xFF
            fat[i + 1] = (fat[i + 1] & 0xF0) | (value >> 8)
    elif bits == 16:
        struct.pack_into("<H", fat, n * 2, value & 0xFFFF)
    else:
        struct.pack_into("<I", fat, n * 4, value & 0x0FFFFFFF)


class SparseImage:
    """Write-only image of a fixed size that records only what is written,
    so a FAT32 volume (which needs >= 65525 clusters, ~34 MB) costs about
    the size of its FATs in memory. ``extents()`` lists (offset, bytes);
    ``tobytes()`` materialises the whole image."""

    def __init__(self, size):
        self.size = size
        self.chunks = []

    def __setitem__(self, key, data):
        start = key.start or 0
        assert 0 <= start and start + len(data) <= self.size
        self.chunks.append((start, bytes(data)))

    def extents(self):
        return list(self.chunks)

    def tobytes(self):
        out = bytearray(self.size)
        for off, data in self.chunks:
            out[off:off + len(data)] = data
        return bytes(out)


def write_sparse(path, size, extents):
    """Write ``extents`` to ``path`` as a (filesystem-sparse where supported)
    file of exactly ``size`` bytes."""
    with open(path, "wb") as fh:
        for off, data in extents:
            fh.seek(off)
            fh.write(data)
        fh.truncate(size)


def build_fat_extents(bits=16, label=b"STRATATEST "):
    """``build_fat`` as (size, [(offset, bytes), ...]) without allocating
    the whole volume. Later extents overwrite earlier ones."""
    img = _build_fat(bits, label)
    return img.size, img.extents()


def build_fat(bits=16, label=b"STRATATEST "):
    """The volume from ``_build_fat`` as bytes (FAT32 is ~34 MB; prefer
    ``build_fat_extents`` for it)."""
    return _build_fat(bits, label).tobytes()


def _build_fat(bits=16, label=b"STRATATEST "):
    """A FAT12, FAT16 or FAT32 volume (512-byte sectors, 1 sector/cluster).

    Geometry per width is in ``FAT_GEOMETRY``; both FAT copies are written
    identically. The first data sector holds cluster 2.

    Root directory (fixed region on FAT12/16, cluster 2 on FAT32):
      * volume label entry ``label`` (attr 0x08)
      * ``HELLO.TXT``   12 bytes in cluster 3; its slack is painted SLACK!;
        created 2024-03-15 10:20:31.50 (tenths byte 150), modified
        2024-03-15 13:45:30, accessed 2024-03-16
      * ``Long file name.txt`` (2 LFN entries + ``LONGFI~1.TXT``),
        1124 bytes over the fragmented chain 4 -> 5 -> 9
      * ``SUBDIR``       directory, chain 6 -> 25. Cluster 6 holds ``.``,
        ``..`` and 14 empty files ``FILE00.DAT``..``FILE13.DAT``; cluster 25
        holds ``NESTED.BIN`` (1000 bytes, clusters 26 -> 27)
      * deleted ``DELETED.TXT`` (0xE5, no LFN), 700 bytes written
        contiguously to clusters 12-13, FAT entries freed; the 324 bytes
        after it in cluster 13 are painted SLACK!
      * deleted ``Removed document.txt`` (2 deleted LFN entries + short
        entry), 50 bytes in cluster 15, FAT entry freed
      * ``CYCLE.BIN``   declares 5000 bytes on a corrupt chain 17 -> 18 -> 17
      * deleted ``Gone file.txt`` (one deleted LFN entry, 13 characters so
        no terminator) + short ``GONEFI~1.TXT``, 30 bytes in cluster 20
    """
    total, reserved, nfats, fat_size, root_entries = FAT_GEOMETRY[bits]
    img = SparseImage(total * SECTOR)

    # Boot sector / BPB.
    b = bytearray(SECTOR)
    b[0:3] = b"\xEB\x3C\x90"
    b[3:11] = b"MSWIN4.1"
    struct.pack_into("<HBHBHHBH", b, 11, SECTOR, 1, reserved, nfats,
                     root_entries, total if (total < 0x10000 and bits != 32)
                     else 0, 0xF8, fat_size if bits != 32 else 0)
    struct.pack_into("<HHI", b, 24, 63, 255, 0)
    struct.pack_into("<I", b, 32, 0 if (total < 0x10000 and bits != 32)
                     else total)
    if bits == 32:
        struct.pack_into("<IHHIHH", b, 36, fat_size, 0, 0,
                         FAT_LAYOUT["root_cluster_fat32"], 1, 6)
        b[64] = 0x80
        b[66] = 0x29
        struct.pack_into("<I", b, 67, 0x32323232)
        b[71:82] = label
        b[82:90] = b"FAT32   "
    else:
        b[36] = 0x80
        b[38] = 0x29
        struct.pack_into("<I", b, 39, 0x16161616)
        b[43:54] = label
        b[54:62] = b"FAT12   " if bits == 12 else b"FAT16   "
    b[510:512] = b"\x55\xAA"
    img[0:SECTOR] = b
    if bits == 32:
        fsinfo = bytearray(SECTOR)
        struct.pack_into("<I", fsinfo, 0, 0x41615252)
        struct.pack_into("<I", fsinfo, 484, 0x61417272)
        struct.pack_into("<II", fsinfo, 488, 0xFFFFFFFF, 0xFFFFFFFF)
        fsinfo[510:512] = b"\x55\xAA"
        img[SECTOR:2 * SECTOR] = fsinfo
        img[6 * SECTOR:7 * SECTOR] = b

    root_dir_sectors = (root_entries * 32 + SECTOR - 1) // SECTOR
    root_region = (reserved + nfats * fat_size) * SECTOR
    first_data = reserved + nfats * fat_size + root_dir_sectors

    def coff(n):
        return (first_data + (n - 2)) * SECTOR

    def put(n, data):
        img[coff(n):coff(n) + len(data)] = data

    fat = bytearray(fat_size * SECTOR)
    eoc = {12: 0xFFF, 16: 0xFFFF, 32: 0x0FFFFFFF}[bits]
    _fat_set(fat, bits, 0, (eoc & ~0xFF) | 0xF8)
    _fat_set(fat, bits, 1, eoc)

    def link(chain):
        for a, nxt in zip(chain, chain[1:]):
            _fat_set(fat, bits, a, nxt)
        _fat_set(fat, bits, chain[-1], eoc)

    # HELLO.TXT
    hello = FAT_LAYOUT["hello"]["cluster"]
    link([hello])
    put(hello, HELLO_TEXT + fill(FAT_CLUSTER - len(HELLO_TEXT), SLACK_MARK))

    # Long file name.txt, fragmented
    link(list(LONG_CLUSTERS))
    data = long_content()
    for k, c in enumerate(LONG_CLUSTERS):
        put(c, data[k * FAT_CLUSTER:(k + 1) * FAT_CLUSTER])

    # SUBDIR and its contents
    sub1, sub2 = FAT_LAYOUT["subdir"]["clusters"]
    link([sub1, sub2])
    dot = short_entry(b".          ", 0x10, sub1, 0)
    dotdot = short_entry(b"..         ", 0x10, 0, 0)
    fillers = [short_entry(("FILE%02d  DAT" % k).encode(), 0x20, 0, 0)
               for k in range(FAT_LAYOUT["subdir_fillers"])]
    put(sub1, dot + dotdot + b"".join(fillers))
    n1, n2 = FAT_LAYOUT["nested"]["clusters"]
    link([n1, n2])
    put(sub2, short_entry(b"NESTED  BIN", 0x20, n1, NESTED_SIZE))
    ndata = nested_content()
    put(n1, ndata[:FAT_CLUSTER])
    put(n2, ndata[FAT_CLUSTER:])

    # Deleted, no LFN, contiguous 12-13, FAT freed (left zero)
    dc = FAT_LAYOUT["deleted"]["cluster"]
    ddata = deleted_content()
    put(dc, ddata[:FAT_CLUSTER])
    put(dc + 1, ddata[FAT_CLUSTER:]
        + fill(2 * FAT_CLUSTER - DELETED_SIZE, SLACK_MARK))

    # Deleted with a two-part LFN
    lc = FAT_LAYOUT["deleted_lfn"]["cluster"]
    put(lc, deleted_lfn_content())

    # Corrupt cyclic chain
    c1, c2 = FAT_LAYOUT["cycle"]["clusters"]
    _fat_set(fat, bits, c1, c2)
    _fat_set(fat, bits, c2, c1)
    put(c1, b"A" * FAT_CLUSTER)
    put(c2, b"B" * FAT_CLUSTER)

    root = bytearray()
    root += short_entry(label, 0x08, 0, 0)
    root += short_entry(b"HELLO   TXT", 0x20, hello, len(HELLO_TEXT),
                        created=HELLO_CREATED, modified=HELLO_MODIFIED,
                        accessed=HELLO_ACCESSED, tenths=150)
    for e in lfn_entries(LONG_NAME, LONG_SHORT):
        root += e
    root += short_entry(LONG_SHORT, 0x20, LONG_CLUSTERS[0], LONG_SIZE)
    root += short_entry(b"SUBDIR     ", 0x10, sub1, 0)
    root += short_entry(b"\xE5ELETED TXT", 0x20, dc, DELETED_SIZE)
    removed_short = b"REMOVE~1TXT"
    for e in lfn_entries(DELETED_LFN_NAME, removed_short, deleted=True):
        root += e
    root += short_entry(b"\xE5" + removed_short[1:], 0x20, lc, 50)
    root += short_entry(b"CYCLE   BIN", 0x20, c1, 5000)
    gc = FAT_LAYOUT["gone"]["cluster"]
    put(gc, GONE_TEXT)
    for e in lfn_entries(GONE_NAME, b"GONEFI~1TXT", deleted=True):
        root += e
    root += short_entry(b"\xE5ONEFI~1TXT", 0x20, gc, len(GONE_TEXT))

    if bits == 32:
        rc = FAT_LAYOUT["root_cluster_fat32"]
        link([rc])
        assert len(root) <= FAT_CLUSTER
        put(rc, bytes(root))
    else:
        assert len(root) <= root_entries * 32
        img[root_region:root_region + len(root)] = root

    for k in range(nfats):
        at = (reserved + k * fat_size) * SECTOR
        img[at:at + len(fat)] = fat
    return img


# --------------------------------------------------------------------------
# exFAT
# --------------------------------------------------------------------------

EXFAT_SECTOR_SHIFT = 9       # 512-byte sectors
EXFAT_CLUSTER_SHIFT = 1      # 2 sectors per cluster
EXFAT_CLUSTER = 1 << (EXFAT_SECTOR_SHIFT + EXFAT_CLUSTER_SHIFT)   # 1024
EXFAT_FAT_OFFSET = 24        # sectors (after main + backup boot regions)
EXFAT_FAT_LENGTH = 1
EXFAT_HEAP_OFFSET = 32
EXFAT_CLUSTERS = 64
EXFAT_SERIAL = 0x1234ABCD
EXFAT_LABEL = "Strata"

EXFAT_LAYOUT = {
    "bitmap": 2, "upcase": 3, "root": (4, 15),
    "hello": {"cluster": 6, "size": 13},                 # NoFatChain
    "fragmented": {"clusters": (7, 9, 8), "size": 2500},  # FAT chain
    "contiguous": {"cluster": 10, "count": 3, "size": 3000},  # NoFatChain
    "deleted": {"cluster": 13, "size": 100},
    "timezone": {"cluster": 14, "size": 5},
    "longname": {"cluster": 16, "size": 10},
    "subdir": {"cluster": 17, "count": 2},               # NoFatChain dir
    "inner": {"cluster": 19, "size": 6},
    "second": {"cluster": 20, "size": 7},
    "tail": {"cluster": 21, "size": 4},
}

EXFAT_HELLO = b"Hello, exFAT\n"
EXFAT_LONG_NAME = "Named with a rather long filename.txt"
EXFAT_MODIFIED = datetime.datetime(2023, 11, 5, 8, 30, 44)
EXFAT_TZ_LOCAL = datetime.datetime(2024, 6, 1, 10, 0, 0)
EXFAT_TZ_OFFSET = 0x80 | 48          # valid, +12:00 (48 quarter hours)


def exfat_fragmented_content():
    return pattern(2500, 11)


def exfat_contiguous_content():
    return pattern(3000, 12)


def exfat_timestamp(dt):
    return (((dt.year - 1980) << 25) | (dt.month << 21) | (dt.day << 16)
            | (dt.hour << 11) | (dt.minute << 5) | (dt.second // 2))


def upcase_table():
    """A short up-case table: 128 UTF-16 code points, a-z mapped to A-Z.
    Code points past the end of a table map to themselves (spec 7.2)."""
    return b"".join(struct.pack("<H", (c - 32) if 0x61 <= c <= 0x7A else c)
                    for c in range(128))


def _upcase_checksum(data):
    c = 0
    for byte in data:
        c = (((c << 31) | (c >> 1)) + byte) & 0xFFFFFFFF
    return c


def _name_hash(name):
    h = 0
    for byte in name.upper().encode("utf-16-le"):
        h = (((h << 15) | (h >> 1)) + byte) & 0xFFFF
    return h


def _set_checksum(entries):
    blob = b"".join(entries)
    c = 0
    for i, byte in enumerate(blob):
        if i in (2, 3):
            continue
        c = (((c << 15) | (c >> 1)) + byte) & 0xFFFF
    first = bytearray(entries[0])
    struct.pack_into("<H", first, 2, c)
    return [bytes(first)] + list(entries[1:])


def exfat_file_set(name, first_cluster, size, attrs=0x20, contiguous=False,
                   deleted=False, modified=EXFAT_MODIFIED, created=None,
                   created_tz=0, valid=None):
    """File + Stream Extension + File Name entries for one file (32 bytes
    each). ``deleted`` clears the InUse bit of every entry in the set."""
    units = name.encode("utf-16-le")
    names = [units[i:i + 30] for i in range(0, len(units), 30)]
    f = bytearray(32)
    f[0] = 0x85
    f[1] = 1 + len(names)
    struct.pack_into("<H", f, 4, attrs)
    struct.pack_into("<III", f, 8,
                     exfat_timestamp(created or modified),
                     exfat_timestamp(modified), exfat_timestamp(modified))
    f[22] = created_tz
    s = bytearray(32)
    s[0] = 0xC0
    s[1] = 0x01 | (0x02 if contiguous else 0)
    s[3] = len(name)
    struct.pack_into("<H", s, 4, _name_hash(name))
    struct.pack_into("<Q", s, 8, size if valid is None else valid)
    struct.pack_into("<IQ", s, 20, first_cluster, size)
    entries = [bytes(f), bytes(s)]
    for part in names:
        n = bytearray(32)
        n[0] = 0xC1
        n[2:2 + len(part)] = part
        entries.append(bytes(n))
    entries = _set_checksum(entries)
    if deleted:
        entries = [bytes([e[0] & 0x7F]) + e[1:] for e in entries]
    return entries


def _boot_checksum(sectors):
    c = 0
    for i, byte in enumerate(sectors):
        if i in (106, 107, 112):
            continue
        c = (((c << 31) | (c >> 1)) + byte) & 0xFFFFFFFF
    return c


def build_exfat():
    """An exFAT volume: 512-byte sectors, 1024-byte clusters, 64 clusters.

    Sectors 0-11 main boot region (boot sector, 8 extended boot sectors with
    AA550000 signatures, OEM, reserved, boot checksum sector); 12-23 backup
    boot region (a copy); 24 the single FAT; 32 onwards the cluster heap
    (cluster 2 at sector 32). Cluster placement is in ``EXFAT_LAYOUT``.

    Clusters: 2 allocation bitmap (8 bytes); 3 up-case table (256 bytes,
    checksummed); 4 -> 15 root directory (a FAT chain). Root entries: volume
    label "Strata", bitmap, up-case, then
      * ``Hello.txt``            13 bytes, cluster 6, NoFatChain; slack
        painted SLACK!
      * ``Fragmented file.bin``  2500 bytes on the FAT chain 7 -> 9 -> 8
      * ``Contiguous.dat``       3000 bytes, clusters 10-12, NoFatChain,
        FAT entries left zero (as a real driver does)
      * ``Deleted file.txt``     InUse cleared on all entries, 100 bytes in
        cluster 13 (bitmap bit clear)
      * ``Timezone.txt``         created 2024-06-01 10:00:00 local with a
        valid UTC offset of +12:00
      * ``Empty.txt``            size 0, no cluster
      * ``Named with a rather long filename.txt``  3 name entries, cluster 16
      * ``Subdir``               directory, NoFatChain over clusters 17-18
        (FAT zero). Cluster 17 holds ``Inner.txt`` then unused entries
        (type 0x40); cluster 18 holds ``Second.txt``.
      * ``Tail.txt``             its entry set straddles clusters 4 and 15
    Every entry set carries a correct SetChecksum and NameHash.
    """
    L = EXFAT_LAYOUT
    cs = EXFAT_CLUSTER
    total_sectors = EXFAT_HEAP_OFFSET + EXFAT_CLUSTERS * (cs // SECTOR)
    img = bytearray(total_sectors * SECTOR)

    def coff(n):
        return EXFAT_HEAP_OFFSET * SECTOR + (n - 2) * cs

    def put(n, data):
        img[coff(n):coff(n) + len(data)] = data

    boot = bytearray(12 * SECTOR)
    boot[0:3] = b"\xEB\x76\x90"
    boot[3:11] = b"EXFAT   "
    struct.pack_into("<QQIIIIIIHH", boot, 64, 0, total_sectors,
                     EXFAT_FAT_OFFSET, EXFAT_FAT_LENGTH, EXFAT_HEAP_OFFSET,
                     EXFAT_CLUSTERS, L["root"][0], EXFAT_SERIAL, 0x0100, 0)
    boot[108] = EXFAT_SECTOR_SHIFT
    boot[109] = EXFAT_CLUSTER_SHIFT
    boot[110] = 1
    boot[111] = 0x80
    boot[112] = 30
    boot[510:512] = b"\x55\xAA"
    for k in range(1, 9):
        boot[k * SECTOR + 508:k * SECTOR + 512] = b"\x00\x00\x55\xAA"
    csum = struct.pack("<I", _boot_checksum(bytes(boot[:11 * SECTOR])))
    boot[11 * SECTOR:12 * SECTOR] = csum * (SECTOR // 4)
    img[0:12 * SECTOR] = boot
    img[12 * SECTOR:24 * SECTOR] = boot

    fat = bytearray(EXFAT_FAT_LENGTH * SECTOR)
    used = set()

    def link(chain):
        for a, nxt in zip(chain, chain[1:]):
            struct.pack_into("<I", fat, a * 4, nxt)
        struct.pack_into("<I", fat, chain[-1] * 4, 0xFFFFFFFF)

    struct.pack_into("<II", fat, 0, 0xFFFFFFF8, 0xFFFFFFFF)

    # Allocation bitmap, up-case table, root chain.
    link([L["bitmap"]])
    link([L["upcase"]])
    link(list(L["root"]))
    upcase = upcase_table()
    put(L["upcase"], upcase)
    used.update([L["bitmap"], L["upcase"]] + list(L["root"]))

    # File data.
    put(L["hello"]["cluster"], EXFAT_HELLO
        + fill(cs - len(EXFAT_HELLO), SLACK_MARK))
    used.add(L["hello"]["cluster"])

    frag = exfat_fragmented_content()
    link(list(L["fragmented"]["clusters"]))
    for k, c in enumerate(L["fragmented"]["clusters"]):
        put(c, frag[k * cs:(k + 1) * cs])
        used.add(c)

    cont = exfat_contiguous_content()
    c0 = L["contiguous"]["cluster"]
    put(c0, cont)
    used.update(range(c0, c0 + L["contiguous"]["count"]))

    put(L["deleted"]["cluster"], pattern(100, 13))            # not in bitmap
    put(L["timezone"]["cluster"], b"tz!!\n")
    put(L["longname"]["cluster"], b"long name\n")
    put(L["inner"]["cluster"], b"inner\n")
    put(L["second"]["cluster"], b"second\n")
    put(L["tail"]["cluster"], b"tail")
    used.update([L["timezone"]["cluster"], L["longname"]["cluster"],
                 L["inner"]["cluster"], L["second"]["cluster"],
                 L["tail"]["cluster"]])
    for n in (L["timezone"], L["longname"], L["inner"], L["second"],
              L["tail"]):
        link([n["cluster"]])

    sub = L["subdir"]["cluster"]
    used.update(range(sub, sub + L["subdir"]["count"]))
    sub1 = b"".join(exfat_file_set("Inner.txt", L["inner"]["cluster"], 6))
    unused = bytes([0x40]) + bytes(31)
    sub1 += unused * ((cs - len(sub1)) // 32)
    put(sub, sub1)
    put(sub + 1, b"".join(exfat_file_set("Second.txt",
                                         L["second"]["cluster"], 7)))

    # Root directory entries.
    label = bytearray(32)
    label[0] = 0x83
    label[1] = len(EXFAT_LABEL)
    label[2:2 + 2 * len(EXFAT_LABEL)] = EXFAT_LABEL.encode("utf-16-le")
    bitmap_e = bytearray(32)
    bitmap_e[0] = 0x81
    struct.pack_into("<IQ", bitmap_e, 20, L["bitmap"],
                     (EXFAT_CLUSTERS + 7) // 8)
    upcase_e = bytearray(32)
    upcase_e[0] = 0x82
    struct.pack_into("<I", upcase_e, 4, _upcase_checksum(upcase))
    struct.pack_into("<IQ", upcase_e, 20, L["upcase"], len(upcase))

    root = [bytes(label), bytes(bitmap_e), bytes(upcase_e)]
    root += exfat_file_set("Hello.txt", L["hello"]["cluster"], 13,
                           contiguous=True)
    root += exfat_file_set("Fragmented file.bin",
                           L["fragmented"]["clusters"][0], 2500)
    root += exfat_file_set("Contiguous.dat", c0, 3000, contiguous=True)
    root += exfat_file_set("Deleted file.txt", L["deleted"]["cluster"], 100,
                           contiguous=True, deleted=True)
    root += exfat_file_set("Timezone.txt", L["timezone"]["cluster"], 5,
                           created=EXFAT_TZ_LOCAL, created_tz=EXFAT_TZ_OFFSET)
    root += exfat_file_set("Empty.txt", 0, 0)
    root += exfat_file_set(EXFAT_LONG_NAME, L["longname"]["cluster"], 10)
    root += exfat_file_set("Subdir", sub, cs * L["subdir"]["count"],
                           attrs=0x10, contiguous=True)
    root += exfat_file_set("Tail.txt", L["tail"]["cluster"], 4)
    blob = b"".join(root)
    assert len(blob) - 96 < cs < len(blob) <= 2 * cs, \
        "Tail.txt must straddle clusters"
    put(L["root"][0], blob[:cs])
    put(L["root"][1], blob[cs:])

    bitmap = bytearray((EXFAT_CLUSTERS + 7) // 8)
    for c in used:
        bitmap[(c - 2) // 8] |= 1 << ((c - 2) % 8)
    put(L["bitmap"], bytes(bitmap))

    img[EXFAT_FAT_OFFSET * SECTOR:EXFAT_FAT_OFFSET * SECTOR + len(fat)] = fat
    return bytes(img)
