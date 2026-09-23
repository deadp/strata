"""Build synthetic hosted sparse VMDK extents in memory: monolithicSparse
(uncompressed grains) and streamOptimized (deflate-compressed grains).

Follows VMware's "Virtual Disk Format 5.0" technical note.

Sparse extent header (sector 0, little-endian):

    0   magic "KDMV"                 4   version (1 sparse, 3 streamOptimized)
    8   flags (bit 0 valid newline test, bit 1 redundant grain table,
        bit 16 compressed grains, bit 17 metadata markers)
    12  capacity (u64, sectors)      20  grainSize (u64, sectors)
    28  descriptorOffset (u64)       36  descriptorSize (u64, sectors)
    44  numGTEsPerGT (u32)           48  rgdOffset (u64)
    56  gdOffset (u64)               64  overHead (u64, sectors)
    72  uncleanShutdown (u8)         73  "\\n", " ", "\\r", "\\n"
    77  compressAlgorithm (u16: 0 none, 1 deflate)

The grain directory (GD) holds one u32 sector offset per grain table (GT);
each GT holds numGTEsPerGT u32 sector offsets, one per grain. 0 means
unallocated (reads as zeros).

monolithicSparse: header, descriptor, GD, GTs, then every allocated grain
stored whole and uncompressed at the sector its GTE names. The redundant GD
and GTs are not written (rgdOffset 0, flag bit 1 clear).

streamOptimized: the header's gdOffset is 0xFFFFFFFFFFFFFFFF (GD at end).
Each allocated grain is a grain marker, 12 bytes (LBA u64, compressed size
u32), followed by the zlib stream and padded to a sector boundary. After the
grains come, each on a sector boundary: a GT marker then the GT, a GD marker
then the GD, a footer marker then a copy of the header carrying the real
gdOffset, and an end-of-stream marker. A metadata marker is one sector: value
(u64, sectors that follow), size (u32, 0), type (u32: 0 EOS, 1 GT, 2 GD,
3 footer).

MEDIA is CAPACITY sectors. Grains 0, 1, 3, 6 and 7 hold distinct data; grains
2, 4 and 5 are unallocated and read as zeros. GTES = 4 gives two grain
tables, so the grain directory is exercised past its first entry.
"""

import struct
import zlib

SECTOR = 512
GRAIN_SECTORS = 8
GRAIN = GRAIN_SECTORS * SECTOR
GRAINS = 8
CAPACITY = GRAINS * GRAIN_SECTORS
GTES = 4
ALLOCATED = (0, 1, 3, 6, 7)
GD_AT_END = 0xFFFFFFFFFFFFFFFF

FLAG_NEWLINE_TEST = 0x1
FLAG_COMPRESSED = 0x10000
FLAG_MARKERS = 0x20000

MARKER_EOS, MARKER_GT, MARKER_GD, MARKER_FOOTER = 0, 1, 2, 3


def grain_content(index):
    """Distinct, poorly compressible-but-deterministic data for one grain."""
    out = bytearray()
    n = 0
    while len(out) < GRAIN:
        out += ("grain %d line %04d | " % (index, n)).encode("ascii")
        out += bytes((index * 37 + n * 11 + k) & 0xFF for k in range(24))
        n += 1
    return bytes(out[:GRAIN])


def media():
    return b"".join(grain_content(g) if g in ALLOCATED else bytes(GRAIN)
                    for g in range(GRAINS))


def descriptor(create_type):
    return ('# Disk DescriptorFile\nversion=1\nCID=12345678\n'
            'parentCID=ffffffff\ncreateType="%s"\n\n'
            '# Extent description\nRW %d SPARSE "disk.vmdk"\n\n'
            '# The Disk Data Base\n#DDB\n\n'
            'ddb.adapterType = "lsilogic"\n'
            'ddb.virtualHWVersion = "14"\n'
            'ddb.uuid.image = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"\n'
            % (create_type, CAPACITY)).encode("ascii")


def _sectors(n_bytes):
    return -(-n_bytes // SECTOR)


def _pad(data):
    return data + bytes(-len(data) % SECTOR)


def header(version, flags, desc_off, desc_sectors, gd_offset, overhead,
           compression):
    h = bytearray(SECTOR)
    struct.pack_into("<4sII", h, 0, b"KDMV", version, flags)
    struct.pack_into("<QQQQ", h, 12, CAPACITY, GRAIN_SECTORS, desc_off,
                     desc_sectors)
    struct.pack_into("<I", h, 44, GTES)
    struct.pack_into("<QQQ", h, 48, 0, gd_offset, overhead)
    h[72] = 0
    h[73:77] = b"\n \r\n"
    struct.pack_into("<H", h, 77, compression)
    return bytes(h)


def _tables():
    return -(-GRAINS // GTES)


def build_sparse():
    """monolithicSparse extent: (bytes)."""
    desc = _pad(descriptor("monolithicSparse"))
    desc_off = 1
    gd_off = desc_off + _sectors(len(desc))
    n_gt = _tables()
    gd_sectors = _sectors(4 * n_gt)
    gt_sectors = _sectors(4 * GTES)
    first_gt = gd_off + gd_sectors
    overhead = first_gt + n_gt * gt_sectors

    gtes = [0] * GRAINS
    grains = bytearray()
    at = overhead
    for g in ALLOCATED:
        gtes[g] = at
        grains += grain_content(g)
        at += GRAIN_SECTORS

    gd = [first_gt + t * gt_sectors for t in range(n_gt)]
    out = bytearray(header(1, FLAG_NEWLINE_TEST, desc_off,
                           _sectors(len(desc)), gd_off, overhead, 0))
    out += desc
    out += _pad(struct.pack("<%dI" % n_gt, *gd))
    for t in range(n_gt):
        chunk = gtes[t * GTES:(t + 1) * GTES]
        chunk += [0] * (GTES - len(chunk))
        out += _pad(struct.pack("<%dI" % GTES, *chunk))
    assert len(out) == overhead * SECTOR
    out += grains
    return bytes(out)


def _marker(kind, sectors_following):
    m = bytearray(SECTOR)
    struct.pack_into("<QII", m, 0, sectors_following, 0, kind)
    return bytes(m)


def build_stream_optimized(grain_mutator=None):
    """streamOptimized extent: (bytes, grain_offsets).

    `grain_mutator(index, compressed) -> compressed` may alter a grain's
    stored zlib stream; the marker's size field records the altered length,
    so a stream cut short is one that genuinely ends early. grain_offsets
    maps grain index -> byte offset of its grain marker.
    """
    desc = _pad(descriptor("streamOptimized"))
    flags = FLAG_NEWLINE_TEST | FLAG_COMPRESSED | FLAG_MARKERS
    desc_off = 1
    overhead = desc_off + _sectors(len(desc))

    out = bytearray(header(3, flags, desc_off, _sectors(len(desc)),
                           GD_AT_END, overhead, 1))
    out += desc
    assert len(out) == overhead * SECTOR

    gtes = [0] * GRAINS
    offsets = {}
    for g in ALLOCATED:
        comp = zlib.compress(grain_content(g), 9)
        if grain_mutator:
            comp = grain_mutator(g, comp)
        gtes[g] = len(out) // SECTOR
        offsets[g] = len(out)
        lba = g * GRAIN_SECTORS
        out += _pad(struct.pack("<QI", lba, len(comp)) + comp)

    n_gt = _tables()
    gd = []
    for t in range(n_gt):
        chunk = gtes[t * GTES:(t + 1) * GTES]
        chunk += [0] * (GTES - len(chunk))
        body = _pad(struct.pack("<%dI" % GTES, *chunk))
        out += _marker(MARKER_GT, len(body) // SECTOR)
        gd.append(len(out) // SECTOR)
        out += body

    body = _pad(struct.pack("<%dI" % n_gt, *gd))
    out += _marker(MARKER_GD, len(body) // SECTOR)
    gd_off = len(out) // SECTOR
    out += body

    out += _marker(MARKER_FOOTER, 1)
    out += header(3, flags, desc_off, _sectors(len(desc)), gd_off, overhead, 1)
    out += _marker(MARKER_EOS, 0)
    return bytes(out), offsets
