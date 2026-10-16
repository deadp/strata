"""Build synthetic EWF v1 (E01) segment files and split raw sets in memory.

Follows the libewf "Expert Witness Compression Format" specification.

Segment file:

    0     file header (13 bytes): "EVF\\x09\\x0d\\x0a\\xff\\x00", 0x01,
          segment number (u16), 0x0000
    13    sections, each starting with a 76-byte descriptor:
            type (16, NUL padded), next section offset (u64, absolute in
            this file), section size (u64, descriptor included),
            40 bytes padding, Adler-32 of the preceding 72 bytes (u32)

Sections written, in order:

    E01:  header, volume, sectors, table, table2, then "hash" + "done" for a
          single segment or "next" when another segment follows
    E02+: data (copy of volume), sectors, table, table2, then next/hash+done

    header   zlib-compressed text: "1", "main", tab-separated keys, values
    volume   1052 bytes: media type @0, chunk count @4, sectors per chunk
             @8, bytes per sector @12, sector count (u64) @16, media flags
             @36, compression level @52, ... Adler-32 @1048
    sectors  chunk data.  Uncompressed chunk = data + Adler-32 (u32 LE);
             compressed chunk = zlib stream
    table    entry count (u32), padding (4), base offset (u64), padding (4),
             Adler-32 of those 20 bytes; entries (u32: offset relative to the
             base offset, MSB set = compressed); Adler-32 of the entries
    hash     MD5 (16), unknown (16), Adler-32 (4)

Chunks are CHUNK_SIZE bytes (SECTORS_PER_CHUNK x 512).  build_e01() stores
even-numbered chunks zlib-compressed and odd ones uncompressed; the media's
last chunk is short when the sector count is not a whole number of chunks.
"""

import hashlib
import struct
import zlib

EVF_SIG = b"EVF\x09\x0d\x0a\xff\x00"
SECTOR = 512
SECTORS_PER_CHUNK = 4
CHUNK_SIZE = SECTOR * SECTORS_PER_CHUNK
DESC = 76

HEADER_FIELDS = [("c", "CASE-1"), ("n", "EV-7"), ("a", "synthetic disk"),
                 ("e", "Examiner"), ("t", "unit test"), ("av", "7.0"),
                 ("ov", "Linux"), ("m", "2026 9 16 10 0 0"),
                 ("u", "2026 9 16 10 0 0"), ("p", "0")]


def adler(data):
    return zlib.adler32(data) & 0xFFFFFFFF


def media(sectors=14):
    """Deterministic media content: `sectors` sectors, each distinct."""
    out = bytearray()
    for s in range(sectors):
        line = ("sector %04d " % s).encode("ascii")
        out += (line * (SECTOR // len(line) + 1))[:SECTOR]
    return bytes(out)


def descriptor(type_, offset, size, next_offset=None):
    raw = type_.encode("ascii").ljust(16, b"\x00")
    raw += struct.pack("<QQ", offset + size if next_offset is None
                       else next_offset, size)
    raw += bytes(40)
    return raw + struct.pack("<I", adler(raw))


def header_body(fields=HEADER_FIELDS):
    text = "1\nmain\n%s\n%s\n\n" % ("\t".join(k for k, _ in fields),
                                     "\t".join(v for _, v in fields))
    return zlib.compress(text.encode("ascii"))


def volume_body(chunk_count, sector_count, compression=1):
    body = bytearray(1052)
    body[0] = 0x01                                   # fixed disk
    struct.pack_into("<IIIQ", body, 4, chunk_count, SECTORS_PER_CHUNK,
                     SECTOR, sector_count)
    body[36] = 0x01                                  # image file
    body[52] = compression
    struct.pack_into("<I", body, 1048, adler(bytes(body[:1048])))
    return bytes(body)


def chunk_bytes(data, compress):
    if compress:
        return zlib.compress(data)
    return data + struct.pack("<I", adler(data))


def table_body(offsets, base, compressed_flags):
    head = struct.pack("<IIQI", len(offsets), 0, base, 0)
    head += struct.pack("<I", adler(head))
    entries = b"".join(struct.pack("<I", (o - base) | (0x80000000 if c else 0))
                       for o, c in zip(offsets, compressed_flags))
    return head + entries + struct.pack("<I", adler(entries))


def hash_body(md5):
    body = md5 + bytes(16)
    return body + struct.pack("<I", adler(body))


def segment(number, chunks, last, total_chunks, sector_count, md5,
            chunk_mutator=None):
    """One segment file.  `chunks` is a list of (data, compress)."""
    out = bytearray(EVF_SIG + struct.pack("<BHH", 1, number, 0))

    def section(type_, body, next_offset=None):
        start = len(out)
        out.extend(descriptor(type_, start, DESC + len(body), next_offset))
        out.extend(body)

    if number == 1:
        section("header", header_body())
        section("volume", volume_body(total_chunks, sector_count))
    else:
        section("data", volume_body(total_chunks, sector_count))

    sectors_start = len(out)
    stored = []
    for i, (data, compress) in enumerate(chunks):
        raw = chunk_bytes(data, compress)
        if chunk_mutator:
            raw = chunk_mutator(i, raw)
        stored.append(raw)
    offsets, pos = [], sectors_start + DESC
    for raw in stored:
        offsets.append(pos)
        pos += len(raw)
    section("sectors", b"".join(stored))

    flags = [c for _d, c in chunks]
    body = table_body(offsets, sectors_start, flags)
    section("table", body)
    section("table2", body)
    if last:
        section("hash", hash_body(md5))
        start = len(out)
        out.extend(descriptor("done", start, DESC, next_offset=start))
    else:
        start = len(out)
        out.extend(descriptor("next", start, DESC, next_offset=start))
    return bytes(out)


def build_e01(data=None, per_segment=None, compress=None, chunk_mutator=None):
    """Return a list of segment file bytes (E01, E02, ...) holding `data`.

    per_segment: chunks per segment file (default: all in one).
    compress:    function(chunk index) -> bool (default: even chunks).
    chunk_mutator: function(global chunk index, stored bytes) -> bytes, to
                   corrupt a chunk after its checksum was computed.
    """
    data = media() if data is None else data
    if len(data) % SECTOR:
        raise ValueError("media must be a whole number of sectors")
    compress = compress or (lambda i: i % 2 == 0)
    chunks = [(data[i:i + CHUNK_SIZE], compress(i // CHUNK_SIZE))
              for i in range(0, len(data), CHUNK_SIZE)]
    per_segment = per_segment or len(chunks)
    md5 = hashlib.md5(data).digest()
    segments = []
    groups = [chunks[i:i + per_segment]
              for i in range(0, len(chunks), per_segment)]
    base = 0
    for n, group in enumerate(groups):
        mut = None
        if chunk_mutator:
            mut = (lambda b: lambda i, raw: chunk_mutator(b + i, raw))(base)
        segments.append(segment(n + 1, group, n == len(groups) - 1,
                                len(chunks), len(data) // SECTOR, md5, mut))
        base += len(group)
    return segments


def segment_names(stem, count):
    """x.E01, x.E02, ... as written by EnCase for the first 99 segments."""
    return ["%s.E%02d" % (stem, i + 1) for i in range(count)]


def split_raw(data, piece):
    """Split raw media into .001/.002/... sized `piece` bytes."""
    return [data[i:i + piece] for i in range(0, len(data), piece)]


def split_names(stem, count, style="ftk", width=None, first=None):
    """Piece names as each acquisition tool writes them.

    ftk       stem.001, stem.002, ...      (FTK Imager, three digits from 1)
    guymager  stem.0000, stem.0001, ...    (Guymager, width digits from 0)
    split     stem.aa, stem.ab, ...        (GNU split, default suffixes)
    splitd    stem.00, stem.01, ...        (GNU split -d)
    """
    defaults = {"ftk": (3, 1), "guymager": (4, 0),
                "split": (2, 0), "splitd": (2, 0)}
    if style not in defaults:
        raise ValueError("unknown split style %r" % (style,))
    dwidth, dfirst = defaults[style]
    width = dwidth if width is None else width
    first = dfirst if first is None else first
    names = []
    for i in range(count):
        index = first + i
        if style == "split":
            letters = []
            for _ in range(width):
                letters.append(chr(97 + index % 26))
                index //= 26
            names.append("%s.%s" % (stem, "".join(reversed(letters))))
        else:
            names.append("%s.%0*d" % (stem, width, index))
    return names
