"""Synthetic Volume Shadow Service snapshot (and carrier disk) builders.

``build_vss_disk()`` wraps an NTFS volume from :mod:`tests.imagebuild_ntfs`
inside a differential shadow-copy image, encoded directly from the on-disk
format (no engine imports): volume header block, catalog block, store
location entry, store header, block list with one overlay descriptor, store
bitmap, and the differential-area bytes themselves.

The layout is fixed and documented in ``build_vss_disk``'s docstring so tests
can assert exact offsets and so the image can seed a fuzzer.
"""

import struct
import uuid

from tests.imagebuild_ntfs import build_ntfs, pattern

SECTOR = 512
STORE_GUID = uuid.UUID("3808876b-c176-4e48-b7ae-04046e6cc752")

# Fixed layout (all offsets in bytes of the carrier image).
VSS_VOLUME_HEADER = 0x1E00   # volume header block (GUID + capacity fields)
CATALOG_OFFSET = 0x30000     # catalog block (entries start 0x30080)
STORE_HEADER_OFFSET = 0x40000
STORE_LOCATION_OFFSET = 0x30080  # first catalog entry (the store entry)
STORE_BLOCK_SIZE = 0x4000    # every VSS record block is 16 KiB
STORE_CHUNK = 512            # granularity inside a redirected block
BLOCK_LIST_OFFSET = 0x50000
BLOCK_RANGES_OFFSET = 0x0000              # none present
BITMAP_OFFSET = 0x60000
DIFF_AREA_OFFSET = 0x70000
CARRIER_SIZE = 0x80000                    # 512 KiB

# Differential content: the shadow copy redirects volume offset 0xA000 (the
# first cluster of big.bin, LCN 40) to these bytes.
REDIRECT_VOLUME_OFFSET = 0xA000
DIFF_SIZE = 1024             # 2 chunks of 512 B — matches the descriptor bitmap
DIFF_SEED = 9

ORIGINATING_MACHINE = "SNAPBOX"
SERVICE_MACHINE = "SNAPSRV"

# The NTFS volume from imagebuild_ntfs is 128 clusters x 1024 bytes.
VOLUME_SIZE = 128 * 1024


def _block_header(record_type, data=b""):
    """A 16 KiB VSS record block: header (GUID, record type, sizes, zero
    timestamps and pointers) followed by ``data``, zero-padded."""
    block = bytearray(STORE_BLOCK_SIZE)
    block[0:16] = STORE_GUID.bytes_le
    struct.pack_into("<IIQQQQ", block, 16, 1, record_type, 0, 0, 0, 0)
    block[16:len(data) + 16] = data
    return block


def build_vss_image():
    """Bytes of a bare VSS store (volume header + catalog + store), without
    an NTFS volume beneath it. Useful for store-parser tests directly."""
    img = bytearray(DIFF_AREA_OFFSET + DIFF_SIZE)

    # Volume header block @0x1E00: GUID, then <QQQ> at +24 =
    # (snapshot_service_volume_size, catalog_offset, maximum_size).
    hdr = bytearray(STORE_BLOCK_SIZE)
    hdr[0:16] = STORE_GUID.bytes_le
    struct.pack_into("<QQQ", hdr, 24, VOLUME_SIZE, CATALOG_OFFSET, VOLUME_SIZE)
    img[VSS_VOLUME_HEADER:VSS_VOLUME_HEADER + STORE_BLOCK_SIZE] = hdr

    # Catalog block: header record (type 1), then two entries sharing one
    # GUID so they pair (layouts as in build_vss_disk below).
    catalog = bytearray(STORE_BLOCK_SIZE)
    catalog[0:16] = STORE_GUID.bytes_le
    struct.pack_into("<IIQQQQ", catalog, 16, 1, 1, 0, 0, 0, 0)
    struct.pack_into("<QQ", catalog, 0x80, 2, VOLUME_SIZE)
    catalog[0x90:0xA0] = STORE_GUID.bytes_le
    struct.pack_into("<Q", catalog, 0xA0, 0x01D9A0B0C0D0E0F0)  # created_at
    struct.pack_into("<Q", catalog, 0x100, 3)
    catalog[0x108:0x118] = STORE_GUID.bytes_le
    struct.pack_into("<QQQQ", catalog, 0x118, STORE_HEADER_OFFSET,
                     BLOCK_LIST_OFFSET, 0, BITMAP_OFFSET)
    img[CATALOG_OFFSET:CATALOG_OFFSET + STORE_BLOCK_SIZE] = catalog

    # Store header block: header (type 4), then the store information
    # (shadow-copy id, zero copy-set id, context/provider/flags) and the
    # two machine-name strings, exactly as the parser reads them.
    store = bytearray(STORE_BLOCK_SIZE)
    store[0:16] = STORE_GUID.bytes_le
    struct.pack_into("<II", store, 16, 1, 4)               # version 1, type 4
    info = bytearray(0x40)
    info[0:16] = STORE_GUID.bytes_le                       # shadow-copy id
    struct.pack_into("<III", info, 48, 0x1D, 0, 0x02000000)
    name = ORIGINATING_MACHINE.encode("utf-16-le") + b"\x00\x00"
    svc = SERVICE_MACHINE.encode("utf-16-le") + b"\x00\x00"
    info += struct.pack("<H", len(name) // 2) + name
    info += struct.pack("<H", len(svc) // 2) + svc
    struct.pack_into("<Q", store, 48, len(info))           # store info size
    store[128:128 + len(info)] = info
    img[STORE_HEADER_OFFSET:STORE_HEADER_OFFSET + STORE_BLOCK_SIZE] = store

    # Block list block: header (type 3), then one overlay descriptor @+0x80
    # covering the 16 KiB block at 0x8000 (chunk 16 = volume offset 0xA000).
    bl = bytearray(STORE_BLOCK_SIZE)
    bl[0:16] = STORE_GUID.bytes_le
    struct.pack_into("<IIQQQQ", bl, 16, 1, 3, 0, 0, 0, 0)
    struct.pack_into("<QQQII", bl, 0x80,
                     REDIRECT_VOLUME_OFFSET & ~(STORE_BLOCK_SIZE - 1),
                     0, DIFF_AREA_OFFSET - 16 * STORE_CHUNK, 0x02, 0b11 << 16)
    img[BLOCK_LIST_OFFSET:BLOCK_LIST_OFFSET + STORE_BLOCK_SIZE] = bl

    # Allocation bitmap block: words mirror the descriptors' bitmaps.
    bm = bytearray(STORE_BLOCK_SIZE)
    bm[0:16] = STORE_GUID.bytes_le
    struct.pack_into("<IIQQQQ", bm, 16, 1, 6, 0, 0, 0, 0)
    struct.pack_into("<I", bm, 128, 0b11 << 16)
    img[BITMAP_OFFSET:BITMAP_OFFSET + STORE_BLOCK_SIZE] = bm

    return bytes(img)


def build_vss_disk():
    """A GPT-free carrier disk: NTFS volume at 0 (``build_ntfs()`` output,
    padded), then a VSS store describing one differential snapshot.

    Layout after the 0x20000-byte NTFS volume (padded to 0x80000):

      0x1E00  volume header block (GUID; volume size 0x20000,
              catalog offset 0x30000, maximum size 0x20000)
      0x30000 catalog block: store-location entry @0x30080 pairing the
              store header @0x40000 and block list @0x50000
      0x40000 store header block (+ 64-byte store info)
      0x50000 block list block: one overlay descriptor @0x50080 mapping
              volume offset 0xA000 to store offset 0x70000 (flags 0x02,
              allocation bitmap 0b11 = both 512 B chunks)
      0x60000 allocation bitmap block (32-bit LE words, LSB-first)
      0x70000 differential bytes: ``pattern(2048, 9)``

    The redirect lands on big.bin's first cluster (volume offset 0xA000 =
    LCN 40): reading those bytes through the overlay yields the pattern,
    not the NTFS base content. hello.txt is resident, so the snapshot tree
    reads identical bytes and proves transparency for non-redirected data.
    """
    volume = build_ntfs()
    img = bytearray(CARRIER_SIZE)
    img[0:len(volume)] = volume

    # Volume header @0x1E00 — only the 128 bytes detect() reads, so the
    # NTFS volume beneath stays intact (the header sits in its slack).
    hdr = bytearray(128)
    hdr[0:16] = STORE_GUID.bytes_le
    struct.pack_into("<QQQ", hdr, 24, VOLUME_SIZE, CATALOG_OFFSET, VOLUME_SIZE)
    img[VSS_VOLUME_HEADER:VSS_VOLUME_HEADER + len(hdr)] = hdr

    # Catalog block: header record (type 1), then two entries sharing one
    # GUID so they pair:
    #   @0x30080 ENTRY_STORE (2): <Q> etype, <Q> volume_size,
    #                             GUID @+16, <Q> created filetime @+32
    #   @0x30100 ENTRY_STORE_LOCATION (3): <Q> 3, GUID @+8,
    #                             <QQQQ> @+24 = (store header, block list,
    #                             block ranges=0, allocation bitmap)
    catalog = bytearray(STORE_BLOCK_SIZE)
    catalog[0:16] = STORE_GUID.bytes_le
    struct.pack_into("<IIQQQQ", catalog, 16, 1, 1, 0, 0, 0, 0)
    struct.pack_into("<QQ", catalog, 0x80, 2, VOLUME_SIZE)
    catalog[0x90:0xA0] = STORE_GUID.bytes_le
    struct.pack_into("<Q", catalog, 0xA0, 0x01D9A0B0C0D0E0F0)  # created_at
    struct.pack_into("<Q", catalog, 0x100, 3)
    catalog[0x108:0x118] = STORE_GUID.bytes_le
    struct.pack_into("<QQQQ", catalog, 0x118, STORE_HEADER_OFFSET,
                     BLOCK_LIST_OFFSET, 0, BITMAP_OFFSET)
    img[CATALOG_OFFSET:CATALOG_OFFSET + STORE_BLOCK_SIZE] = catalog

    # Store header block @0x40000: header (type 4) + store information
    # (shadow-copy id, zero copy-set id, context/provider/flags) followed
    # by the originating/service machine name strings.
    store = bytearray(STORE_BLOCK_SIZE)
    store[0:16] = STORE_GUID.bytes_le
    struct.pack_into("<II", store, 16, 1, 4)               # version 1, type 4
    info = bytearray(0x40)
    info[0:16] = STORE_GUID.bytes_le                       # shadow-copy id
    # copy-set id (zero) @+16..32; context/provider/flags @+48.
    struct.pack_into("<III", info, 48, 0x1D, 0, 0x02000000)
    # Originating/service machine names follow the 64-byte store info
    # record: <H>-prefixed UTF-16LE, one right after the other.
    name = ORIGINATING_MACHINE.encode("utf-16-le") + b"\x00\x00"
    svc = SERVICE_MACHINE.encode("utf-16-le") + b"\x00\x00"
    info += struct.pack("<H", len(name) // 2) + name
    info += struct.pack("<H", len(svc) // 2) + svc
    struct.pack_into("<Q", store, 48, len(info))           # store info size
    store[128:128 + len(info)] = info
    img[STORE_HEADER_OFFSET:STORE_HEADER_OFFSET + STORE_BLOCK_SIZE] = store

    # Block list block: header (type 3, no ranges), then descriptors @+0x80.
    bl = bytearray(STORE_BLOCK_SIZE)
    bl[0:16] = STORE_GUID.bytes_le
    struct.pack_into("<IIQQQQ", bl, 16, 1, 3, 0, 0, 0, 0)
    desc = bytearray(32)
    # Descriptor covers the 16 KiB block containing volume offset 0xA000:
    # block starts at 0x8000; the redirect lands at delta 0x2000 (chunk 16).
    # store_data_offset is chosen so chunk 16 maps to DIFF_AREA_OFFSET.
    struct.pack_into("<QQQII", desc, 0,
                     REDIRECT_VOLUME_OFFSET & ~(STORE_BLOCK_SIZE - 1),
                     0, DIFF_AREA_OFFSET - 16 * STORE_CHUNK, 0x02, 0b11 << 16)
    bl[0x80:0x80 + 32] = desc
    img[BLOCK_LIST_OFFSET:BLOCK_LIST_OFFSET + STORE_BLOCK_SIZE] = bl

    # Allocation bitmap block: words mirror the descriptors' bitmaps.
    bm = bytearray(STORE_BLOCK_SIZE)
    bm[0:16] = STORE_GUID.bytes_le
    struct.pack_into("<IIQQQQ", bm, 16, 1, 6, 0, 0, 0, 0)
    struct.pack_into("<I", bm, 128, 0b11 << 16)
    img[BITMAP_OFFSET:BITMAP_OFFSET + STORE_BLOCK_SIZE] = bm

    # The differential bytes themselves.
    img[DIFF_AREA_OFFSET:DIFF_AREA_OFFSET + DIFF_SIZE] = pattern(DIFF_SIZE, 9)

    return bytes(img)