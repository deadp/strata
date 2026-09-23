"""Build a minimal synthetic Unicode-format PST (.pst) for testing
engine.pst against, following [MS-PST]: Outlook Personal Folders (.pst)
File Format -- narrowed to exactly what engine.pst.Pst actually reads,
since nothing here needs to satisfy Outlook itself.

Layout produced by build_pst():

    0x0000  header (600+ bytes): magic "!BDN", client "SM", version 23
            (Unicode), crypt method (none), and the four root pointers
            engine.pst.Pst reads at fixed offsets: nbt_bid/nbt_ib,
            bbt_bid/bbt_ib.
    ...     BBT root page (512 bytes, PTYPE_BBT leaf): one BBTENTRY per
            block this file defines.
    ...     NBT root page (512 bytes, PTYPE_NBT leaf): one entry, an
            orphaned message (no folder references it) at MESSAGE_NID.
    ...     one subnode-tree block (btype 0x02, leaf): one SLENTRY per
            attachment, each pointing at that attachment's own
            heap-on-node (HN) block.
    ...     one HN block per attachment, holding a BTH (property context)
            with PID_ATTACH_LONG_FILENAME, PID_ATTACH_MIME_TAG,
            PID_ATTACH_SIZE and PID_ATTACH_DATA_BIN.
    ...     one HN block for the message itself, holding a BTH with
            PID_SUBJECT and PID_MESSAGE_FLAGS (MSG_FLAG_HAS_ATTACH set).

A fixed-size (<=4 byte) property value is stored inline in its BTH
record's hnid field, per the real format. Anything larger becomes its own
heap allocation, addressed by a heap ID (HID); nothing here is large
enough to need an external subnode instead.
"""

import struct

MAGIC = b"!BDN"
MAGIC_CLIENT = b"SM"
VER_UNICODE = 23

CRYPT_NONE = 0

HN_SIG = 0xEC
CLIENT_PC = 0xBC
BTH_SIG = 0xB5

PTYPE_BBT = 0x80
PTYPE_NBT = 0x81

NID_TYPE_ATTACHMENT = 0x05
NID_TYPE_NORMAL_MESSAGE = 0x04

PT_STRING = 0x001F
PT_INT32 = 0x0003
PT_BINARY = 0x0102

PID_SUBJECT = 0x0037
PID_MESSAGE_FLAGS = 0x0E07
PID_ATTACH_DATA_BIN = 0x3701
PID_ATTACH_LONG_FILENAME = 0x3707
PID_ATTACH_MIME_TAG = 0x370E
PID_ATTACH_SIZE = 0x0E20

MSG_FLAG_HAS_ATTACH = 0x10

HEADER_SIZE = 600
PAGE_SIZE = 512

# A deterministic, recognisable payload -- not a real PDF, just something
# attachment_bytes() should return byte-for-byte.
ATTACHMENT_BYTES = bytes((i * 13 + 7) & 0xFF for i in range(300))
ATTACHMENT_NAME = "invoice.pdf"
ATTACHMENT_MIME = "application/pdf"

# An attachment nid guaranteed absent from the subnode tree, for the
# "wrong id" case -- well past any index build_pst() itself hands out.
MISSING_ATTACHMENT_NID = (99 << 5) | NID_TYPE_ATTACHMENT


class HeapBuilder:
    """One heap-on-node (HN) block: a client_sig header followed by
    sequential allocations, each retrievable by a heap ID (HID)."""

    def __init__(self, client_sig):
        self.client_sig = client_sig
        self.allocs = []

    def alloc(self, data):
        """Adds a heap allocation and returns its HID (block 0)."""
        index = len(self.allocs) + 1
        self.allocs.append(bytes(data))
        return index << 5

    def build(self):
        body = b"".join(self.allocs)
        ib = 8 + len(body)
        offsets = [8]
        for a in self.allocs:
            offsets.append(offsets[-1] + len(a))
        page_map = struct.pack("<HH", len(self.allocs), 0)
        page_map += b"".join(struct.pack("<H", o) for o in offsets)
        header = struct.pack("<HBB", ib, HN_SIG, self.client_sig) + b"\x00" * 4
        return header + body + page_map


def _bth_property_context(properties):
    """properties: list of (pid, ptype, value_bytes_or_int). A ptype in
    _PT_INLINE-equivalent set (PT_INT32 here) stores its value directly in
    the 4-byte hnid; anything else is heap-allocated and referenced by HID.
    Returns the built HN block bytes (client_sig CLIENT_PC)."""
    hn = HeapBuilder(CLIENT_PC)
    records = []
    for pid, ptype, value in sorted(properties):
        if ptype == PT_INT32:
            hnid = value & 0xFFFFFFFF
        else:
            hnid = hn.alloc(value)
        records.append(struct.pack("<HHI", pid, ptype, hnid))
    leaf_hid = hn.alloc(b"".join(records))
    bth_header = struct.pack("<BBBBI", BTH_SIG, 2, 6, 0, leaf_hid)
    root_hid = hn.alloc(bth_header)
    hn_bytes = hn.build()
    # user_root (bytes 4-7) must point at the BTH header allocation.
    hn_bytes = hn_bytes[:4] + struct.pack("<I", root_hid) + hn_bytes[8:]
    return hn_bytes


class FileBuilder:
    """Accumulates blocks after a fixed-size header and records a BBT
    entry (bid -> (ib, cb)) for each one."""

    def __init__(self):
        self.chunks = [bytearray(HEADER_SIZE)]
        self.length = HEADER_SIZE
        self.bbt_entries = []
        # +4 each time: bit 0x01 clear keeps bid & ~1 == bid, and bit 0x02
        # clear keeps Pst.blocks_of() from treating it as an XBLOCK.
        self._next_bid = 4

    def add_block(self, data):
        bid = self._next_bid
        self._next_bid += 4
        ib = self.length
        self.chunks.append(bytes(data))
        self.length += len(data)
        self.bbt_entries.append((bid, ib, len(data)))
        return bid

    def add_page(self, data):
        assert len(data) == PAGE_SIZE
        ib = self.length
        self.chunks.append(bytes(data))
        self.length += PAGE_SIZE
        return ib

    def data(self):
        return b"".join(bytes(c) for c in self.chunks)


def _bt_page(entries, cb_ent, ptype):
    page = bytearray(PAGE_SIZE)
    for i, e in enumerate(entries):
        off = i * cb_ent
        page[off:off + len(e)] = e
    page[488] = len(entries)
    page[490] = cb_ent
    page[491] = 0  # leaf
    page[496] = ptype
    return bytes(page)


MESSAGE_NID = (1 << 5) | NID_TYPE_NORMAL_MESSAGE
MESSAGE_SUBJECT = "Q3 invoice"


def build_pst(attachment_count=1):
    """Returns (pst_bytes, node, attachment_nids): node is the dict to
    pass as Pst.attachments(node)/attachment_bytes(node, nid)'s node
    argument (a stand-in for a real Pst.nbt() entry -- the file also gets
    a real NBT entry at MESSAGE_NID, with its own minimal property context
    (subject, MSG_FLAG_HAS_ATTACH) pointing at the same subnode tree, so
    Pst.message()/mail() -- what the server's /api/mail actually calls --
    surface it as an orphaned message rather than dropping it), and
    attachment_nids is the list of real attachment nids build_pst
    created."""
    fb = FileBuilder()

    attachment_nids = []
    slentries = []
    for i in range(attachment_count):
        nid = ((i + 1) << 5) | NID_TYPE_ATTACHMENT
        pc = _bth_property_context([
            (PID_ATTACH_LONG_FILENAME, PT_STRING,
             ATTACHMENT_NAME.encode("utf-16-le")),
            (PID_ATTACH_MIME_TAG, PT_STRING,
             ATTACHMENT_MIME.encode("utf-16-le")),
            (PID_ATTACH_SIZE, PT_INT32, len(ATTACHMENT_BYTES)),
            (PID_ATTACH_DATA_BIN, PT_BINARY, ATTACHMENT_BYTES),
        ])
        data_bid = fb.add_block(pc)
        attachment_nids.append(nid)
        slentries.append(struct.pack("<QQQ", nid, data_bid, 0))

    subtree = struct.pack("<BBH", 0x02, 0, len(slentries)) + b"\x00" * 4
    subtree += b"".join(slentries)
    sub_bid = fb.add_block(subtree)

    message_pc = _bth_property_context([
        (PID_SUBJECT, PT_STRING, MESSAGE_SUBJECT.encode("utf-16-le")),
        (PID_MESSAGE_FLAGS, PT_INT32, MSG_FLAG_HAS_ATTACH),
    ])
    message_data_bid = fb.add_block(message_pc)

    bbt_entries = [struct.pack("<QQHBB", bid, ib, cb, 0, 0)
                   for bid, ib, cb in fb.bbt_entries]
    bbt_ib = fb.add_page(_bt_page(bbt_entries, 24, PTYPE_BBT))
    nbt_entries = [struct.pack("<QQQI", MESSAGE_NID, message_data_bid,
                               sub_bid, 0)]
    nbt_ib = fb.add_page(_bt_page(nbt_entries, 32, PTYPE_NBT))

    raw = bytearray(fb.data())
    struct.pack_into("<4s", raw, 0, MAGIC)
    struct.pack_into("<2s", raw, 8, MAGIC_CLIENT)
    struct.pack_into("<H", raw, 10, VER_UNICODE)
    struct.pack_into("<H", raw, 12, 0x15)
    raw[512] = 0x80
    raw[513] = CRYPT_NONE
    r = 180
    struct.pack_into("<Q", raw, r + 4, len(raw))
    struct.pack_into("<Q", raw, r + 36, 0)          # nbt_bid (unused)
    struct.pack_into("<Q", raw, r + 44, nbt_ib)
    struct.pack_into("<Q", raw, r + 52, 0)          # bbt_bid (unused)
    struct.pack_into("<Q", raw, r + 60, bbt_ib)

    node = {"data": 0, "sub": sub_bid}
    return bytes(raw), node, attachment_nids
