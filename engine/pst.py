import datetime
import struct

MAGIC = b"!BDN"
MAGIC_CLIENT = b"SM"

VER_ANSI = (14, 15)
VER_UNICODE = 23

CRYPT_NONE, CRYPT_PERMUTE, CRYPT_CYCLIC = 0, 1, 2

PTYPE_BBT, PTYPE_NBT = 0x80, 0x81

NID_TYPE_NORMAL_FOLDER = 0x02
NID_TYPE_SEARCH_FOLDER = 0x03
NID_TYPE_NORMAL_MESSAGE = 0x04
NID_TYPE_ATTACHMENT = 0x05
NID_TYPE_CONTENTS_TABLE = 0x0E
NID_TYPE_HIERARCHY_TABLE = 0x0D

NID_ROOT_FOLDER = 0x122

_MPBB_R = bytes((
    65,  54,  19,  98, 168,  33, 110, 187, 244,  22, 204,   4, 127, 100, 232,
    93,  30, 242, 203,  42, 116, 197,  94,  53, 210, 149,  71, 158, 150,  45,
    154, 136,  76, 125, 132,  63, 219, 172,  49, 182,  72,  95, 246, 196, 216,
    57, 139, 231,  35,  59,  56, 142, 200, 193, 223,  37, 177,  32, 165,  70,
    96,  78, 156, 251, 170, 211,  86,  81,  69, 124,  85,   0,   7, 201,  43,
    157, 133, 155,   9, 160, 143, 173, 179,  15,  99, 171, 137,  75, 215, 167,
    21,  90, 113, 102,  66, 191,  38,  74, 107, 152, 250, 234, 119,  83, 178,
    112,   5,  44, 253,  89,  58, 134, 126, 206,   6, 235, 130, 120,  87, 199,
    141,  67, 175, 180,  28, 212,  91, 205, 226, 233,  39,  79, 195,   8, 114,
    128, 207, 176, 239, 245,  40, 109, 190,  48,  77,  52, 146, 213,  14,  60,
    34,  50, 229, 228, 249, 159, 194, 209,  10, 129,  18, 225, 238, 145, 131,
    118, 227, 151, 230,  97, 138,  23, 121, 164, 183, 220, 144, 122,  92, 140,
    2, 166, 202, 105, 222,  80,  26,  17, 147, 185,  82, 135,  88, 252, 237,
    29,  55,  73,  27, 106, 224,  41,  51, 153, 189, 108, 217, 148, 243,  64,
    84, 111, 240, 198, 115, 184, 214,  62, 101,  24,  68,  31, 221, 103,  16,
    241,  12,  25, 236, 174,   3, 161,  20, 123, 169,  11, 255, 248, 163, 192,
    162,   1, 247,  46, 188,  36, 104, 117,  13, 254, 186,  47, 181, 208, 218,
    61,
))

_MPBB = None
_MPBB_INV = None

class PermuteTableUnavailable(Exception):
    pass

def set_permute_table(table):
    global _MPBB, _MPBB_INV
    t = bytes(table)
    if len(t) != 256 or len(set(t)) != 256:
        raise ValueError(
            "not a permutation of 0..255 (%d entries, %d distinct)"
            % (len(t), len(set(t))))
    _MPBB = t
    inv = bytearray(256)
    for i, v in enumerate(t):
        inv[v] = i
    _MPBB_INV = bytes(inv)
    return True

set_permute_table(_MPBB_R)

def _permute(data, encode=False):
    if _MPBB is None:
        raise PermuteTableUnavailable(
            "PST permute table not installed; block contents cannot be decoded")
    table = _MPBB if encode else _MPBB_INV
    return bytes(table[b] for b in data)

def _cyclic(data, key):
    out = bytearray(data)
    w = key & 0xFFFF
    x = ((key >> 16) & 0xFFFF) ^ w
    for i in range(len(out)):
        b = out[i]
        b = (b + (w & 0xFF)) & 0xFF
        b ^= (x & 0xFF)
        b = (b - (w & 0xFF)) & 0xFF
        out[i] = b
        w = (w + 1) & 0xFFFF
    return bytes(out)

def decode_block(data, crypt, bid):
    if crypt == CRYPT_NONE:
        return data
    if crypt == CRYPT_PERMUTE:
        return _permute(data)
    if crypt == CRYPT_CYCLIC:
        return _cyclic(data, bid)
    return data

def filetime(v):
    if not v:
        return None
    try:
        return (datetime.datetime(1601, 1, 1)
                + datetime.timedelta(microseconds=v // 10)).isoformat() + "Z"
    except (OverflowError, ValueError):
        return None

HN_SIG = 0xEC
CLIENT_PC = 0xBC
CLIENT_TC = 0x7C
BTH_SIG = 0xB5

_PT_INLINE = {0x0002: "<h", 0x0003: "<i", 0x0004: "<f", 0x000A: "<I",
              0x000B: "<H"}

PID_MESSAGE_CLASS = 0x001A
PID_SUBJECT = 0x0037
PID_CLIENT_SUBMIT_TIME = 0x0039
PID_SENT_REPRESENTING_NAME = 0x0042
PID_DISPLAY_CC = 0x0E03
PID_DISPLAY_TO = 0x0E04
PID_MESSAGE_DELIVERY_TIME = 0x0E06
PID_MESSAGE_FLAGS = 0x0E07
PID_MESSAGE_SIZE = 0x0E08
PID_NORMALIZED_SUBJECT = 0x0E1D
PID_SENDER_NAME = 0x0C1A
PID_SENDER_EMAIL = 0x0C1F
PID_SENT_REPRESENTING_EMAIL = 0x0065
PID_BODY = 0x1000
PID_DISPLAY_NAME = 0x3001
PID_CREATION_TIME = 0x3007
PID_LAST_MODIFICATION_TIME = 0x3008
PID_ATTACH_DATA_BIN = 0x3701
PID_ATTACH_LONG_FILENAME = 0x3707
PID_ATTACH_MIME_TAG = 0x370E
PID_ATTACH_SIZE = 0x0E20
PID_LTP_ROW_ID = 0x67F2

MSG_FLAG_READ = 0x01
MSG_FLAG_HAS_ATTACH = 0x10

def hnid_is_hid(hnid):
    return (hnid & 0x1F) == 0

class HeapOnNode:

    def __init__(self, blocks):
        self.blocks = blocks
        self.maps = []
        for b in blocks:
            self.maps.append(self._page_map(b))
        hdr = blocks[0] if blocks else b""
        self.sig = hdr[2] if len(hdr) > 3 else 0
        self.client_sig = hdr[3] if len(hdr) > 3 else 0
        self.user_root = (struct.unpack_from("<I", hdr, 4)[0]
                          if len(hdr) >= 8 else 0)

    @staticmethod
    def _page_map(b):
        if len(b) < 4:
            return []
        ib = struct.unpack_from("<H", b, 0)[0]
        if ib + 4 > len(b):
            return []
        n = struct.unpack_from("<H", b, ib)[0]
        end = ib + 4 + 2 * (n + 1)
        if end > len(b):
            return []
        return list(struct.unpack_from("<%dH" % (n + 1), b, ib + 4))

    @property
    def valid(self):
        return self.sig == HN_SIG

    def get(self, hid):
        if not hid or not hnid_is_hid(hid):
            return b""
        bi = (hid >> 16) & 0xFFFF
        ix = (hid >> 5) & 0x7FF
        if bi >= len(self.blocks) or ix < 1:
            return b""
        offs = self.maps[bi]
        if ix >= len(offs):
            return b""
        return self.blocks[bi][offs[ix - 1]:offs[ix]]

def bth_records(hn, hid_header):
    hdr = hn.get(hid_header)
    if len(hdr) < 8 or hdr[0] != BTH_SIG:
        return None, []
    cb_key, cb_ent, levels = hdr[1], hdr[2], hdr[3]
    hid_root = struct.unpack_from("<I", hdr, 4)[0]
    out = []
    if not cb_key or not cb_ent:
        return (cb_key, cb_ent), out

    def walk(hid, level, depth):
        if depth > 16:
            return
        data = hn.get(hid)
        if not data:
            return
        if level > 0:
            step = cb_key + 4
            for i in range(0, len(data) - step + 1, step):
                child = struct.unpack_from("<I", data, i + cb_key)[0]
                walk(child, level - 1, depth + 1)
        else:
            step = cb_key + cb_ent
            for i in range(0, len(data) - step + 1, step):
                out.append((data[i:i + cb_key], data[i + cb_key:i + step]))

    walk(hid_root, levels, 0)
    return (cb_key, cb_ent), out

def _clean_subject(s):
    if s and s[0] == "\x01" and len(s) >= 2:
        return s[2:]
    return s

class Pst:

    def __init__(self, data):
        self.data = data
        self.valid = False
        self.findings = []
        self.ansi = False
        if len(data) < 600 or data[:4] != MAGIC:
            return
        if data[8:10] != MAGIC_CLIENT:
            self.findings.append("Header magic client is not 'SM'.")
        self.ver = struct.unpack_from("<H", data, 10)[0]
        self.client_ver = struct.unpack_from("<H", data, 12)[0]
        if self.ver in VER_ANSI:
            self.ansi = True
            self.findings.append(
                "This is an ANSI (32-bit) PST. Its structures are the same "
                "shape at narrower widths; this parser reads the Unicode "
                "format only and will not guess at them.")
            return
        if self.ver != VER_UNICODE:
            self.findings.append("Unknown PST version %d." % self.ver)
            return

        self.crypt = data[513]
        self.sentinel = data[512]
        r = 180
        self.file_eof = struct.unpack_from("<Q", data, r + 4)[0]
        self.nbt_bid = struct.unpack_from("<Q", data, r + 36)[0]
        self.nbt_ib = struct.unpack_from("<Q", data, r + 44)[0]
        self.bbt_bid = struct.unpack_from("<Q", data, r + 52)[0]
        self.bbt_ib = struct.unpack_from("<Q", data, r + 60)[0]
        if self.file_eof != len(data):
            self.findings.append(
                "Header says the file ends at %d but it is %d bytes — it is "
                "truncated or has trailing data."
                % (self.file_eof, len(data)))
        self.valid = True
        self._bbt = None
        self._nbt = None

    def _page(self, ib):
        return self.data[ib:ib + 512]

    def _walk_bt(self, ib, want_leaf, out, depth=0, seen=None):
        if seen is None:
            seen = set()
        if ib in seen or depth > 32:
            return out
        seen.add(ib)
        page = self._page(ib)
        if len(page) < 512:
            return out
        cEnt = page[488]
        cbEnt = page[490]
        cLevel = page[491]
        ptype = page[496]
        if ptype not in (PTYPE_BBT, PTYPE_NBT):
            return out
        for i in range(cEnt):
            off = i * cbEnt
            if off + cbEnt > 488:
                break
            e = page[off:off + cbEnt]
            if cLevel > 0:
                child_ib = struct.unpack_from("<Q", e, 16)[0]
                self._walk_bt(child_ib, want_leaf, out, depth + 1, seen)
            else:
                out.append(e)
        return out

    def bbt(self):
        if self._bbt is None:
            self._bbt = {}
            for e in self._walk_bt(self.bbt_ib, True, []):
                bid, ib, cb = struct.unpack_from("<QQH", e, 0)
                self._bbt[bid & ~1] = (ib, cb)
        return self._bbt

    def nbt(self):
        if self._nbt is None:
            self._nbt = {}
            for e in self._walk_bt(self.nbt_ib, True, []):
                nid, bid_data, bid_sub, parent = struct.unpack_from("<QQQI", e, 0)
                self._nbt[nid & 0xFFFFFFFF] = {
                    "nid": nid & 0xFFFFFFFF,
                    "type": nid & 0x1F,
                    "data": bid_data,
                    "sub": bid_sub,
                    "parent": parent,
                }
        return self._nbt

    def blocks_of(self, bid, _depth=0, _out=None):
        out = [] if _out is None else _out
        if not bid or _depth > 16:
            return out
        loc = self.bbt().get(bid & ~1)
        if not loc:
            return out
        ib, cb = loc
        raw = self.data[ib:ib + cb]
        if len(raw) < cb:
            return out
        if bid & 0x02:
            if len(raw) >= 8 and raw[0] == 0x01:
                count = struct.unpack_from("<H", raw, 2)[0]
                for i in range(count):
                    off = 8 + i * 8
                    if off + 8 > len(raw):
                        break
                    self.blocks_of(struct.unpack_from("<Q", raw, off)[0],
                                   _depth + 1, out)
            return out
        out.append(decode_block(raw, self.crypt, bid))
        return out

    def block(self, bid):
        return b"".join(self.blocks_of(bid))

    def subnodes(self, bid, _depth=0, _out=None):
        out = {} if _out is None else _out
        if not bid or _depth > 16:
            return out
        loc = self.bbt().get(bid & ~1)
        if not loc:
            return out
        ib, cb = loc
        raw = self.data[ib:ib + cb]
        if len(raw) < 8 or raw[0] != 0x02:
            return out
        level, count = raw[1], struct.unpack_from("<H", raw, 2)[0]
        if level == 0:
            for i in range(count):
                off = 8 + i * 24
                if off + 24 > len(raw):
                    break
                nid, bd, bs = struct.unpack_from("<QQQ", raw, off)
                out[nid & 0xFFFFFFFF] = (bd, bs)
        else:
            for i in range(count):
                off = 8 + i * 16
                if off + 16 > len(raw):
                    break
                child = struct.unpack_from("<Q", raw, off + 8)[0]
                self.subnodes(child, _depth + 1, out)
        return out

    def heap(self, node):
        blocks = self.blocks_of(node["data"])
        if not blocks:
            return None
        hn = HeapOnNode(blocks)
        return hn if hn.valid else None

    def _hnid_bytes(self, hnid, hn, subs):
        if not hnid:
            return b""
        if hnid_is_hid(hnid):
            return hn.get(hnid)
        ent = subs.get(hnid & 0xFFFFFFFF)
        if not ent:
            return b""
        return b"".join(self.blocks_of(ent[0]))

    def _value(self, ptype, hnid, hn, subs):
        fmt = _PT_INLINE.get(ptype)
        if fmt:
            return struct.unpack_from(fmt, struct.pack("<I", hnid & 0xFFFFFFFF),
                                      0)[0]
        if ptype == 0x000B:
            return bool(hnid & 0xFF)
        if ptype in (0x0000, 0x0001):
            return None
        raw = self._hnid_bytes(hnid, hn, subs)
        if ptype == 0x001F:
            return raw.decode("utf-16-le", "replace").rstrip("\x00")
        if ptype == 0x001E:
            return raw.decode("cp1252", "replace").rstrip("\x00")
        if ptype == 0x0040:
            return filetime(struct.unpack_from("<Q", raw, 0)[0]
                            if len(raw) >= 8 else 0)
        if ptype == 0x0014:
            return struct.unpack_from("<q", raw, 0)[0] if len(raw) >= 8 else None
        if ptype == 0x0005 or ptype == 0x0007:
            return struct.unpack_from("<d", raw, 0)[0] if len(raw) >= 8 else None
        return raw

    def pc(self, node):
        hn = self.heap(node)
        if hn is None or hn.client_sig != CLIENT_PC:
            return {}
        subs = self.subnodes(node.get("sub") or 0)
        props = {}
        _, recs = bth_records(hn, hn.user_root)
        for key, ent in recs:
            if len(key) < 2 or len(ent) < 6:
                continue
            pid = struct.unpack_from("<H", key, 0)[0]
            ptype, hnid = struct.unpack_from("<HI", ent, 0)
            try:
                props[pid] = self._value(ptype, hnid, hn, subs)
            except Exception:
                props[pid] = None
        return props

    def tc(self, node):
        hn = self.heap(node)
        if hn is None or hn.client_sig != CLIENT_TC:
            return []
        subs = self.subnodes(node.get("sub") or 0)
        info = hn.get(hn.user_root)
        if len(info) < 22 or info[0] != CLIENT_TC:
            return []
        n_cols = info[1]
        rgib = struct.unpack_from("<4H", info, 2)
        hnid_rows = struct.unpack_from("<I", info, 14)[0]
        cols = []
        for i in range(n_cols):
            off = 22 + i * 8
            if off + 8 > len(info):
                break
            tag, ib_data, cb_data, i_bit = struct.unpack_from("<IHBB", info, off)
            cols.append((tag, ib_data, cb_data, i_bit))

        width = rgib[3]
        ceb_at = rgib[2]
        if width <= 0:
            return []

        if hnid_is_hid(hnid_rows):
            row_blocks = [hn.get(hnid_rows)]
        else:
            ent = subs.get(hnid_rows & 0xFFFFFFFF)
            row_blocks = self.blocks_of(ent[0]) if ent else []

        rows = []
        for blk in row_blocks:
            for r in range(len(blk) // width):
                row = blk[r * width:(r + 1) * width]
                rec = {}
                for tag, ib_data, cb_data, i_bit in cols:
                    byte = ceb_at + (i_bit >> 3)
                    if byte < len(row) and not (row[byte] & (0x80 >> (i_bit & 7))):
                        continue
                    if ib_data + cb_data > len(row):
                        continue
                    cell = row[ib_data:ib_data + cb_data]
                    ptype = tag & 0xFFFF
                    pid = (tag >> 16) & 0xFFFF
                    if cb_data == 4:
                        hnid = struct.unpack_from("<I", cell, 0)[0]
                    elif cb_data == 2:
                        hnid = struct.unpack_from("<H", cell, 0)[0]
                    elif cb_data == 1:
                        hnid = cell[0]
                    else:
                        rec[pid] = cell
                        continue
                    try:
                        rec[pid] = self._value(ptype, hnid, hn, subs)
                    except Exception:
                        rec[pid] = None
                rows.append(rec)
        return rows

    @staticmethod
    def _sibling(nid, nid_type):
        return (nid & ~0x1F) | nid_type

    def folders(self):
        nbt = self.nbt()
        out = []
        seen = set()

        def walk(nid, path, depth):
            if nid in seen or depth > 32:
                return
            seen.add(nid)
            node = nbt.get(nid)
            if not node:
                return
            props = self.pc(node)
            name = props.get(PID_DISPLAY_NAME) or ""
            here = path if not name else (path.rstrip("/") + "/" + name)
            if not here:
                here = "/"
            contents = nbt.get(self._sibling(nid, NID_TYPE_CONTENTS_TABLE))
            rows = self.tc(contents) if contents else []
            out.append({
                "nid": nid, "name": name or "(root)", "path": here,
                "depth": depth,
                "message_count": len(rows),
                "messages": [r.get(PID_LTP_ROW_ID) for r in rows
                             if r.get(PID_LTP_ROW_ID)],
                "created": props.get(PID_CREATION_TIME),
                "modified": props.get(PID_LAST_MODIFICATION_TIME),
            })
            hier = nbt.get(self._sibling(nid, NID_TYPE_HIERARCHY_TABLE))
            for row in (self.tc(hier) if hier else []):
                child = row.get(PID_LTP_ROW_ID)
                if isinstance(child, int) and child:
                    walk(child & 0xFFFFFFFF, here, depth + 1)

        walk(NID_ROOT_FOLDER, "", 0)
        return out

    def attachments(self, node):
        out = []
        for nid, (bd, bs) in self.subnodes(node.get("sub") or 0).items():
            if (nid & 0x1F) != NID_TYPE_ATTACHMENT:
                continue
            props = self.pc({"data": bd, "sub": bs})
            if not props:
                continue
            out.append({
                "nid": nid,
                "name": props.get(PID_ATTACH_LONG_FILENAME) or None,
                "size": props.get(PID_ATTACH_SIZE),
                "content_type": props.get(PID_ATTACH_MIME_TAG) or None,
            })
        return out

    def attachment_bytes(self, node, att_nid):
        """The one attachment property mail() never reads: the content
        itself. Kept out of attachments()/mail() because that runs over
        every message in the store, and decoding every attachment's binary
        content there would hash-run-eagerly what should be fetched only
        when an examiner opens one."""
        ent = self.subnodes(node.get("sub") or 0).get(int(att_nid) & 0xFFFFFFFF)
        if not ent or (int(att_nid) & 0x1F) != NID_TYPE_ATTACHMENT:
            return None
        bd, bs = ent
        props = self.pc({"data": bd, "sub": bs})
        return props.get(PID_ATTACH_DATA_BIN)

    def message(self, nid, folder=None):
        node = self.nbt().get(nid)
        if not node:
            return None
        props = self.pc(node)
        if not props:
            return None
        subject = _clean_subject(props.get(PID_SUBJECT) or "") or None
        if not subject:
            subject = props.get(PID_NORMALIZED_SUBJECT) or None
        sender = props.get(PID_SENDER_NAME) or \
            props.get(PID_SENT_REPRESENTING_NAME)
        email = props.get(PID_SENDER_EMAIL) or \
            props.get(PID_SENT_REPRESENTING_EMAIL)
        if sender and email and email != sender:
            frm = "%s <%s>" % (sender, email)
        else:
            frm = sender or email or None
        flags = props.get(PID_MESSAGE_FLAGS) or 0
        body = props.get(PID_BODY)
        if isinstance(body, bytes):
            body = body.decode("utf-8", "replace")
        atts = self.attachments(node) if flags & MSG_FLAG_HAS_ATTACH else []
        return {
            "nid": nid,
            "folder": folder,
            "subject": subject,
            "from": frm,
            "to": props.get(PID_DISPLAY_TO) or None,
            "cc": props.get(PID_DISPLAY_CC) or None,
            "date": props.get(PID_MESSAGE_DELIVERY_TIME) or
            props.get(PID_CLIENT_SUBMIT_TIME),
            "submitted": props.get(PID_CLIENT_SUBMIT_TIME),
            "delivered": props.get(PID_MESSAGE_DELIVERY_TIME),
            "message_class": props.get(PID_MESSAGE_CLASS),
            "size": props.get(PID_MESSAGE_SIZE),
            "read": bool(flags & MSG_FLAG_READ),
            "body": body,
            "attachments": atts,
        }

    def mail(self, limit=20000, progress=None):
        folders = self.folders()
        by_nid = {}
        for f in folders:
            for m in f["messages"]:
                by_nid.setdefault(m & 0xFFFFFFFF, f["path"])

        orphans = [nid for nid, n in self.nbt().items()
                   if (nid & 0x1F) == NID_TYPE_NORMAL_MESSAGE
                   and nid not in by_nid]

        out, failed = [], 0
        todo = list(by_nid.items()) + [(n, None) for n in orphans]
        total = max(1, len(todo))
        for i, (nid, path) in enumerate(todo):
            if progress and i % 32 == 0:
                progress(i / total)
            if len(out) >= limit:
                break
            try:
                m = self.message(nid, path)
            except Exception:
                failed += 1
                continue
            if m is None:
                failed += 1
                continue
            m["unlinked"] = path is None
            out.append(m)
        if progress:
            progress(1.0)
        out.sort(key=lambda m: m.get("date") or "", reverse=True)
        findings = list(self.findings)
        if orphans:
            findings.append(
                "%d message node%s present but listed in no folder's contents "
                "table. They are included and marked unlinked."
                % (len(orphans), "" if len(orphans) == 1 else "s"))
        if failed:
            findings.append(
                "%d message node%s could not be decoded and %s omitted."
                % (failed, "" if failed == 1 else "s",
                   "is" if failed == 1 else "are"))
        return {"folders": folders, "messages": out, "count": len(out),
                "findings": findings}

    def summary(self):
        nbt = self.nbt()
        counts = {}
        for node in nbt.values():
            counts[node["type"]] = counts.get(node["type"], 0) + 1
        return {
            "nodes": len(nbt),
            "blocks": len(self.bbt()),
            "folders": counts.get(NID_TYPE_NORMAL_FOLDER, 0),
            "search_folders": counts.get(NID_TYPE_SEARCH_FOLDER, 0),
            "messages": counts.get(NID_TYPE_NORMAL_MESSAGE, 0),
            "attachments": counts.get(NID_TYPE_ATTACHMENT, 0),
            "node_types": counts,
        }

    def info(self):
        return {
            "type": "pst", "format": "Unicode (64-bit)" if not self.ansi
            else "ANSI (32-bit)",
            "version": getattr(self, "ver", None),
            "client_version": getattr(self, "client_ver", None),
            "encoding": {CRYPT_NONE: "none", CRYPT_PERMUTE: "permute",
                         CRYPT_CYCLIC: "cyclic"}.get(getattr(self, "crypt", 0),
                                                     "unknown"),
            "file_eof": getattr(self, "file_eof", None),
            "findings": self.findings,
        }

def open_pst(data):
    p = Pst(data)
    return p if p.valid else None

def looks_like_pst(head):
    return head[:4] == MAGIC
