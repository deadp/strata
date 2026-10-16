import datetime
import struct

REGF = b"regf"
HBIN = b"hbin"
BASE_BLOCK = 4096

REG_TYPES = {
    0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY",
    4: "REG_DWORD", 5: "REG_DWORD_BIG_ENDIAN", 6: "REG_LINK",
    7: "REG_MULTI_SZ", 8: "REG_RESOURCE_LIST", 9: "REG_FULL_RESOURCE_DESCRIPTOR",
    10: "REG_RESOURCE_REQUIREMENTS_LIST", 11: "REG_QWORD",
}

INLINE_LIMIT = 2048

def filetime(v):
    if not v:
        return None
    try:
        return (datetime.datetime(1601, 1, 1)
                + datetime.timedelta(microseconds=v // 10)).isoformat() + "Z"
    except (OverflowError, ValueError):
        return None

def _u16(b, o): return struct.unpack_from("<H", b, o)[0]
def _u32(b, o): return struct.unpack_from("<I", b, o)[0]
def _i32(b, o): return struct.unpack_from("<i", b, o)[0]
def _u64(b, o): return struct.unpack_from("<Q", b, o)[0]

def _name(raw, compressed):
    try:
        if compressed:
            return raw.decode("latin-1")
        return raw.decode("utf-16-le", "replace")
    except Exception:
        return raw.decode("latin-1", "replace")

class Hive:

    def __init__(self, data, name=""):
        self.data = data
        self.name = name
        self.valid = data[:4] == REGF
        self.findings = []
        if not self.valid:
            return
        if len(data) < BASE_BLOCK:
            self.findings.append(
                "Hive is cut short inside its base block (%d of %d bytes), "
                "so it holds no keys to read." % (len(data), BASE_BLOCK))
        head = data[:48].ljust(48, b"\x00")
        self.seq1 = _u32(head, 4)
        self.seq2 = _u32(head, 8)
        self.modified = filetime(_u64(head, 12))
        self.major = _u32(head, 20)
        self.minor = _u32(head, 24)
        self.root_offset = _u32(head, 36)
        self.hive_bins_size = _u32(head, 40)
        self.dirty = self.seq1 != self.seq2
        if self.dirty:
            self.findings.append(
                "Hive was not cleanly unmounted (sequence %d/%d). The .LOG "
                "files hold changes not present here." % (self.seq1, self.seq2))
        self.embedded_name = self._embedded_name()

    def _embedded_name(self):
        raw = self.data[48:48 + 64]
        try:
            s = raw.decode("utf-16-le", "ignore").split("\x00")[0]
            return s or None
        except Exception:
            return None

    def cell(self, offset):
        pos = BASE_BLOCK + offset
        if pos < BASE_BLOCK or pos + 4 > len(self.data):
            return None
        size = _i32(self.data, pos)
        if size == 0:
            return None
        length = abs(size)
        if pos + length > len(self.data):
            return None
        return self.data[pos + 4:pos + length]

    def key(self, offset, deleted=False):
        b = self.cell(offset)
        if not b or len(b) < 74 or b[:2] != b"nk":
            return None
        flags = _u16(b, 2)
        name_len = _u16(b, 72)
        raw = b[76:76 + name_len]
        if len(raw) < name_len:
            return None
        return {
            "offset": offset,
            "name": _name(raw, flags & 0x20),
            "flags": flags,
            "root": bool(flags & 0x04),
            "modified": filetime(_u64(b, 4)),
            "parent": _u32(b, 16),
            "subkey_count": _u32(b, 20),
            "subkeys": _u32(b, 28),
            "value_count": _u32(b, 36),
            "values": _u32(b, 40),
            "classname_offset": _u32(b, 48),
            "deleted": deleted,
        }

    def root(self):
        return self.key(self.root_offset)

    def subkeys(self, key):
        if not key or key["subkey_count"] == 0:
            return []
        out = []
        self._walk_list(key["subkeys"], out, set())
        keys = []
        for off in out:
            k = self.key(off)
            if k:
                keys.append(k)
        keys.sort(key=lambda k: k["name"].lower())
        return keys

    def _walk_list(self, offset, out, seen, depth=0):
        if offset in (0, 0xFFFFFFFF) or offset in seen or depth > 16:
            return
        seen.add(offset)
        b = self.cell(offset)
        if not b or len(b) < 4:
            return
        sig, count = b[:2], _u16(b, 2)
        if sig in (b"lf", b"lh"):
            for i in range(count):
                p = 4 + i * 8
                if p + 4 <= len(b):
                    out.append(_u32(b, p))
        elif sig == b"li":
            for i in range(count):
                p = 4 + i * 4
                if p + 4 <= len(b):
                    out.append(_u32(b, p))
        elif sig == b"ri":
            for i in range(count):
                p = 4 + i * 4
                if p + 4 <= len(b):
                    self._walk_list(_u32(b, p), out, seen, depth + 1)

    def values(self, key, inline=True):
        if not key or key["value_count"] == 0:
            return []
        lst = self.cell(key["values"])
        if not lst:
            return []
        out = []
        for i in range(key["value_count"]):
            p = i * 4
            if p + 4 > len(lst):
                break
            v = self.value(_u32(lst, p), inline=inline)
            if v:
                out.append(v)
        return out

    def value(self, offset, deleted=False, inline=True):
        b = self.cell(offset)
        if not b or len(b) < 20 or b[:2] != b"vk":
            return None
        name_len = _u16(b, 2)
        data_len = _u32(b, 4)
        data_off = _u32(b, 8)
        vtype = _u32(b, 12)
        flags = _u16(b, 16)
        name = _name(b[20:20 + name_len], flags & 0x01) if name_len else "(Default)"

        resident = bool(data_len & 0x80000000)
        size = data_len & 0x7FFFFFFF
        if resident:
            raw = struct.pack("<I", data_off)[:min(size, 4)]
        else:
            raw = self._value_data(data_off, size)

        v = {
            "offset": offset, "name": name, "type": REG_TYPES.get(vtype, "0x%X" % vtype),
            "type_id": vtype, "size": size, "deleted": deleted,
            "resident": resident, "data_offset": None if resident else data_off,
        }
        if inline and size <= INLINE_LIMIT:
            v["value"] = self.decode(vtype, raw)
        elif inline:
            v["value"] = None
            v["truncated"] = True
        return v

    BIG_DATA_LIMIT = 16344

    def value_bytes(self, vk_offset):
        b = self.cell(vk_offset)
        if not b or len(b) < 20 or b[:2] != b"vk":
            return b""
        data_len = _u32(b, 4)
        data_off = _u32(b, 8)
        if data_len & 0x80000000:
            size = data_len & 0x7FFFFFFF
            return struct.pack("<I", data_off)[:min(size, 4)]
        return self._value_data(data_off, data_len & 0x7FFFFFFF)

    def _value_data(self, offset, size):
        cell = self.cell(offset)
        if not cell:
            return b""
        if size > self.BIG_DATA_LIMIT and cell[:2] == b"db":
            count = _u16(cell, 2)
            list_off = _u32(cell, 4)
            seglist = self.cell(list_off) or b""
            out = bytearray()
            for i in range(count):
                if (i + 1) * 4 > len(seglist):
                    break
                seg = self.cell(_u32(seglist, i * 4))
                if seg is None:
                    break
                out += seg[:self.BIG_DATA_LIMIT]
                if len(out) >= size:
                    break
            return bytes(out[:size])
        return cell[:size]

    @staticmethod
    def decode(vtype, raw):
        try:
            if vtype in (1, 2, 6):
                return raw.decode("utf-16-le", "replace").split("\x00")[0]
            if vtype == 7:
                s = raw.decode("utf-16-le", "replace")
                return [x for x in s.split("\x00") if x]
            if vtype == 4:
                return struct.unpack("<I", raw[:4].ljust(4, b"\x00"))[0]
            if vtype == 5:
                return struct.unpack(">I", raw[:4].ljust(4, b"\x00"))[0]
            if vtype == 11:
                return struct.unpack("<Q", raw[:8].ljust(8, b"\x00"))[0]
        except Exception:
            pass
        return " ".join("%02X" % c for c in raw[:64]) + (" …" if len(raw) > 64 else "")

    def open_path(self, path):
        k = self.root()
        if not path or path in ("\\", "/"):
            return k
        for part in path.replace("/", "\\").strip("\\").split("\\"):
            if not part:
                continue
            nxt = None
            for s in self.subkeys(k):
                if s["name"].lower() == part.lower():
                    nxt = s
                    break
            if not nxt:
                return None
            k = nxt
        return k

    def carve_deleted(self, limit=5000):
        keys, values = [], []
        pos = BASE_BLOCK
        declared = BASE_BLOCK + self.hive_bins_size if self.hive_bins_size else 0
        end = min(len(self.data), declared or len(self.data))
        while pos + 32 <= end and len(keys) + len(values) < limit:
            if self.data[pos:pos + 4] != HBIN:
                pos += 4096
                continue
            bin_size = _u32(self.data, pos + 8)
            if bin_size < 4096 or pos + bin_size > end:
                bin_size = 4096
            cur = pos + 32
            stop = min(pos + bin_size, end)   # a hive cut short mid-bin
            while cur + 4 <= stop:
                size = _i32(self.data, cur)
                length = abs(size)
                if length < 8 or cur + length > stop:
                    break
                if size > 0:
                    body = self.data[cur + 4:cur + length]
                    rel = cur - BASE_BLOCK
                    if body[:2] == b"nk":
                        k = self.key(rel, deleted=True)
                        if k and k["name"]:
                            keys.append(k)
                    elif body[:2] == b"vk":
                        v = self.value(rel, deleted=True)
                        if v:
                            values.append(v)
                cur += length
            pos += bin_size
        return {"keys": keys, "values": values}

    def info(self):
        return {
            "type": "regf", "name": self.name,
            "embedded_name": self.embedded_name,
            "version": "%d.%d" % (self.major, self.minor),
            "modified": self.modified,
            "sequence": [self.seq1, self.seq2],
            "dirty": self.dirty,
            "size": len(self.data),
            "findings": self.findings,
        }

def open_hive(data, name=""):
    h = Hive(data, name)
    return h if h.valid else None

WELL_KNOWN = [
    ("ntuser.dat", "NTUSER.DAT", "Per-user settings: typed paths, run MRU, "
                                 "mounted devices, recent documents."),
    ("usrclass.dat", "UsrClass.DAT", "Per-user class registrations, including "
                                     "shellbags."),
    ("system", "SYSTEM", "Services, mounted devices, USB history, time zone, "
                         "computer name."),
    ("software", "SOFTWARE", "Installed software, OS build, network profiles, "
                             "autostart entries."),
    ("sam", "SAM", "Local accounts, RIDs, login counts, last login."),
    ("security", "SECURITY", "Local security policy."),
    ("default", "DEFAULT", "Default user profile."),
    ("amcache.hve", "Amcache.hve", "Executed and installed program metadata."),
]

def classify(path):
    low = (path or "").replace("/", "\\").lower()
    base = low.rsplit("\\", 1)[-1]
    for needle, label, why in WELL_KNOWN:
        if base == needle:
            return {"label": label, "why": why}
    return None
