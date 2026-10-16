import hashlib
import os
import re
import struct
import threading

from .inflate import DAMAGED, STOPPED, inflate_ended
from .text import t as _t

SEGMENT_MAGIC = b"ADSEGMENTEDFILE\x00"
IMAGE_MAGIC = b"ADLOGICALIMAGE\x00\x00"

TYPE_FILE = 0
TYPE_DIR = 5

KEYS = {
    0x0003: "logical_size",
    0x0004: "physical_size",
    0x0007: "created",
    0x0008: "modified",
    0x0009: "accessed",
    0x5001: "md5",
    0x5002: "sha1",
    0xA007: "owner_sid",
    0xA008: "owner_name",
    0xA009: "group_sid",
    0xA00A: "group_name",
    0xA028: "source_name",
}

IMAGE_KEYS = {
    0x9001: "cluster_size",
    0x9002: "total_clusters",
    0x9003: "free_clusters",
    0x9005: "volume_name",
    0x9006: "volume_serial",
    0x900C: "source_os",
}

_TS = re.compile(r"^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})\.(\d+)$")

_SOURCE = re.compile(
    r"^(?P<image>[^:]*):Partition\s+(?P<number>\d+)\s*\[(?P<size>[^\]]*)\]"
    r":(?P<volume>.*?)\s*\[(?P<fs>[^\]]+)\]\s*$")

_SIZE = re.compile(r"^\s*([\d.]+)\s*(B|KB|MB|GB|TB)\s*$", re.I)
_UNITS = {"B": 1, "KB": 1 << 10, "MB": 1 << 20, "GB": 1 << 30, "TB": 1 << 40}

def _size_bytes(text):
    m = _SIZE.match(text or "")
    if not m:
        return None
    try:
        return int(float(m.group(1)) * _UNITS[m.group(2).upper()])
    except (ValueError, KeyError, OverflowError):
        return None

def split_source_name(name):
    m = _SOURCE.match(name or "")
    if not m:
        return None
    vol = (m.group("volume") or "").strip()
    return {
        "size_bytes": _size_bytes(m.group("size")),
        "image": m.group("image").strip() or None,
        "number": int(m.group("number")),
        "size_text": m.group("size").strip() or None,
        "volume": vol or None,
        "filesystem": m.group("fs").strip() or None,
    }

class Ad1Error(ValueError):

    def __init__(self, message, advice=""):
        self.message = message
        self.advice = advice or (
            "Re-acquire as E01 or raw, or export the files with the tool "
            "that produced the image.")
        super().__init__(message)

def looks_like_ad1(head):
    return head[:len(SEGMENT_MAGIC)] == SEGMENT_MAGIC

def _ts(text):
    m = _TS.match(text or "")
    if not m:
        return text or None
    y, mo, d, h, mi, s, frac = m.groups()
    return "%s-%s-%sT%s:%s:%s.%sZ" % (y, mo, d, h, mi, s, frac[:6])

class Ad1Segments:

    def __init__(self, path):
        self.paths = self._siblings(path)
        self._files = [open(p, "rb") for p in self.paths]
        try:
            self._init_from_files()
        except BaseException:
            # Otherwise a rejected segment leaves the evidence files held
            # open, which on Windows keeps them locked.
            self.close()
            raise

    def _init_from_files(self):
        self._io_lock = threading.Lock()
        self._sizes = [os.path.getsize(p) for p in self.paths]
        self.size = sum(self._sizes)

        head = self.read_at(0, 0x40)
        if not looks_like_ad1(head):
            raise Ad1Error(_t("ad1.ad1_segment_magic_missing"))
        if len(head) < 0x2C:
            raise Ad1Error(_t("ad1.segment_header_runs_past"))
        self.version = struct.unpack_from("<I", head, 0x10)[0]
        index = struct.unpack_from("<I", head, 0x18)[0]
        count = struct.unpack_from("<I", head, 0x1C)[0]
        self.header_length = struct.unpack_from("<I", head, 0x28)[0]
        if index != 1:
            raise Ad1Error(
                _t("ad1.segment_d_d_open") % (index, count))
        if count != len(self.paths):
            raise Ad1Error(
                _t("ad1.image_says_d_segments") % (count, len(self.paths),
                            ", ".join(os.path.basename(p)
                                      for p in self.paths)))
        if not (0 < self.header_length <= (1 << 20)):
            raise Ad1Error(_t("ad1.segment_header_length_d")
                           % self.header_length)

    @staticmethod
    def _siblings(path):
        stem, ext = os.path.splitext(path)
        if not re.match(r"^\.ad\d+$", ext, re.I):
            return [path]
        found = []
        d = os.path.dirname(path) or "."
        base = os.path.basename(stem).lower()
        for name in os.listdir(d):
            s, e = os.path.splitext(name)
            m = re.match(r"^\.ad(\d+)$", e, re.I)
            if m and s.lower() == base:
                found.append((int(m.group(1)), os.path.join(d, name)))
        return [p for _, p in sorted(found)] or [path]

    def read_at(self, offset, length):
        if offset < 0 or length <= 0 or offset >= self.size:
            return b""
        out = bytearray()
        with self._io_lock:
            for fh, size in zip(self._files, self._sizes):
                if offset >= size:
                    offset -= size
                    continue
                fh.seek(offset)
                got = fh.read(min(length - len(out), size - offset))
                out += got
                offset = 0
                if len(out) >= length:
                    break
        return bytes(out)

    def close(self):
        for fh in self._files:
            try:
                fh.close()
            except Exception:
                pass

class Ad1:

    name = "AD1"
    root_node = 0

    def __init__(self, source):
        self.src = source
        base = getattr(source, "header_length", None)
        if base is None:
            head = source.read_at(0, 0x40)
            if not looks_like_ad1(head):
                raise Ad1Error(_t("ad1.ad1_segment_magic_missing"))
            base = struct.unpack_from("<I", head, 0x28)[0]
        self.base = base

        h = source.read_at(base, 0x40)
        if h[:len(IMAGE_MAGIC)] != IMAGE_MAGIC:
            raise Ad1Error(
                _t("ad1.segment_header_ad1_but") % base)
        if len(h) < 0x38:
            raise Ad1Error(_t("ad1.logical_image_header_runs_past") % base)
        declared_chunk_size = struct.unpack_from("<I", h, 0x18)[0]
        # Bounded like _chunk_ceiling()'s decompression cap: real chunks run
        # tens of KB, and this value also sizes every zero-fill for a chunk
        # that fails to decompress, so an unbounded declaration is a
        # multi-gigabyte allocation from one damaged or hostile chunk.
        self.chunk_size = min(max(declared_chunk_size, 1), 1 << 26)
        self.findings = []
        if self.chunk_size != declared_chunk_size:
            self.findings.append(
                "Chunk size declared as %d bytes is implausible; using %d."
                % (declared_chunk_size, self.chunk_size))
        trailer = struct.unpack_from("<I", h, 0x24)[0]
        nlen = struct.unpack_from("<I", h, 0x2C)[0]
        noff = struct.unpack_from("<I", h, 0x34)[0]
        self.label = self._read(noff, nlen).decode("utf-8", "replace")

        self.sources = self._sources(trailer)
        if not self.sources:
            raise Ad1Error(_t("ad1.image_declares_sources"))
        first = self.sources[0]
        self.root_offset = first["root"]
        self.meta_offset = first["meta"]
        self.root_node = self.root_offset
        self.attributes = first["attributes"]

        if self.object(self.root_offset) is None:
            raise Ad1Error(_t("ad1.first_source_root_object"))

    def _chunk_ceiling(self):
        return max(1 << 16, min(int(self.chunk_size or 0), 1 << 26))

    def _sources(self, rel):
        out, at, seen = [], rel, set()
        while at and at not in seen and len(out) < 4096:
            seen.add(at)
            b = self._read(at, 0x30)
            if len(b) < 0x30:
                break
            nxt, root, meta = struct.unpack_from("<3Q", b, 0)
            kind, nlen = struct.unpack_from("<2I", b, 0x28)
            if nlen > 4096:
                break
            name = self._read(at + 0x30, nlen).decode("utf-8", "replace")
            out.append({
                "at": at, "root": root, "meta": meta, "kind": kind,
                "name": name,
                "parsed": split_source_name(name),
                "attributes": self._chain(meta, IMAGE_KEYS) if meta else {},
            })
            at = nxt
        return out

    def _read(self, rel, length):
        return self.src.read_at(self.base + rel, length)

    def object(self, rel):
        b = self._read(rel, 0x30)
        if len(b) < 0x30:
            return None
        nxt, child, meta, data, size = struct.unpack_from("<5Q", b, 0)
        kind, nlen = struct.unpack_from("<2I", b, 0x28)
        if nlen > 4096:
            return None
        name = self._read(rel + 0x30, nlen).decode("utf-8", "replace")
        return {"at": rel, "next": nxt, "child": child, "meta": meta,
                "data": data, "size": size, "type": kind, "name": name}

    def top_level(self, root=None):
        out = []
        at, seen = (self.root_offset if root is None else root), set()
        while at and at not in seen and len(out) < 4096:
            seen.add(at)
            o = self.object(at)
            if o is None:
                break
            out.append(o)
            at = o["next"]
        return out

    def children(self, rel):
        o = self.object(rel)
        if o is None or not o["child"]:
            return []
        out = []
        at = o["child"]
        seen = set()
        while at and at not in seen and len(out) < 1 << 20:
            seen.add(at)
            child = self.object(at)
            if child is None:
                break
            out.append(child)
            at = child["next"]
        return out

    def _chain(self, rel, names=None):
        names = names or KEYS
        out = {}
        at, seen = rel, set()
        while at and at not in seen:
            seen.add(at)
            r = self._read(at, 20)
            if len(r) < 20:
                break
            nxt, kind, key, ln = struct.unpack_from("<QIII", r, 0)
            if ln > (1 << 16):
                break
            raw = self._read(at + 20, ln)
            text = raw.decode("utf-8", "replace")
            name = names.get(key)
            if name is None:
                out.setdefault("unknown", {})["0x%04X" % key] = text
            elif kind == 5:
                out[name] = _ts(text)
            else:
                out[name] = text
            at = nxt
        return out

    def metadata(self, o):
        return self._chain(o["meta"]) if o.get("meta") else {}

    def chunk_table(self, o):
        if not o.get("data"):
            return []
        b = self._read(o["data"], 8)
        if len(b) < 8:
            return []
        count = struct.unpack("<Q", b)[0]
        ceiling = (o["size"] // max(1, self.chunk_size)) + 2
        if count > max(ceiling, 1 << 20):
            raise Ad1Error(
                _t("ad1.object_r_declares_d") % (o["name"], count, o["size"]))
        raw = self._read(o["data"] + 8, 8 * (count + 1))
        if len(raw) < 8 * (count + 1):
            raise Ad1Error(_t("ad1.chunk_table_r_runs") % o["name"])
        offs = struct.unpack("<%dQ" % (count + 1), raw)
        return list(zip(offs[:-1], offs[1:]))

    def _decompress_chunk(self, index, name, raw, nominal):
        """Inflate one stored chunk to exactly `nominal` bytes -- the length
        the AD1 chunking scheme expects at this index -- reporting and
        zero-filling whatever could not be recovered. Every chunk keeps its
        own place this way; nothing shifts because an earlier one came back
        short."""
        if not raw:
            self.findings.append(
                "Chunk %d of %r could not be read; zero-filled."
                % (index, name))
            return bytes(nominal)
        part, over, status = inflate_ended(raw, self._chunk_ceiling())
        if over:
            self.findings.append(
                "A chunk inflates past the %d-byte chunk size this "
                "container declares; it was cut off there."
                % self._chunk_ceiling())
        if not part or status == DAMAGED:
            self.findings.append(
                "Chunk %d of %r failed to decompress; zero-filled."
                % (index, name))
            return bytes(nominal)
        if len(part) < nominal:
            self.findings.append(
                "Chunk %d of %r is incomplete: its compressed data %s and "
                "gave %d of %d bytes; the rest reads as zeros."
                % (index, name, "ends early" if status == STOPPED
                   else "decompressed short", len(part), nominal))
            return part + bytes(nominal - len(part))
        return part[:nominal]

    def read_object(self, o, max_bytes=None):
        out = bytearray()
        want = o["size"] if max_bytes is None else min(o["size"], max_bytes)
        cs = max(1, self.chunk_size)
        for n, (start, end) in enumerate(self.chunk_table(o)):
            if want and len(out) >= want:
                break
            nominal = min(cs, o["size"] - n * cs)
            if nominal <= 0:
                break
            raw = self._read(start, end - start)
            out += self._decompress_chunk(n, o["name"], raw, nominal)
        if want and len(out) < want:
            out += bytes(want - len(out))
        return bytes(out[:want]) if want else bytes(out)

    def read_range(self, o, off, length):
        if off < 0 or length <= 0:
            return b""
        size = o["size"] or 0
        if off >= size:
            return b""
        length = min(length, size - off)
        cs = max(1, self.chunk_size)
        table = self.chunk_table(o)
        first = off // cs
        out = bytearray()
        for n in range(first, len(table)):
            if len(out) >= length:
                break
            nominal = min(cs, size - n * cs)
            if nominal <= 0:
                break
            start, end = table[n]
            raw = self._read(start, end - start)
            part = self._decompress_chunk(n, o["name"], raw, nominal)
            pos = n * cs
            out += part[max(0, off - pos):]
        return bytes(out[:length])

    def hash_object(self, o, algos=("md5", "sha1")):
        hs = {name: hashlib.new(name) for name in algos}
        total = 0
        cs = max(1, self.chunk_size)
        for n, (start, end) in enumerate(self.chunk_table(o)):
            nominal = min(cs, o["size"] - total)
            if nominal <= 0:
                break
            raw = self._read(start, end - start)
            part = self._decompress_chunk(n, o["name"], raw, nominal)
            total += len(part)
            for h in hs.values():
                h.update(part)
        return total, {k: v.hexdigest() for k, v in hs.items()}

    def verify(self, o):
        md = self.metadata(o)
        want_md5 = (md.get("md5") or "").lower().strip()
        want_sha1 = (md.get("sha1") or "").lower().strip()
        if not (want_md5 or want_sha1):
            return None
        total, digests = self.hash_object(o)
        got_md5, got_sha1 = digests["md5"], digests["sha1"]
        return {
            "bytes": total,
            "declared_size": o["size"],
            "size_ok": total == o["size"],
            "md5": got_md5, "stored_md5": want_md5 or None,
            "md5_ok": (got_md5 == want_md5) if want_md5 else None,
            "sha1": got_sha1, "stored_sha1": want_sha1 or None,
            "sha1_ok": (got_sha1 == want_sha1) if want_sha1 else None,
        }

class Ad1Image:

    def __init__(self, path):
        self.path = path
        self.segments = Ad1Segments(path)
        try:
            self.segment_paths = list(self.segments.paths)
            self.size = self.segments.size
            self.bytes_per_sector = 512
            self.header = {}
            self.stored_md5 = None
            self.stored_sha1 = None
            self._pos = 0
            self.image = Ad1(self.segments)
        except BaseException:
            # Otherwise a logical image the segments reject leaves them
            # held open, which on Windows keeps the evidence files locked.
            self.segments.close()
            raise
        self.findings = (list(self.image.attributes.get("findings", []) or [])
                         + list(self.image.findings))
        self.findings.append(
            "AD1 is a logical image: a selection of files and their metadata "
            "rather than a copy of media. The absence of a file from it is "
            "not evidence that it was absent from the source.")

    def read_at(self, offset, length):
        return self.segments.read_at(offset, length)

    def read(self, n=-1):
        d = self.read_at(self._pos, self.size - self._pos if n < 0 else n)
        self._pos += len(d)
        return d

    def seek(self, off, whence=0):
        if whence == 0:
            self._pos = off
        elif whence == 1:
            self._pos += off
        else:
            self._pos = self.size + off
        return self._pos

    def close(self):
        self.segments.close()

    def verify(self, progress=None):
        md5, sha1 = hashlib.md5(), hashlib.sha1()
        pos = 0
        while pos < self.size:
            d = self.read_at(pos, 1 << 20)
            if not d:
                break
            md5.update(d)
            sha1.update(d)
            pos += len(d)
            if progress:
                progress(pos / self.size)
        return {"computed_md5": md5.hexdigest(),
                "computed_sha1": sha1.hexdigest(),
                "stored_md5": None, "stored_sha1": None,
                "md5_match": None, "sha1_match": None,
                "note": _t("ad1.ad1_carries_digest_container")}

    def info(self):
        a = self.image.attributes
        return {
            "format": "AccessData logical image (AD1)",
            "segments": [os.path.basename(p) for p in self.segment_paths],
            "size": self.size,
            "bytes_per_sector": 512,
            "chunk_size": self.image.chunk_size,
            "logical": True,
            "acquisition": {
                "description": self.image.label,
                "source_volume": a.get("volume_name"),
                "volume_serial": a.get("volume_serial"),
                "source_os": a.get("source_os"),
            },
            "findings": self.findings,
        }
