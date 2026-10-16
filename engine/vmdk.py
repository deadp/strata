import io
import os
import re
import struct
import threading

from .inflate import DAMAGED, STOPPED, inflate_ended
from .text import t as _t

SECTOR = 512
MAGIC = b"KDMV"

_HDR = struct.Struct("<4sII")
_HDR_Q = struct.Struct("<QQQQ")
FLAG_COMPRESSED = 0x20000

COMPRESSION_NONE = 0
COMPRESSION_DEFLATE = 1

GTE_UNALLOCATED = 0
GTE_ZEROED = 1

NO_GD = 0xFFFFFFFFFFFFFFFF

GRAIN_CACHE = 64

# Bounds for header and grain-table fields that come straight from the
# evidence, unvalidated: a genuine VMDK never comes close to these, but a
# damaged or hostile one otherwise trades a byte count for one that seeks
# to nowhere, allocates gigabytes, or divides by zero.
MAX_GRAIN_BYTES = 64 << 20        # real grains run 64 KiB-2 MiB
MAX_NUM_GTES = 1 << 16            # the default is 512
MAX_GRAIN_TABLES = 1 << 20        # bounds the grain directory read

class VmdkError(Exception):

    def __init__(self, message, advice=""):
        Exception.__init__(self, message)
        self.message = message
        self.advice = advice

def looks_like_vmdk(head):
    if head[:4] == MAGIC:
        return True
    return b"# Disk DescriptorFile" in head[:512]

_EXTENT = re.compile(
    r'^\s*(RW|RDONLY|NOACCESS)\s+(\d+)\s+(FLAT|SPARSE|ZERO|VMFS|VMFSSPARSE)'
    r'(?:\s+"([^"]*)")?(?:\s+(\d+))?', re.M)

def parse_descriptor(text):
    out = {"create_type": None, "parent_cid": None, "cid": None,
           "extents": [], "ddb": {}}
    m = re.search(r'createType\s*=\s*"([^"]*)"', text)
    if m:
        out["create_type"] = m.group(1)
    m = re.search(r'^\s*CID\s*=\s*(\w+)', text, re.M)
    if m:
        out["cid"] = m.group(1)
    m = re.search(r'^\s*parentCID\s*=\s*(\w+)', text, re.M)
    if m:
        out["parent_cid"] = m.group(1)
    for access, sectors, kind, name, offset in _EXTENT.findall(text):
        out["extents"].append({
            "access": access, "sectors": int(sectors), "kind": kind,
            "file": name or None, "offset": int(offset or 0),
        })
    for k, v in re.findall(r'^\s*(ddb\.[\w.]+)\s*=\s*"([^"]*)"', text, re.M):
        out["ddb"][k] = v
    return out

def _extent_beside(descriptor_path, name):
    # The name comes from the evidence. It is judged as text before anything
    # touches the filesystem, because even os.path.exists() on a UNC name
    # reaches the network. An extent must sit directly beside its descriptor
    # and not be a symlink (checked with lstat, which never follows one).
    # None when the name would lead anywhere else.
    if not name or "\x00" in name:
        return None
    if (os.path.isabs(name) or os.path.splitdrive(name)[0]
            or name.startswith(("/", "\\"))):
        return None
    base = os.path.dirname(os.path.abspath(descriptor_path))
    target = os.path.normpath(os.path.join(base, name))
    if os.path.normcase(os.path.dirname(target)) != os.path.normcase(base):
        return None
    if os.path.islink(target):
        return None
    return target

def _read_header(fh, at):
    fh.seek(at)
    raw = fh.read(SECTOR)
    if len(raw) < 84 or raw[:4] != MAGIC:
        return None
    magic, version, flags = _HDR.unpack_from(raw, 0)
    capacity, grain_size, desc_off, desc_size = _HDR_Q.unpack_from(raw, 12)
    num_gtes, = struct.unpack_from("<I", raw, 44)
    rgd, gd, overhead = struct.unpack_from("<QQQ", raw, 48)
    unclean, = struct.unpack_from("<B", raw, 72)
    compression, = struct.unpack_from("<H", raw, 77)
    return {"version": version, "flags": flags, "capacity": capacity,
            "grain_size": grain_size, "descriptor_offset": desc_off,
            "descriptor_size": desc_size, "num_gtes": num_gtes,
            "rgd_offset": rgd, "gd_offset": gd, "overhead": overhead,
            "unclean": bool(unclean), "compression": compression}

def _find_footer(fh, size):
    for back in range(2, 64):
        at = size - back * SECTOR
        if at < SECTOR:
            break
        head = _read_header(fh, at)
        if head and head["gd_offset"] not in (0, NO_GD):
            return head, at
    return None, None

class VmdkImage:

    def __init__(self, path):
        self.path = path
        self.segment_paths = [path]
        self.findings = []
        self.header = {}
        self.stored_md5 = None
        self.stored_sha1 = None
        self.bytes_per_sector = SECTOR
        self._pos = 0
        self._io_lock = threading.Lock()
        self._cache = {}
        self._cache_order = []
        self._fh = None
        self._flat = None

        try:
            self._load()
        except Exception:
            if self._fh:
                self._fh.close()
            raise

    def _load(self):
        with open(self.path, "rb") as probe:
            head = probe.read(2048)

        if head[:4] != MAGIC:
            return self._load_descriptor(head)

        self._fh = open(self.path, "rb")
        self.file_size = os.path.getsize(self.path)
        hdr = _read_header(self._fh, 0)
        if hdr is None:
            raise VmdkError(_t("vmdk.file_starts_kdmv_but"))

        self.descriptor = {}
        if hdr["descriptor_offset"] and hdr["descriptor_size"]:
            raw, clipped = self._bounded_read(
                hdr["descriptor_offset"] * SECTOR,
                hdr["descriptor_size"] * SECTOR)
            if clipped:
                self.findings.append(
                    "The descriptor declares %d bytes at sector %d, past "
                    "the end of the file; only %d bytes were read."
                    % (hdr["descriptor_size"] * SECTOR,
                       hdr["descriptor_offset"], len(raw)))
            self.descriptor = parse_descriptor(
                raw.split(b"\x00", 1)[0].decode("ascii", "replace"))
        self._refuse_if_differencing(self.descriptor)

        self.stream_optimized = bool(hdr["flags"] & FLAG_COMPRESSED)
        if hdr["compression"] not in (COMPRESSION_NONE, COMPRESSION_DEFLATE):
            raise VmdkError(
                _t("vmdk.vmdk_uses_compression_method")
                % hdr["compression"],
                "Only deflate is defined by the format. Convert the image "
                "with qemu-img or VMware's own tools first.")

        if hdr["gd_offset"] in (0, NO_GD):
            footer, at = _find_footer(self._fh, self.file_size)
            if footer is None:
                raise VmdkError(
                    _t("vmdk.stream_optimized_vmdk_whose"),
                    "The file is truncated. A stream-optimized extent is "
                    "written front to back and is not usable without its "
                    "tail.")
            self.findings.append(
                "Grain directory read from the footer at offset %d; the "
                "header at the start of a stream-optimized extent does not "
                "carry one." % at)
            hdr = footer

        if hdr["unclean"]:
            self.findings.append(
                "The extent is marked as not cleanly closed. What was in "
                "flight at the time is not in the file.")

        self.header = hdr
        self.size = hdr["capacity"] * SECTOR
        self.grain_bytes = hdr["grain_size"] * SECTOR
        if (not self.grain_bytes or hdr["grain_size"] % 8
                or self.grain_bytes > MAX_GRAIN_BYTES):
            raise VmdkError(_t("vmdk.implausible_vmdk_grain_size")
                            % hdr["grain_size"])
        self._read_tables(hdr)

    def _refuse_if_differencing(self, desc):
        parent = (desc or {}).get("parent_cid")
        create = ((desc or {}).get("create_type") or "").lower()
        if (parent and parent.lower() not in ("ffffffff", "")) or \
                "delta" in create or "differencing" in create:
            raise VmdkError(
                _t("vmdk.differencing_vmdk_holds_only"),
                "The parent carries the rest and Strata has not been given "
                "it. Merge the chain first, or treat this and the parent as "
                "separate exhibits knowing neither is whole.")

    def _load_descriptor(self, head):
        text = head.decode("ascii", "replace")
        if "# Disk DescriptorFile" not in text:
            raise VmdkError(_t("vmdk.vmdk"))
        with io.open(self.path, "r", encoding="ascii",
                     errors="replace") as fh:
            desc = parse_descriptor(fh.read(64 << 10))
        self.descriptor = desc
        self._refuse_if_differencing(desc)

        usable = [e for e in desc["extents"] if e["kind"] in ("FLAT", "VMFS")]
        if not usable:
            kinds = sorted({e["kind"] for e in desc["extents"]}) or ["none"]
            raise VmdkError(
                _t("vmdk.vmdk_descriptor_names_only") % "/".join(kinds),
                "A descriptor pointing at a SPARSE extent needs that extent "
                "opened instead; open the .vmdk holding the data.")
        if len(usable) > 1:
            raise VmdkError(
                _t("vmdk.vmdk_split_across_d") % len(usable),
                "Split flat extents are not joined by this reader yet. "
                "Concatenate them, or convert the set with qemu-img.")

        ext = usable[0]
        target = _extent_beside(self.path, ext["file"])
        if ext["file"] and target is None:
            raise VmdkError(
                _t("vmdk.extent_outside_folder") % ext["file"],
                "A flat extent is read only from the descriptor's own folder. "
                "Put the -flat file beside the descriptor and open it again; "
                "a descriptor that points elsewhere may have been altered.")
        if not ext["file"] or not os.path.exists(target):
            raise VmdkError(
                _t("vmdk.vmdk_descriptor_names_r")
                % (ext["file"] or "no file"),
                "A flat VMDK is two files. Acquire the -flat extent as well; "
                "the descriptor on its own carries no disk content at all.")

        self._flat = {"path": target, "offset": ext["offset"] * SECTOR}
        self._fh = open(target, "rb")
        self.segment_paths = [self.path, target]
        self.file_size = os.path.getsize(target)
        self.size = ext["sectors"] * SECTOR
        self.stream_optimized = False
        self.header = {}
        self.grain_bytes = 0
        self._gd = self._gt = None
        avail = self.file_size - self._flat["offset"]
        if avail < self.size:
            self.findings.append(
                "The flat extent is %d bytes shorter than the descriptor "
                "declares; the tail reads as zeros."
                % (self.size - avail))

    def _read_tables(self, hdr):
        num_gtes = hdr["num_gtes"]
        if not (0 < num_gtes <= MAX_NUM_GTES):
            raise VmdkError(_t("vmdk.implausible_vmdk_grain_table_entries")
                            % num_gtes)
        n_gt = -(-hdr["capacity"] // (hdr["grain_size"] * num_gtes))
        if not (0 < n_gt <= MAX_GRAIN_TABLES):
            raise VmdkError(_t("vmdk.implausible_vmdk_grain_table_count")
                            % n_gt)
        raw, clipped = self._bounded_read(hdr["gd_offset"] * SECTOR,
                                          4 * n_gt)
        if clipped or len(raw) < 4 * n_gt:
            raise VmdkError(_t("vmdk.grain_directory_runs_past"))
        self._gd = struct.unpack("<%dI" % n_gt, raw)
        self._num_gtes = num_gtes
        self._gt = {}
        self.tables_present = sum(1 for g in self._gd if g)
        self.tables_total = n_gt

    def _bounded_read(self, offset, size):
        """Read `size` bytes at `offset`, never past the end of the file, so
        a table entry or header field that names a huge or absurd position
        seeks nowhere rather than raising OSError or allocating what it
        claims. Returns (data, clipped)."""
        if offset < 0 or offset >= self.file_size or size <= 0:
            return b"", size > 0
        want = min(size, self.file_size - offset)
        self._fh.seek(offset)
        return self._fh.read(want), want < size

    def _table(self, n):
        got = self._gt.get(n)
        if got is not None:
            return got
        at = self._gd[n] if n < len(self._gd) else 0
        if not at:
            self._gt[n] = ()
            return ()
        with self._io_lock:
            raw, _ = self._bounded_read(at * SECTOR, 4 * self._num_gtes)
        got = struct.unpack("<%dI" % self._num_gtes, raw) \
            if len(raw) >= 4 * self._num_gtes else ()
        self._gt[n] = got
        return got

    def _grain(self, index):
        hit = self._cache.get(index)
        if hit is not None:
            return hit

        per_table = self._num_gtes
        table = self._table(index // per_table)
        if not table:
            return None
        gte = table[index % per_table]
        if gte in (GTE_UNALLOCATED, GTE_ZEROED):
            return None

        offset = gte * SECTOR
        with self._io_lock:
            if not self.stream_optimized:
                data, clipped = self._bounded_read(offset, self.grain_bytes)
                if clipped:
                    self._note_once(
                        "A grain table entry points past the end of the "
                        "file; that grain reads as zeros past where the "
                        "file ends.")
            else:
                head, clipped = self._bounded_read(offset, 12)
                if clipped or len(head) < 12:
                    return None
                _lba, csize = struct.unpack("<QI", head)
                if not csize:
                    self._note_once("A grain table points at a metadata "
                                    "marker rather than a grain; that grain "
                                    "reads as zeros.")
                    return None
                # A compressed grain can exceed its raw size only by zlib's
                # small worst-case expansion; a far larger declared size is
                # itself implausible, and reading it as given could mean
                # reading gigabytes from a file that holds nothing like it.
                cap = self.grain_bytes + self.grain_bytes // 64 + 1024
                comp, _ = self._bounded_read(offset + 12, min(csize, cap))
                if csize > cap:
                    self._note_once(
                        "A grain declares %d bytes of compressed data, more "
                        "than is plausible for a %d-byte grain; only %d "
                        "bytes were read." % (csize, self.grain_bytes,
                                              len(comp)))
        if self.stream_optimized:
            data, over, status = inflate_ended(comp, self.grain_bytes)
            if over:
                self._note_once("A compressed grain inflates past the %d-byte "
                                "grain size this descriptor declares; it was "
                                "cut off there." % self.grain_bytes)
            elif not data or status == DAMAGED:
                self._note_once("A compressed grain would not inflate; "
                                "it reads as zeros.")
                return None
            elif len(data) < self.grain_bytes:
                self._note_once(
                    "A grain is incomplete: its compressed data %s and gave "
                    "%d of %d bytes; the rest reads as zeros."
                    % ("ends early" if status == STOPPED
                       else "decompressed short", len(data), self.grain_bytes))
            elif status == STOPPED:
                self._note_once(
                    "A grain's compressed data ends before its checksum, "
                    "so it could not be verified.")

        if len(data) < self.grain_bytes:
            data = data + bytes(self.grain_bytes - len(data))

        self._cache[index] = data
        self._cache_order.append(index)
        if len(self._cache_order) > GRAIN_CACHE:
            self._cache.pop(self._cache_order.pop(0), None)
        return data

    def _note_once(self, message):
        if message not in self.findings:
            self.findings.append(message)

    def read_at(self, offset, length):
        if offset < 0 or offset >= self.size or length <= 0:
            return b""
        length = min(length, self.size - offset)

        if self._flat is not None:
            with self._io_lock:
                self._fh.seek(self._flat["offset"] + offset)
                got = self._fh.read(length)
            return got + bytes(length - len(got)) if len(got) < length else got

        out = bytearray()
        pos = offset
        while len(out) < length:
            index = pos // self.grain_bytes
            within = pos - index * self.grain_bytes
            take = min(self.grain_bytes - within, length - len(out))
            grain = self._grain(index)
            out += grain[within:within + take] if grain else bytes(take)
            pos += take
        return bytes(out)

    def read(self, n=-1):
        d = self.read_at(self._pos, self.size - self._pos if n < 0 else n)
        self._pos += len(d)
        return d

    def seek(self, off, whence=io.SEEK_SET):
        if whence == io.SEEK_SET:
            self._pos = off
        elif whence == io.SEEK_CUR:
            self._pos += off
        else:
            self._pos = self.size + off
        return self._pos

    def close(self):
        if self._fh:
            self._fh.close()

    def verify(self, progress=None):
        import hashlib
        md5, sha1 = hashlib.md5(), hashlib.sha1()
        pos = 0
        while pos < self.size:
            d = self.read_at(pos, 1 << 22)
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
                "note": _t("vmdk.vmdk_virtual_disk_format")}

    def info(self):
        desc = getattr(self, "descriptor", {}) or {}
        if self._flat is not None:
            kind = "flat"
        elif self.stream_optimized:
            kind = "stream-optimized"
        else:
            kind = "sparse"
        acq = {
            "create type": desc.get("create_type"),
            "adapter": desc.get("ddb", {}).get("ddb.adapterType"),
            "virtual hardware": desc.get("ddb", {}).get("ddb.virtualHWVersion"),
            "image uuid": desc.get("ddb", {}).get("ddb.uuid.image"),
            "container size on disk": getattr(self, "file_size", None),
        }
        if self._flat is None:
            acq["grain size"] = self.grain_bytes
            acq["grain tables present"] = "%d of %d" % (
                self.tables_present, self.tables_total)
        else:
            acq["extent"] = os.path.basename(self._flat["path"])
        return {
            "format": "VMware VMDK (%s)" % kind,
            "segments": [os.path.basename(p) for p in self.segment_paths],
            "size": self.size,
            "bytes_per_sector": SECTOR,
            "chunk_size": self.grain_bytes or (1 << 20),
            "acquisition": {k: v for k, v in acq.items() if v is not None},
            "findings": list(self.findings),
        }
