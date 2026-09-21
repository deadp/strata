import datetime
import struct
import uuid

VSS_GUID = "3808876b-c176-4e48-b7ae-04046e6cc752"
VOLUME_HEADER_OFFSET = 0x1E00
CATALOG_BLOCK_SIZE = 0x4000
CATALOG_ENTRY_SIZE = 128
ENTRY_END = 0x01
ENTRY_STORE = 0x02
ENTRY_STORE_LOCATION = 0x03
STORE_HEADER_SIZE = 64            # store information, after the 128 B block header
BLOCK_HEADER_SIZE = 128
BLOCK_LIST = 0x03
BLOCK_HEADER = 0x04
BLOCK_RANGES = 0x05
BLOCK_BITMAP = 0x06
STORE_BLOCK_SIZE = 0x4000        # differential-area blocks are this large
STORE_CHUNK = 512                # granularity inside a redirected block

# Snapshot context (why the copy was taken).
CONTEXTS = {
    0x0: "backup",
    0x9: "application rollback",
    0xD: "client accessible (writers)",
    0x10: "file share backup",
    0x19: "NAS rollback",
    0x1D: "client accessible",
}

# Attribute flags. Only the two names the format document spells out are
# certain; anything else is reported hex-only.
FLAG_NAMES = {
    0x1: "persistent",
    0x2000000: "TXF recovery",
}

# Block-list descriptor flags.
DESC_FORWARDER = 0x01
DESC_OVERLAY = 0x02
DESC_NOT_USED = 0x04


def filetime(v):
    if not v:
        return None
    try:
        return (datetime.datetime(1601, 1, 1)
                + datetime.timedelta(microseconds=v // 10)).isoformat() + "Z"
    except (OverflowError, ValueError):
        return None

def _guid(b):
    try:
        return str(uuid.UUID(bytes_le=b))
    except (ValueError, TypeError):
        return None

def detect(source):
    try:
        hdr = source.read_at(VOLUME_HEADER_OFFSET, 128)
    except Exception:
        return None
    if len(hdr) < 128:
        return None
    if _guid(hdr[0:16]) != VSS_GUID:
        return None
    version, rec_type = struct.unpack_from("<II", hdr, 16)
    current, catalog, maximum = struct.unpack_from("<QQQ", hdr, 24)
    return {
        "present": True, "version": version, "record_type": rec_type,
        "current_offset": current, "catalog_offset": catalog,
        "maximum_size": maximum,
    }

def read_catalog(source, catalog_offset, limit_blocks=64):
    entries = []
    offset = catalog_offset
    seen = set()
    blocks = 0
    while offset and offset not in seen and blocks < limit_blocks:
        seen.add(offset)
        blocks += 1
        try:
            block = source.read_at(offset, CATALOG_BLOCK_SIZE)
        except Exception:
            break
        if len(block) < 128:
            break
        if _guid(block[0:16]) != VSS_GUID:
            break
        nxt = struct.unpack_from("<Q", block, 40)[0]
        pos = 128
        stop = False
        while pos + CATALOG_ENTRY_SIZE <= len(block):
            etype = struct.unpack_from("<Q", block, pos)[0]
            if etype == ENTRY_END:
                stop = True
                break
            if etype in (ENTRY_STORE, ENTRY_STORE_LOCATION):
                entries.append((etype, block[pos:pos + CATALOG_ENTRY_SIZE]))
            pos += CATALOG_ENTRY_SIZE
        if stop:
            break
        offset = nxt
    return entries

def _string16(block, pos):
    """A <H size-prefixed UTF-16LE string, or None when empty/out of range."""
    if pos + 2 > len(block):
        return None
    (n,) = struct.unpack_from("<H", block, pos)
    if not n:
        return None
    raw = block[pos + 2:pos + 2 + n * 2]
    if len(raw) < n * 2:
        return None
    try:
        return raw.decode("utf-16-le").rstrip("\x00") or None
    except UnicodeDecodeError:
        return None

def snapshots(source):
    info = detect(source)
    if not info:
        return {"present": False, "snapshots": [], "findings": []}

    raw = read_catalog(source, info["catalog_offset"])
    stores, locations = {}, {}
    order = []
    for etype, e in raw:
        if etype == ENTRY_STORE:
            vol_size = struct.unpack_from("<Q", e, 8)[0]
            gid = _guid(e[16:32])
            created = struct.unpack_from("<Q", e, 32)[0]
            if gid:
                stores[gid] = {"id": gid, "volume_size": vol_size,
                               "created_at": filetime(created)}
                order.append(gid)
        else:
            gid = _guid(e[8:24])
            hdr, blist, brange, bitmap = struct.unpack_from("<QQQQ", e, 24)
            if gid:
                locations[gid] = {"header_offset": hdr,
                                  "block_list_offset": blist,
                                  "block_range_offset": brange,
                                  "bitmap_offset": bitmap}

    findings = []
    out = []
    for gid in order:
        snap = dict(stores[gid])
        loc = locations.get(gid)
        if not loc:
            snap["unsupported"] = ("No location entry in the catalog, so this "
                                   "snapshot's blocks cannot be found.")
            findings.append("Shadow copy %s has no store location entry." % gid[:8])
        else:
            snap.update(loc)
            if loc.get("header_offset"):
                hdr = read_store_header(source, loc["header_offset"], findings)
                if hdr:
                    ctx = hdr.get("context")
                    name = CONTEXTS.get(ctx)
                    snap["context"] = "0x%X" % ctx if ctx is not None else None
                    snap["context_name"] = name
                    if name is None:
                        findings.append(
                            "Shadow copy %s has an unrecognised context 0x%X."
                            % (gid[:8], ctx))
                    flags = hdr.get("attribute_flags") or 0
                    names = [label for bit, label in FLAG_NAMES.items()
                             if flags & bit]
                    if flags and not names:
                        findings.append(
                            "Shadow copy %s has unrecognised attribute flags "
                            "0x%X." % (gid[:8], flags))
                    snap["attribute_flags"] = "0x%X" % flags
                    snap["attribute_flag_names"] = names
                    snap["copy_set_id"] = hdr.get("copy_set_id")
                    snap["originating_machine"] = hdr.get("originating_machine")
                    snap["service_machine"] = hdr.get("service_machine")
                records = []
                for key, label in (("block_list_offset", "block list"),
                                   ("block_range_offset", "block ranges"),
                                   ("bitmap_offset", "bitmap")):
                    if loc.get(key):
                        records.append(label)
                snap["store_records"] = records
        out.append(snap)

    out.sort(key=lambda s: s.get("created_at") or "", reverse=True)
    return {"present": True, "snapshots": out, "findings": findings,
            "catalog_offset": info["catalog_offset"],
            "volume_maximum": info["maximum_size"]}

def read_store_header(source, header_offset, findings=None):
    """Store-header block (record type 0x04): the 128 B block header plus
    the 48 B store information and the machine-name strings."""
    try:
        block = source.read_at(header_offset, CATALOG_BLOCK_SIZE)
    except Exception as exc:
        if findings is not None:
            findings.append("Store header at 0x%X could not be read (%s)."
                            % (header_offset, exc))
        return None
    if len(block) < BLOCK_HEADER_SIZE + STORE_HEADER_SIZE:
        if findings is not None:
            findings.append("Store header at 0x%X is truncated." % header_offset)
        return None
    if _guid(block[0:16]) != VSS_GUID:
        if findings is not None:
            findings.append("Store header at 0x%X lacks the store GUID."
                            % header_offset)
        return None
    version, record_type = struct.unpack_from("<II", block, 16)
    if record_type != BLOCK_HEADER:
        if findings is not None:
            findings.append("Block at 0x%X is not a store header (type 0x%X)."
                            % (header_offset, record_type))
        return None
    info = {
        "version": version,
        "record_type": record_type,
        "store_information_size": struct.unpack_from("<Q", block, 48)[0],
    }
    # Store information sits straight after the block header.
    pos = BLOCK_HEADER_SIZE
    copy_id = _guid(block[pos + 16:pos + 32])
    set_id = _guid(block[pos + 32:pos + 48])
    context, provider, flags = struct.unpack_from("<III", block, pos + 48)
    info.update({
        "copy_set_id": set_id,
        "context": context,
        "provider": provider,
        "attribute_flags": flags,
    })
    pos += STORE_HEADER_SIZE
    info["originating_machine"] = _string16(block, pos)
    if info["originating_machine"] is not None:
        pos += 2 + 2 * struct.unpack_from("<H", block, pos)[0]
    info["service_machine"] = _string16(block, pos)
    return info

def read_block_list(source, block_list_offset, findings=None):
    """Block-list chain (record type 0x03): 32 B descriptors telling the
    reader where each original volume block now lives in the store."""
    entries = []
    offset = block_list_offset
    seen = set()
    blocks = 0
    while offset and offset not in seen and blocks < 64:
        seen.add(offset)
        blocks += 1
        try:
            block = source.read_at(offset, CATALOG_BLOCK_SIZE)
        except Exception as exc:
            findings.append("Block list at 0x%X could not be read (%s)."
                            % (offset, exc))
            break
        if len(block) < BLOCK_HEADER_SIZE:
            findings.append("Block list at 0x%X is truncated." % offset)
            break
        if _guid(block[0:16]) != VSS_GUID:
            findings.append("Block list at 0x%X lacks the store GUID." % offset)
            break
        record_type = struct.unpack_from("<I", block, 20)[0]
        if record_type != BLOCK_LIST:
            findings.append("Block at 0x%X is not a block list (type 0x%X)."
                            % (offset, record_type))
            break
        nxt = struct.unpack_from("<Q", block, 40)[0]
        pos = BLOCK_HEADER_SIZE
        while pos + 32 <= len(block):
            original, relative, data_off, flags, alloc = struct.unpack_from(
                "<QQQII", block, pos)
            if not original and not relative and not data_off:
                break
            entries.append({
                "original_offset": original, "relative_offset": relative,
                "store_data_offset": data_off, "flags": flags,
                "allocation_bitmap": alloc,
            })
            pos += 32
        offset = nxt
    return entries

def read_block_ranges(source, block_range_offset, findings=None):
    """Block-range chain (record type 0x05): 24 B offset/relative/size
    triples summarising what the store holds. Optional — absent on some
    stores, so a missing chain is not a finding."""
    entries = []
    offset = block_range_offset
    seen = set()
    blocks = 0
    while offset and offset not in seen and blocks < 64:
        seen.add(offset)
        blocks += 1
        try:
            block = source.read_at(offset, CATALOG_BLOCK_SIZE)
        except Exception:
            break
        if len(block) < BLOCK_HEADER_SIZE:
            break
        if _guid(block[0:16]) != VSS_GUID:
            break
        record_type = struct.unpack_from("<I", block, 20)[0]
        if record_type != BLOCK_RANGES:
            break
        nxt = struct.unpack_from("<Q", block, 40)[0]
        pos = BLOCK_HEADER_SIZE
        while pos + 24 <= len(block):
            off, rel, size = struct.unpack_from("<QQQ", block, pos)
            if not off and not rel and not size:
                break
            entries.append({"offset": off, "relative_offset": rel,
                            "size": size})
            pos += 24
        offset = nxt
    return entries

def read_store_bitmap(source, bitmap_offset, findings=None):
    """Store bitmap chain (record type 0x06): 32-bit LE words from byte 128,
    LSB-first, one bit per 0x4000 block. Parsed for reporting only — the
    bit polarity is disputed between sources, so no claim is made."""
    words = []
    offset = bitmap_offset
    seen = set()
    blocks = 0
    while offset and offset not in seen and blocks < 64:
        seen.add(offset)
        blocks += 1
        try:
            block = source.read_at(offset, CATALOG_BLOCK_SIZE)
        except Exception:
            break
        if len(block) < BLOCK_HEADER_SIZE:
            break
        if _guid(block[0:16]) != VSS_GUID:
            break
        record_type = struct.unpack_from("<I", block, 20)[0]
        if record_type != BLOCK_BITMAP:
            break
        nxt = struct.unpack_from("<Q", block, 40)[0]
        pos = BLOCK_HEADER_SIZE
        while pos + 4 <= len(block):
            (w,) = struct.unpack_from("<I", block, pos)
            words.append(w)
            pos += 4
        offset = nxt
    return words



class VssOverlay:
    """Reads a differential-area store over a volume region: redirected
    blocks come from the store, everything else falls through to the base.
    Offsets are volume-relative, matching the underlying region."""

    def __init__(self, base, snapshot, findings=None):
        self.base = base
        self.snapshot = snapshot
        self.findings = findings if findings is not None else []
        self.size = getattr(base, "size", 0) or 0
        self.bytes_per_sector = getattr(base, "bytes_per_sector", 512)
        self.offsets = {}
        self._forwarded = set()
        entries = read_block_list(base, snapshot["block_list_offset"],
                                  self.findings)
        for e in entries:
            flags = e["flags"]
            if flags & DESC_FORWARDER:
                # v1 never resolves forwarder chains into newer stores:
                # falling through yields the old (pre-redirect) bytes, which
                # is safe; the alternative would be guessing.
                key = e["original_offset"] // STORE_BLOCK_SIZE
                if key not in self._forwarded:
                    self._forwarded.add(key)
                    self.findings.append(
                        "Block at 0x%X is a forwarder into a newer store; "
                        "showing the previous copy." % e["original_offset"])
                continue
            self.offsets[e["original_offset"]] = e
        self._pos = 0

    def _blocks(self, offset, length):
        """Yield (chunk_offset, length, store_offset_or_None) covering the
        request, where None means "serve from the base"."""
        end = offset + length
        pos = offset
        while pos < end:
            block = pos - (pos % STORE_BLOCK_SIZE)
            e = self.offsets.get(block)
            if not e or e["flags"] & DESC_NOT_USED:
                take = min(end - pos, STORE_BLOCK_SIZE - (pos - block))
                yield pos, take, None
                pos += take
                continue
            if e["flags"] & DESC_OVERLAY:
                # 32 bitmap chunks of 512 B each; runs of set bits map to
                # consecutive 512 B chunks starting at the store data offset.
                alloc = e["allocation_bitmap"]
                chunk = (pos - block) // STORE_CHUNK
                while pos < end and chunk < 32:
                    take = min(end - pos, STORE_CHUNK)
                    if alloc & (1 << chunk):
                        # The chunk's copy lives at store_data_offset +
                        # chunk*512; advance by the intra-chunk delta so
                        # the read lands on ``pos`` exactly.
                        chunk_start = block + chunk * STORE_CHUNK
                        store = (e["store_data_offset"]
                                 + chunk * STORE_CHUNK
                                 + (pos - chunk_start))
                        yield pos, take, store
                    else:
                        yield pos, take, None
                    pos += take
                    chunk += 1
                continue
            # Plain entry: the whole block lives at the store offset plus the
            # intra-block delta.
            delta = pos - block
            take = min(end - pos, STORE_BLOCK_SIZE - delta)
            yield pos, take, e["store_data_offset"] + delta
            pos += take

    def read_at(self, offset, length):
        if offset < 0 or length <= 0 or offset >= self.size:
            return b""
        length = min(length, self.size - offset)
        parts = []
        for pos, take, store in self._blocks(offset, length):
            if store is None:
                parts.append(self.base.read_at(pos, take))
            else:
                got = self.base.read_at(store, take)
                if len(got) < take:
                    self.findings.append(
                        "Store data at 0x%X is short by %d bytes; falling "
                        "back to the base volume." % (store, take - len(got)))
                    got += self.base.read_at(pos, take)[len(got):]
                parts.append(got)
        return b"".join(parts)

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

    def tell(self):
        return self._pos

    def info(self):
        out = {"type": "VSS snapshot",
               "snapshot_id": self.snapshot.get("id"),
               "created_at": self.snapshot.get("created_at")}
        base_info = getattr(self.base, "info", None)
        if callable(base_info):
            try:
                out.update(base_info() or {})
            except Exception:
                pass
        out["type"] = "VSS snapshot"
        return out

