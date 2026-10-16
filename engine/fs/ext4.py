from .streams import UnsupportedStream
from .ranges import read_runs
import base64
import datetime
import struct

INCOMPAT_FILETYPE = 0x0002
INCOMPAT_EXTENTS = 0x0040
INCOMPAT_64BIT = 0x0080
INCOMPAT_INLINE_DATA = 0x8000

FL_EXTENTS = 0x00080000
FL_INLINE_DATA = 0x10000000
XATTR_MAGIC = 0xEA020000
XATTR_SYSTEM = 7

# e_name_index -> the attribute's namespace prefix, per the ext4 kernel
# source (fs/ext4/xattr.h). Anything not listed here (e.g. 2/3, the POSIX
# ACL indices, whose complete name is a fixed string rather than
# prefix+suffix) is shown as "index:name" instead of guessed at.
XATTR_PREFIX = {0: "", 1: "user.", 4: "trusted.", 6: "security.",
               XATTR_SYSTEM: "system."}

XATTR_VALUE_CAP = 4096

S_IFMT = 0xF000
S_IFDIR = 0x4000
S_IFREG = 0x8000
S_IFLNK = 0xA000

FILE_TYPES = {1: "file", 2: "dir", 3: "chardev", 4: "blockdev",
              5: "fifo", 6: "socket", 7: "symlink"}

def _time(sec, extra=0):
    if not sec:
        return None
    sec |= (extra & 0x3) << 32
    try:
        return datetime.datetime.utcfromtimestamp(sec).isoformat() + "Z"
    except (OSError, ValueError, OverflowError):
        return None

def _mode_string(mode):
    kind = {S_IFDIR: "d", S_IFREG: "-", S_IFLNK: "l"}.get(mode & S_IFMT, "?")
    bits = ""
    for shift in (6, 3, 0):
        p = (mode >> shift) & 7
        bits += ("r" if p & 4 else "-") + ("w" if p & 2 else "-") + \
                ("x" if p & 1 else "-")
    return kind + bits

def _xattr_entries(buf, entries_start, value_base, limit, max_value, out):
    """Appends each ext4_xattr_entry found in buf[entries_start:limit] to
    out, stopping at an all-zero header (the end of the list) or when a
    header would run past limit. value_base is where e_value_offs counts
    from: right after the in-inode magic for an in-inode list, or the
    start of the block for an external xattr block."""
    i = entries_start
    while i + 16 <= limit:
        name_len, index, value_offs, value_inum, value_size = \
            struct.unpack("<BBHII", buf[i:i + 12])
        if not name_len and not index and not value_offs:
            break
        name = buf[i + 16:i + 16 + name_len].decode("utf-8", "replace")
        if not value_inum and not (index == XATTR_SYSTEM and name == "data"):
            v = value_base + value_offs
            cap = min(value_size, max_value)
            value = bytes(buf[v:min(len(buf), v + cap)])
            prefix = XATTR_PREFIX.get(index)
            label = (prefix + name) if prefix is not None \
                else "%d:%s" % (index, name)
            out.append({"name": label, "size": value_size, "value": value,
                        "truncated": value_size > max_value})
        i += (16 + name_len + 3) & ~3
    return out

class Inode:
    def __init__(self, num, raw, fs):
        self.num = num
        self.raw = raw
        self.fs = fs
        (self.mode, self.uid, size_lo, atime, ctime, mtime, self.dtime,
         self.gid, self.links) = struct.unpack("<HHIIIIIHH", raw[0:28])
        self.blocks_lo = struct.unpack("<I", raw[28:32])[0]
        self.flags = struct.unpack("<I", raw[32:36])[0]
        size_hi = struct.unpack("<I", raw[108:112])[0]
        self.size = size_lo | (size_hi << 32) if (self.mode & S_IFMT) == S_IFREG \
            else size_lo
        self.block_area = raw[40:100]
        extra = raw[128:132] if len(raw) >= 132 else b"\0\0\0\0"
        self.extra_isize = struct.unpack("<H", extra[0:2])[0] if len(raw) > 129 else 0
        self.atime = _time(atime)
        self.ctime = _time(ctime)
        self.mtime = _time(mtime)
        self.crtime = None
        if len(raw) >= 148:
            crtime = struct.unpack("<I", raw[144:148])[0]
            self.crtime = _time(crtime)
        self.deleted = bool(self.dtime) or self.links == 0
        self.dtime_iso = _time(self.dtime)

    @property
    def is_dir(self):
        return (self.mode & S_IFMT) == S_IFDIR

    @property
    def is_link(self):
        return (self.mode & S_IFMT) == S_IFLNK

    @property
    def uses_extents(self):
        return bool(self.flags & FL_EXTENTS)

    @property
    def inline(self):
        return bool(self.flags & FL_INLINE_DATA)

    @property
    def file_acl(self):
        """The block holding this inode's external xattrs, or 0 when
        every attribute (if any) fits in the inode itself."""
        raw = self.raw
        lo = struct.unpack("<I", raw[104:108])[0] if len(raw) >= 108 else 0
        hi = struct.unpack("<H", raw[118:120])[0] if len(raw) >= 120 else 0
        return lo | (hi << 32)

    def xattrs(self, max_value=XATTR_VALUE_CAP):
        """Every extended attribute on this file, in-inode and (via
        file_acl) in its external xattr block, each value read up to
        max_value bytes. system.data -- inline file data kept in this
        same entry format, read whole by inline_xattr() for the file's
        actual content -- is not an attribute an examiner is asking for
        here, so it is left out."""
        out = []
        raw = self.raw
        start = 128 + self.extra_isize
        if len(raw) >= start + 4 and \
                struct.unpack("<I", raw[start:start + 4])[0] == XATTR_MAGIC:
            first = start + 4
            _xattr_entries(raw, first, first, len(raw), max_value, out)
        block = self.file_acl
        if block:
            blk = self.fs.source.read_at(block * self.fs.block_size,
                                         self.fs.block_size)
            if len(blk) >= 32 and \
                    struct.unpack("<I", blk[0:4])[0] == XATTR_MAGIC:
                _xattr_entries(blk, 32, 0, len(blk), max_value, out)
        return out

    def inline_xattr(self):
        """The in-inode "system.data" extended attribute, where inline data
        past the 60 bytes of i_block is kept; b"" when there is none."""
        start = 128 + self.extra_isize
        raw = self.raw
        if len(raw) < start + 4 or \
                struct.unpack("<I", raw[start:start + 4])[0] != XATTR_MAGIC:
            return b""
        first = start + 4
        i = first
        while i + 16 <= len(raw):
            name_len, index, value_offs, value_inum, value_size = \
                struct.unpack("<BBHII", raw[i:i + 12])
            if not name_len and not index and not value_offs:
                break
            name = raw[i + 16:i + 16 + name_len]
            if index == XATTR_SYSTEM and name == b"data" and not value_inum:
                v = first + value_offs
                return bytes(raw[v:min(len(raw), v + value_size)])
            i += (16 + name_len + 3) & ~3
        return b""

class Ext4FS:
    name = "ext4"
    root_node = 2

    def __init__(self, source):
        self.source = source
        sb = source.read_at(1024, 1024)
        if len(sb) < 1024 or sb[56:58] != b"\x53\xEF":
            raise ValueError("No ext superblock magic at offset 1024.")
        self.inodes_count = struct.unpack("<I", sb[0:4])[0]
        blocks_lo = struct.unpack("<I", sb[4:8])[0]
        self.first_data_block = struct.unpack("<I", sb[20:24])[0]
        log_bs = struct.unpack("<I", sb[24:28])[0]
        self.block_size = 1024 << log_bs
        self.blocks_per_group = struct.unpack("<I", sb[32:36])[0]
        self.inodes_per_group = struct.unpack("<I", sb[40:44])[0]
        self.mtime = _time(struct.unpack("<I", sb[44:48])[0])
        self.wtime = _time(struct.unpack("<I", sb[48:52])[0])
        self.state = struct.unpack("<H", sb[58:60])[0]
        self.rev = struct.unpack("<I", sb[76:80])[0]
        self.first_ino = struct.unpack("<I", sb[84:88])[0] if self.rev else 11
        self.inode_size = struct.unpack("<H", sb[88:90])[0] if self.rev else 128
        self.feature_compat = struct.unpack("<I", sb[92:96])[0]
        self.feature_incompat = struct.unpack("<I", sb[96:100])[0]
        self.feature_ro = struct.unpack("<I", sb[100:104])[0]
        self.uuid = sb[104:120].hex()
        self.label = sb[120:136].split(b"\x00")[0].decode("utf-8", "replace")
        self.last_mounted = sb[136:200].split(b"\x00")[0].decode("utf-8", "replace")
        blocks_hi = struct.unpack("<I", sb[336:340])[0] \
            if self.feature_incompat & INCOMPAT_64BIT else 0
        self.blocks_count = blocks_lo | (blocks_hi << 32)
        desc_size = struct.unpack("<H", sb[254:256])[0]
        self.desc_size = desc_size if (self.feature_incompat & INCOMPAT_64BIT
                                       and desc_size) else 32

        if not self.blocks_per_group or not self.inodes_per_group:
            raise ValueError("ext superblock has zero group sizing.")
        self.group_count = (self.blocks_count - self.first_data_block
                            + self.blocks_per_group - 1) // self.blocks_per_group
        if self.feature_incompat & INCOMPAT_EXTENTS:
            self.name = "ext4"
        elif self.feature_compat & 0x0004:
            self.name = "ext3"
        else:
            self.name = "ext2"

        self.journal_inum = struct.unpack("<I", sb[224:228])[0] or 8
        self.data_offset = 0
        self._gd = None
        self._inode_cache = {}
        self._journal = None

    @property
    def journal(self):
        if self._journal is None:
            from . import jbd2
            try:
                self._journal = jbd2.Journal(self, self.journal_inum)
            except Exception as exc:
                class _Absent:
                    valid = False
                    findings = ["Journal could not be read: %s" % exc]

                    def info(self):
                        return {"present": False, "findings": self.findings}

                    def recover(self, num):
                        return None

                    def read_recovered(self, num, max_bytes=None):
                        return b""

                    def inode_versions(self, num):
                        return []
                self._journal = _Absent()
        return self._journal

    def _group_descriptors(self):
        if self._gd is None:
            gd_block = self.first_data_block + 1
            raw = self.source.read_at(gd_block * self.block_size,
                                      self.group_count * self.desc_size)
            out = []
            for i in range(self.group_count):
                d = raw[i * self.desc_size:(i + 1) * self.desc_size]
                if len(d) < 12:
                    break
                bb, ib, it = struct.unpack("<III", d[0:12])
                if self.desc_size >= 64:
                    bb |= struct.unpack("<I", d[32:36])[0] << 32
                    ib |= struct.unpack("<I", d[36:40])[0] << 32
                    it |= struct.unpack("<I", d[40:44])[0] << 32
                out.append({"block_bitmap": bb, "inode_bitmap": ib,
                            "inode_table": it})
            self._gd = out
        return self._gd

    def inode(self, num):
        if num in self._inode_cache:
            return self._inode_cache[num]
        if num < 1 or num > self.inodes_count:
            return None
        idx = num - 1
        group = idx // self.inodes_per_group
        within = idx % self.inodes_per_group
        gds = self._group_descriptors()
        if group >= len(gds):
            return None
        off = gds[group]["inode_table"] * self.block_size + within * self.inode_size
        raw = self.source.read_at(off, self.inode_size)
        if len(raw) < 128:
            return None
        ino = Inode(num, raw, self)
        ino.table_offset = off
        self._inode_cache[num] = ino
        return ino

    def _extent_runs(self, block_area, depth_guard=0, want_depth=None,
                     seen=None):
        if len(block_area) < 12 or block_area[0:2] != b"\x0A\xF3":
            return []
        entries = struct.unpack("<H", block_area[2:4])[0]
        depth = struct.unpack("<H", block_area[6:8])[0]
        # Each level down is exactly one shallower, and no index block is
        # read twice: a damaged tree that points back at itself, or at one
        # node many times, would otherwise cost fan-out ** depth reads.
        if want_depth is not None and depth != want_depth:
            return []
        if seen is None:
            seen = set()
        out = []
        if depth == 0:
            for i in range(entries):
                e = block_area[12 + i * 12: 24 + i * 12]
                if len(e) < 12:
                    break
                logical = struct.unpack("<I", e[0:4])[0]
                length = struct.unpack("<H", e[4:6])[0]
                hi = struct.unpack("<H", e[6:8])[0]
                lo = struct.unpack("<I", e[8:12])[0]
                initialised = length <= 32768
                out.append((logical, lo | (hi << 32),
                            length if initialised else length - 32768,
                            initialised))
        elif depth_guard < 8:
            for i in range(entries):
                e = block_area[12 + i * 12: 24 + i * 12]
                if len(e) < 12:
                    break
                leaf = struct.unpack("<I", e[4:8])[0] | \
                    (struct.unpack("<H", e[8:10])[0] << 32)
                if leaf in seen:
                    continue
                seen.add(leaf)
                node = self.source.read_at(leaf * self.block_size, self.block_size)
                out.extend(self._extent_runs(node, depth_guard + 1,
                                             depth - 1, seen))
        return out

    def _indirect_blocks(self, block_area, needed):
        ptrs = struct.unpack("<15I", block_area[:60])
        blocks = []
        per = self.block_size // 4

        def read_ptr_block(b):
            if not b:
                return []
            d = self.source.read_at(b * self.block_size, self.block_size)
            return list(struct.unpack("<%dI" % (len(d) // 4), d[:len(d) // 4 * 4]))

        for b in ptrs[:12]:
            if len(blocks) >= needed:
                return blocks
            blocks.append(b)
        for b in read_ptr_block(ptrs[12]):
            if len(blocks) >= needed:
                return blocks
            blocks.append(b)
        for b1 in read_ptr_block(ptrs[13]):
            for b in read_ptr_block(b1):
                if len(blocks) >= needed:
                    return blocks
                blocks.append(b)
        for b2 in read_ptr_block(ptrs[14]):
            for b1 in read_ptr_block(b2):
                for b in read_ptr_block(b1):
                    if len(blocks) >= needed:
                        return blocks
                    blocks.append(b)
        return blocks

    def _hole(self, logical, count):
        return {"offset": 0, "length": count * self.block_size,
                "block": 0, "blocks": count, "logical": logical,
                "sparse": True, "initialised": True}

    def runs(self, ino):
        if ino.inline:
            return []
        out = []
        if ino.uses_extents:
            if ino.block_area[0:2] != b"\x0A\xF3":
                return []
            ext = self._extent_runs(ino.block_area)
            ext.sort()
            # Extents only cover what was written, and every reader walks
            # the runs end to end, so a gap in logical block numbers has to
            # become an explicit hole or later data shifts down into it.
            # Directories are never sparse in ext4, and listing reads them
            # whole, so a hole there is corruption and is not filled.
            holes = not ino.is_dir
            expected = 0
            for logical, phys, count, initialised in ext:
                if holes and logical > expected:
                    out.append(self._hole(expected, logical - expected))
                out.append({
                    "offset": phys * self.block_size,
                    "length": count * self.block_size,
                    "block": phys, "blocks": count,
                    "logical": logical, "sparse": False,
                    "initialised": initialised,
                })
                expected = max(expected, logical + count)
            size_blocks = (ino.size + self.block_size - 1) // self.block_size
            if holes and size_blocks > expected:
                out.append(self._hole(expected, size_blocks - expected))
        else:
            needed = (ino.size + self.block_size - 1) // self.block_size
            blocks = self._indirect_blocks(ino.block_area, needed)
            run_start = None
            run_len = 0
            for b in blocks + [None]:
                if run_start is not None and b == run_start + run_len:
                    run_len += 1
                    continue
                if run_start is not None:
                    out.append({"offset": run_start * self.block_size,
                                "length": run_len * self.block_size,
                                "block": run_start, "blocks": run_len,
                                "sparse": run_start == 0, "initialised": True})
                run_start, run_len = b, 1
        remaining = ino.size
        for r in out:
            r["used"] = max(0, min(r["length"], remaining))
            remaining -= r["length"]
        return out

    def read_inode_data(self, ino, max_bytes=None):
        limit = ino.size if max_bytes is None else min(ino.size, max_bytes)
        if ino.inline:
            body = ino.block_area + ino.inline_xattr()
            return bytes(body[:limit])
        if ino.is_link and ino.size < 60:
            return bytes(ino.block_area[:ino.size])
        out = bytearray()
        for r in self.runs(ino):
            if len(out) >= limit:
                break
            take = min(r["length"], limit - len(out))
            if r["sparse"] or not r.get("initialised", True):
                out += b"\x00" * take
            else:
                out += self.source.read_at(r["offset"], take)
        return bytes(out[:limit])

    def _dir_entries(self, ino):
        if ino.inline:
            # i_block opens with the parent's inode number (the ".." entry)
            # and the xattr value continues the dirents on its own.
            return (self._parse_dirents(ino.block_area[4:])
                    + self._parse_dirents(ino.inline_xattr()))
        return self._parse_dirents(self.read_inode_data(ino))

    def _parse_dirents(self, data):
        out = []
        i = 0
        filetype = bool(self.feature_incompat & INCOMPAT_FILETYPE)
        while i + 8 <= len(data):
            inum, rec_len = struct.unpack("<IH", data[i:i + 6])
            if rec_len < 8 or i + rec_len > len(data):
                break
            if filetype:
                name_len = data[i + 6]
                ftype = data[i + 7]
            else:
                name_len = struct.unpack("<H", data[i + 6:i + 8])[0]
                ftype = 0
            name = data[i + 8:i + 8 + name_len].decode("utf-8", "replace")
            if inum and name not in (".", ".."):
                out.append((inum, name, ftype))
            i += rec_len
        return out

    def listdir(self, inode_num=2, path="/"):
        ino = self.inode(inode_num or 2)
        if not ino or not ino.is_dir:
            return []
        out = []
        for inum, name, ftype in self._dir_entries(ino):
            child = self.inode(inum)
            if not child:
                continue
            is_dir = child.is_dir if child else ftype == 2
            out.append({
                "name": name, "path": path.rstrip("/") + "/" + name,
                "inode": inum, "is_dir": is_dir,
                "deleted": child.deleted,
                "size": 0 if is_dir else child.size,
                "mode": _mode_string(child.mode),
                "uid": child.uid, "gid": child.gid, "links": child.links,
                "created": child.crtime, "modified": child.mtime,
                "accessed": child.atime, "changed": child.ctime,
                "deleted_at": child.dtime_iso,
                "inline": child.inline,
                "type": FILE_TYPES.get(ftype, ""),
                "system": inum < self.first_ino,
                "id": "ext:%d" % inum,
            })
        out.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
        return out

    def read_file(self, entry, max_bytes=None, stream=""):
        if stream:
            raise UnsupportedStream("ext4", stream)
        ino = self.inode(entry["inode"])
        if not ino:
            return b""
        data = self.read_inode_data(ino, max_bytes)
        if not data and entry.get("deleted"):
            return self.journal.read_recovered(ino.num, max_bytes)
        return data

    def read_range(self, entry, off, length, stream=""):
        if stream:
            raise UnsupportedStream("ext4", stream)
        ino = self.inode(entry["inode"])
        if not ino:
            return b""
        if ino.inline or (ino.is_link and ino.size < 60):
            data = self.read_inode_data(ino)
            return data[off:off + length]
        runs = self.runs(ino)
        if not runs:
            data = self.read_file(entry, off + length)
            return data[off:off + length]
        return read_runs(self.source, runs, off,
                         min(length, max(0, ino.size - off)))

    def stat(self, entry):
        ino = self.inode(entry["inode"])
        if not ino:
            return {}
        info = {
            "filesystem": self.name, "cluster_size": self.block_size,
            "inode": ino.num, "inode_offset": ino.table_offset,
            "mode": _mode_string(ino.mode), "links": ino.links,
            "uid": ino.uid, "gid": ino.gid,
            "mapping": "extent tree" if ino.uses_extents
                       else ("inline" if ino.inline else "indirect blocks"),
            "flags": "0x%08X" % ino.flags,
        }
        xattrs = ino.xattrs()
        if xattrs:
            info["xattrs"] = [
                {"name": a["name"], "size": a["size"],
                 "truncated": a["truncated"],
                 "value": base64.b64encode(a["value"]).decode("ascii")}
                for a in xattrs]
        if ino.inline:
            info["note"] = ("Content is stored inside the inode itself. No "
                            "blocks are allocated, so there is nothing to "
                            "carve and nothing in slack.")
            return info
        runs = self.runs(ino)
        if runs:
            info["runs"] = runs
            tail = ino.size % self.block_size
            last = runs[-1]
            if tail and not last["sparse"]:
                info["slack"] = {
                    "offset": last["offset"] + last["length"]
                    - (self.block_size - tail),
                    "length": self.block_size - tail}
            if any(not r.get("initialised", True) for r in runs):
                info["note"] = ("Contains uninitialised extents — space was "
                                "preallocated but never written. Those ranges "
                                "may still hold earlier content on disk.")
        if entry.get("deleted"):
            if runs:
                info["recovery"] = (
                    "Inode is unlinked but block pointers survive. Verify the "
                    "blocks have not been reallocated before relying on "
                    "content.")
            else:
                info["recovery"] = (
                    "Inode is unlinked (dtime %s) and its block map has been "
                    "cleared, which is what ext4 does on delete."
                    % (ino.dtime_iso or "set"))
                rec = self.journal.recover(ino.num)
                if rec:
                    info["journal_recovery"] = rec
                    info["runs"] = rec["runs"]
                    info["recovered_size"] = rec["size"]
                    info["recovery"] += (
                        " An earlier image of this inode survives in the "
                        "journal, so the block map below was recovered rather "
                        "than read from the live inode table. %s" % rec["note"])
                else:
                    info["recovery"] += (
                        " No earlier image of it survives in the journal "
                        "either, so recovery here is a carving problem.")
        return info

    def info(self):
        feats = []
        for bit, nm in ((INCOMPAT_EXTENTS, "extents"),
                        (INCOMPAT_64BIT, "64bit"),
                        (INCOMPAT_INLINE_DATA, "inline_data"),
                        (INCOMPAT_FILETYPE, "filetype")):
            if self.feature_incompat & bit:
                feats.append(nm)
        if self.feature_compat & 0x0004:
            feats.append("has_journal")
        return {
            "type": self.name, "label": self.label, "uuid": self.uuid,
            "block_size": self.block_size, "cluster_size": self.block_size,
            "blocks": self.blocks_count, "inodes": self.inodes_count,
            "blocks_per_group": self.blocks_per_group,
            "inodes_per_group": self.inodes_per_group,
            "inode_size": self.inode_size,
            "groups": self.group_count,
            "first_inode": self.first_ino,
            "features": feats,
            "last_mounted": self.last_mounted,
            "last_write": self.wtime,
            "clean": self.state == 1,
            "journal_inode": self.journal_inum,
        }

    def journal_info(self):
        return self.journal.info()

    def allocated_extents(self):
        out = []
        seen = set()
        stack = [2]
        while stack:
            num = stack.pop()
            if num in seen:
                continue
            seen.add(num)
            ino = self.inode(num)
            if not ino:
                continue
            if ino.is_dir:
                for inum, name, ftype in self._dir_entries(ino):
                    child = self.inode(inum)
                    if child and child.is_dir:
                        stack.append(inum)
                    elif child and not child.deleted and not child.inline:
                        for r in self.runs(child):
                            if not r["sparse"]:
                                out.append((r["offset"],
                                            r["offset"] + r["length"]))
        return out
