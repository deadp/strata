import struct

JBD2_MAGIC = 0xC03B3998

BLOCKTYPE_DESCRIPTOR = 1
BLOCKTYPE_COMMIT = 2
BLOCKTYPE_SUPERBLOCK_V1 = 3
BLOCKTYPE_SUPERBLOCK_V2 = 4
BLOCKTYPE_REVOKE = 5

FLAG_ESCAPE = 0x01
FLAG_SAME_UUID = 0x02
FLAG_LAST_TAG = 0x08
INCOMPAT_64BIT = 0x00000002
INCOMPAT_CSUM_V2 = 0x00000008
INCOMPAT_CSUM_V3 = 0x00000010

class Journal:
    def __init__(self, fs, inode_num=8):
        self.fs = fs
        self.findings = []
        self.valid = False
        self.transactions = []
        self.block_index = {}
        self.revoked = {}
        self.inode_num = inode_num
        self._load()

    def _journal_runs(self):
        ino = self.fs.inode(self.inode_num)
        if not ino:
            return None, []
        return ino, self.fs.runs(ino)

    def _read_journal_block(self, n):
        want = n * self.block_size
        pos = 0
        for r in self._runs:
            if r["sparse"]:
                pos += r["length"]
                continue
            if pos + r["length"] > want:
                return self.fs.source.read_at(r["offset"] + (want - pos),
                                              self.block_size)
            pos += r["length"]
        return b""

    def _load(self):
        # Set before any early return: recover() and inode_versions() stay
        # reachable on an invalid journal (ext4.stat calls recover() for
        # deleted inodes) and both read block_size.
        self._runs = []
        self.block_size = self.fs.block_size
        ino, runs = self._journal_runs()
        if not ino or not runs:
            self.findings.append("No journal inode, or it has no blocks. "
                                 "This filesystem may be ext2, or the journal "
                                 "may be on an external device.")
            return
        self._runs = runs

        sb = self._read_journal_block(0)
        if len(sb) < 68 or struct.unpack(">I", sb[0:4])[0] != JBD2_MAGIC:
            self.findings.append("Journal superblock magic not found; the "
                                 "journal inode does not look like jbd2.")
            return
        blocktype = struct.unpack(">I", sb[4:8])[0]
        if blocktype not in (BLOCKTYPE_SUPERBLOCK_V1, BLOCKTYPE_SUPERBLOCK_V2):
            self.findings.append("Journal block 0 is type %d, not a superblock."
                                 % blocktype)
            return
        self.journal_block_size = struct.unpack(">I", sb[12:16])[0]
        self.maxlen = struct.unpack(">I", sb[16:20])[0]
        self.first = struct.unpack(">I", sb[20:24])[0]
        self.sequence = struct.unpack(">I", sb[24:28])[0]
        self.start = struct.unpack(">I", sb[28:32])[0]
        self.feature_incompat = struct.unpack(">I", sb[40:44])[0]
        self.uuid = sb[48:64].hex()
        self.nr_users = struct.unpack(">I", sb[64:68])[0]
        if self.journal_block_size != self.block_size:
            self.findings.append(
                "Journal block size (%d) differs from the filesystem block "
                "size (%d)." % (self.journal_block_size, self.block_size))
        self.valid = True
        self._walk()

    def _tag_size(self):
        if self.feature_incompat & INCOMPAT_CSUM_V3:
            return 16, True
        size = 8
        if self.feature_incompat & INCOMPAT_64BIT:
            size += 4
        return size, False

    def _parse_tags(self, block):
        tag_size, v3 = self._tag_size()
        tags = []
        i = 12
        limit = len(block) - (
            4 if self.feature_incompat & (INCOMPAT_CSUM_V2 | INCOMPAT_CSUM_V3)
            else 0)
        while i + tag_size <= limit:
            if v3:
                blocknr = struct.unpack(">I", block[i:i + 4])[0]
                flags = struct.unpack(">I", block[i + 4:i + 8])[0]
                hi = struct.unpack(">I", block[i + 8:i + 12])[0]
                blocknr |= hi << 32
            else:
                blocknr = struct.unpack(">I", block[i:i + 4])[0]
                flags = struct.unpack(">H", block[i + 6:i + 8])[0]
                if self.feature_incompat & INCOMPAT_64BIT:
                    blocknr |= struct.unpack(">I", block[i + 8:i + 12])[0] << 32
            i += tag_size
            if not (flags & FLAG_SAME_UUID):
                i += 16
            tags.append({"block": blocknr, "flags": flags,
                         "escaped": bool(flags & FLAG_ESCAPE)})
            if flags & FLAG_LAST_TAG:
                break
        return tags

    def _walk(self):
        pos = self.first
        guard = 0
        while pos < self.maxlen and guard < self.maxlen * 2:
            guard += 1
            block = self._read_journal_block(pos)
            if len(block) < 12:
                break
            magic, btype, seq = struct.unpack(">III", block[0:12])
            if magic != JBD2_MAGIC:
                pos += 1
                continue
            if btype == BLOCKTYPE_DESCRIPTOR:
                tags = self._parse_tags(block)
                data_at = pos + 1
                entries = []
                for t in tags:
                    entries.append({"fs_block": t["block"],
                                    "journal_block": data_at,
                                    "escaped": t["escaped"],
                                    "sequence": seq})
                    self.block_index.setdefault(t["block"], []).append(
                        (seq, data_at, t["escaped"]))
                    data_at += 1
                self.transactions.append({"sequence": seq, "descriptor": pos,
                                          "blocks": entries,
                                          "committed": False})
                pos = data_at
                continue
            if btype == BLOCKTYPE_COMMIT:
                for t in reversed(self.transactions):
                    if t["sequence"] == seq:
                        t["committed"] = True
                        break
                pos += 1
                continue
            if btype == BLOCKTYPE_REVOKE:
                count = struct.unpack(">I", block[12:16])[0]
                i = 16
                width = 8 if self.feature_incompat & INCOMPAT_64BIT else 4
                while i + width <= min(count, len(block)):
                    b = (struct.unpack(">Q", block[i:i + 8])[0] if width == 8
                         else struct.unpack(">I", block[i:i + 4])[0])
                    prev = self.revoked.get(b, 0)
                    self.revoked[b] = max(prev, seq)
                    i += width
                pos += 1
                continue
            pos += 1

    def _inode_location(self, num):
        idx = num - 1
        group = idx // self.fs.inodes_per_group
        within = idx % self.fs.inodes_per_group
        gds = self.fs._group_descriptors()
        if group >= len(gds):
            return None, None
        byte = within * self.fs.inode_size
        block = gds[group]["inode_table"] + byte // self.block_size
        return block, byte % self.block_size

    def inode_versions(self, num):
        if not self.valid:
            return []
        from .ext4 import Inode
        block, offset = self._inode_location(num)
        if block is None:
            return []
        copies = sorted(self.block_index.get(block, []))
        out = []
        for seq, jblock, escaped in copies:
            raw = self._read_journal_block(jblock)
            if len(raw) < self.block_size:
                continue
            if escaped:
                raw = struct.pack(">I", JBD2_MAGIC) + raw[4:]
            chunk = raw[offset:offset + self.fs.inode_size]
            if len(chunk) < 128:
                continue
            try:
                ino = Inode(num, chunk, self.fs)
            except Exception:
                continue
            committed = any(t["sequence"] == seq and t["committed"]
                            for t in self.transactions)
            out.append({
                "sequence": seq, "journal_block": jblock,
                "committed": committed,
                "inode": ino,
                "size": ino.size, "links": ino.links,
                "deleted": ino.deleted,
                "deleted_at": ino.dtime_iso,
                "modified": ino.mtime, "changed": ino.ctime,
                "created": ino.crtime,
                "mapping": "extent tree" if ino.uses_extents
                           else ("inline" if ino.inline else "indirect"),
                "runs": self.fs.runs(ino),
            })
        return out

    def recover(self, num):
        if not self.valid:
            return None
        versions = self.inode_versions(num)
        usable = [v for v in versions if v["runs"] and not v["deleted"]]
        if not usable:
            return None
        best = usable[-1]
        return {
            "sequence": best["sequence"],
            "committed": best["committed"],
            "size": best["size"],
            "mapping": best["mapping"],
            "runs": best["runs"],
            "modified": best["modified"],
            "versions_found": len(versions),
            "note": ("Recovered from journal transaction %d. This is where the "
                     "data was when that transaction was written; the blocks "
                     "may have been reallocated since, so verify the content "
                     "before relying on it." % best["sequence"]),
        }

    def read_recovered(self, num, max_bytes=None):
        if not self.valid:
            return b""
        rec = self.recover(num)
        if not rec:
            return b""
        limit = rec["size"] if max_bytes is None else min(rec["size"], max_bytes)
        out = bytearray()
        for r in rec["runs"]:
            if len(out) >= limit:
                break
            take = min(r["length"], limit - len(out))
            if r["sparse"]:
                out += b"\x00" * take
            else:
                out += self.fs.source.read_at(r["offset"], take)
        return bytes(out[:limit])

    def info(self):
        if not self.valid:
            return {"present": False, "findings": self.findings}
        committed = sum(1 for t in self.transactions if t["committed"])
        return {
            "present": True,
            "inode": self.inode_num,
            "blocks": self.maxlen,
            "first_block": self.first,
            "sequence": self.sequence,
            "uuid": self.uuid,
            "filesystems_sharing": self.nr_users,
            "transactions": len(self.transactions),
            "committed": committed,
            "blocks_journalled": len(self.block_index),
            "revoked_blocks": len(self.revoked),
            "csum_v3": bool(self.feature_incompat & INCOMPAT_CSUM_V3),
            "64bit": bool(self.feature_incompat & INCOMPAT_64BIT),
            "findings": self.findings,
        }
