import datetime
import struct
import uuid

KNOWN_FOLDERS = {
    "20d04fe0-3aea-1069-a2d8-08002b30309d": "This PC",
    "5e6c858f-0e22-4760-9afe-ea3317b67173": "User profile",
    "59031a47-3f72-44a7-89c5-5595fe6b30ee": "Users",
    "b4bfcc3a-db2c-424c-b029-7fe99a87c641": "Desktop",
    "374de290-123f-4565-9164-39c4925e467b": "Downloads",
    "f42ee2d3-909f-4907-8871-4c22fc0bf756": "Documents",
    "24ad3ad4-a569-4530-98e1-ab02f9417aa8": "Pictures",
    "3dfdf296-dbec-4fb4-81d1-6a3438bcf4de": "Music",
    "f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a": "Videos",
    "088e3905-0323-4b02-9826-5d99428e115f": "Downloads (known folder)",
    "0ac0837c-bbf8-452a-850d-79d08e667ca7": "Computer",
    "871c5380-42a0-1069-a2ea-08002b30309d": "Internet Explorer",
    "645ff040-5081-101b-9f08-00aa002f954e": "Recycle Bin",
    "031e4825-7b94-4dc3-b131-e946b44c8dd5": "Libraries",
    "a0953c92-50dc-43bf-be83-3742fed03c9c": "Videos (library)",
    "d3162b92-9365-467a-956b-92703aca08af": "Documents (library)",
    "1cf1260c-4dd0-4ebb-811f-33c572699fde": "Music (library)",
    "3add1653-eb32-4cb0-bbd7-dfa0abb5acca": "Pictures (library)",
    "7b0db17d-9cd2-4a93-9733-46cc89022e7c": "Documents (library, legacy)",
    "de974d24-d9c6-4d3e-bf91-f4455120b917": "Common Files",
    "6d809377-6af0-444b-8957-a3773f02200e": "Program Files (x64)",
    "7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e": "Program Files (x86)",
    "1ac14e77-02e7-4e5d-b744-2eb1ae5198b7": "System32",
    "f38bf404-1d43-42f2-9305-67de0b28fc23": "Windows",
    "679f85cb-0220-4080-b29b-5540cc05aab6": "Quick Access",
    "26ee0668-a00a-44d7-9371-beb064c98683": "Control Panel",
    "018d5c66-4533-4307-9b53-224de2ed1fe6": "OneDrive",
    "f874310e-b6b7-47dc-bc84-b9e6b38f5903": "Home",
    "e31ea727-12ed-4702-820c-4b6445f28e1a": "Recent files",
    "d34a6ca6-62c2-4c34-8a7c-14709c1ad938": "Network shortcuts",
    "22877a6d-37a1-461a-91b0-dbda5aaebc99": "Recent places",
    "4234d49b-0245-4df3-b780-3893943456e1": "Applications",
    "3936e9e4-d92c-4eee-a85a-9c16a352dfab": "Public Documents",
    "ed4824af-dce4-45a8-81e2-fc7965083634": "Public Documents (alt)",
    "f02c1a0d-be21-4350-88b0-7367fc96ef3c": "Network",
    "5b934b42-522b-4c34-bbfe-37a3ef7b9c90": "This PC (folder)",
    "d20ea4e1-3957-11d2-a40b-0c5020524153": "Administrative Tools",
    "9e3995ab-1f9c-4f13-b827-48b24b6c7174": "Taskbar pinned",
    "b155bdf8-02f0-451e-9a26-ae317cfd7779": "Network locations",
}

def _readable(name):
    if not name:
        return None
    printable = sum(1 for c in name if c.isprintable() and ord(c) < 0x2000)
    return name if printable >= max(1, len(name) * 0.8) else None

TYPE_ROOT = 0x1F
TYPE_VOLUME = 0x20
TYPE_FILE = 0x30
TYPE_NETWORK = 0x40
TYPE_URI = 0x60
TYPE_CONTROL = 0x70

EXT_BEEF0004 = 0xBEEF0004

def dos_datetime(v):
    if not v:
        return None
    date = (v >> 16) & 0xFFFF
    time = v & 0xFFFF
    y = ((date >> 9) & 0x7F) + 1980
    mo = (date >> 5) & 0x0F
    d = date & 0x1F
    h = (time >> 11) & 0x1F
    mi = (time >> 5) & 0x3F
    s = (time & 0x1F) * 2
    if not (1 <= mo <= 12 and 1 <= d <= 31 and h < 24 and mi < 60 and s < 60):
        return None
    try:
        # A DOS time carries no zone, so no "Z": nothing says it is UTC.
        return datetime.datetime(y, mo, d, h, mi, s).isoformat()
    except ValueError:
        return None

def _utf16z(data, pos):
    end = pos
    while end + 1 < len(data) and data[end:end + 2] != b"\x00\x00":
        end += 2
    return data[pos:end].decode("utf-16-le", "replace"), end + 2

def _asciiz(data, pos):
    end = data.find(b"\x00", pos)
    if end < 0:
        end = len(data)
    return data[pos:end].decode("latin-1", "replace"), end + 1

def _extension_blocks(item, start):
    out = {}
    pos = start
    while pos + 8 <= len(item):
        size = struct.unpack_from("<H", item, pos)[0]
        if size < 8 or pos + size > len(item):
            break
        version = struct.unpack_from("<H", item, pos + 2)[0]
        sig = struct.unpack_from("<I", item, pos + 4)[0]
        if sig == EXT_BEEF0004:
            created = struct.unpack_from("<I", item, pos + 8)[0]
            accessed = struct.unpack_from("<I", item, pos + 12)[0]
            out["created"] = dos_datetime(created)
            out["accessed"] = dos_datetime(accessed)
            p = pos + 18
            if version >= 7:
                p += 2 + 8 + 8
            if version >= 3:
                p += 2
            if version >= 9:
                p += 4
            if version >= 8:
                p += 4
            if p < pos + size:
                name, _ = _utf16z(item, p)
                if name:
                    out["long_name"] = name
        pos += size
    return out

def parse_shell_item(item):
    if len(item) < 4:
        return None
    itype = item[2]
    high = itype & 0x70

    if high == TYPE_ROOT or itype == TYPE_ROOT:
        if len(item) >= 20:
            try:
                gid = str(uuid.UUID(bytes_le=item[4:20]))
            except ValueError:
                gid = None
            if gid:
                return {"kind": "root", "guid": gid,
                        "name": KNOWN_FOLDERS.get(gid, "{%s}" % gid)}
        return {"kind": "root", "name": "(root)"}

    if high == TYPE_VOLUME:
        if itype == 0x2E and len(item) >= 20:
            try:
                gid = str(uuid.UUID(bytes_le=item[4:20]))
                return {"kind": "device", "guid": gid,
                        "name": KNOWN_FOLDERS.get(gid, "{%s}" % gid)}
            except ValueError:
                pass
        name, _ = _asciiz(item, 3)
        clean = _readable(name.strip("\x00"))
        if not clean:
            return {"kind": "volume", "name": "(volume, name not decodable)",
                    "undecoded": True}
        return {"kind": "volume", "name": clean}

    if high == TYPE_FILE:
        if len(item) < 14:
            return {"kind": "file", "name": "(truncated)"}
        size = struct.unpack_from("<I", item, 4)[0]
        modified = struct.unpack_from("<I", item, 8)[0]
        attrs = struct.unpack_from("<H", item, 12)[0]
        short, after = _asciiz(item, 14)
        ext = _extension_blocks(item, (after + 1) & ~1)
        label = _readable(ext.get("long_name")) or _readable(short)
        return {
            "kind": "directory" if attrs & 0x10 else "file",
            "name": label or "(name not decodable)",
            "undecoded": label is None,
            "short_name": short,
            "size": size or None,
            "modified": dos_datetime(modified),
            "created": ext.get("created"),
            "accessed": ext.get("accessed"),
        }

    if high == TYPE_NETWORK:
        name, _ = _asciiz(item, 5)
        return {"kind": "network", "name": name or "(network)"}

    if high == TYPE_URI:
        try:
            name, _ = _utf16z(item, 6)
        except Exception:
            name = ""
        return {"kind": "uri", "name": name or "(uri)"}

    if high == TYPE_CONTROL:
        return {"kind": "control panel", "name": "(control panel)"}

    return {"kind": "unknown", "type": "0x%02X" % itype,
            "name": "(unrecognised shell item 0x%02X)" % itype}

def walk_bagmru(hive, key, path=(), out=None, depth=0, seen=None):
    if out is None:
        out = []
    if seen is None:
        seen = set()
    if depth > 32 or not key:
        return out
    if key["offset"] in seen:
        return out
    seen.add(key["offset"])

    values = {str(v["name"]): v for v in hive.values(key, inline=False)}
    for sub in hive.subkeys(key):
        name = sub["name"]
        if not name.isdigit():
            continue
        v = values.get(name)
        item = hive.value_bytes(v["offset"]) if v else b""
        parsed = parse_shell_item(item) if item else None
        label = parsed["name"] if parsed else "(no shell item)"
        here = path + (label,)
        out.append({
            "path": "\\".join(here),
            "name": label,
            "kind": parsed["kind"] if parsed else "unknown",
            "shell_size": parsed.get("size") if parsed else None,
            "shell_modified": parsed.get("modified") if parsed else None,
            "shell_created": parsed.get("created") if parsed else None,
            "shell_accessed": parsed.get("accessed") if parsed else None,
            "last_opened": sub.get("modified"),
            "depth": depth,
            "slot": next((x.get("value") for x in hive.values(sub)
                          if x["name"] == "NodeSlot"), None),
        })
        walk_bagmru(hive, sub, here, out, depth + 1, seen)
    return out

BAG_PATHS = [
    r"Software\Microsoft\Windows\Shell\BagMRU",
    r"Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
    r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
    r"Wow6432Node\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
]

def parse(hive, source=""):
    out = {"entries": [], "findings": [], "root": None}
    for path in BAG_PATHS:
        k = hive.open_path(path)
        if not k:
            continue
        entries = walk_bagmru(hive, k)
        if entries:
            out["root"] = path
            out["entries"] = entries
            break
    if not out["entries"]:
        out["findings"].append(
            "No shellbags in this hive. On Windows 10 they live in "
            "UsrClass.dat, not NTUSER.DAT.")
    unknown = sum(1 for e in out["entries"] if e["kind"] == "unknown")
    if unknown:
        out["findings"].append(
            "%d entries use a shell item type this parser does not decode; "
            "their position in the tree is right but the name is not." % unknown)
    out["source"] = source
    return out
