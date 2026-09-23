import datetime
import struct

WIN10_HEADER = 0x34
WIN81_HEADER = 0x30
WIN7_HEADER = 0x80

ENTRY_WIN10 = b"10ts"
ENTRY_WIN8 = b"00ts"

def filetime(v):
    if not v:
        return None
    try:
        return (datetime.datetime(1601, 1, 1)
                + datetime.timedelta(microseconds=v // 10)).isoformat() + "Z"
    except (OverflowError, ValueError):
        return None

def unix_time(v):
    if not v:
        return None
    try:
        return (datetime.datetime(1970, 1, 1)
                + datetime.timedelta(seconds=int(v))).isoformat() + "Z"
    except (OverflowError, ValueError, TypeError):
        return None

def parse_shimcache(data):
    out = {"entries": [], "findings": [], "format": None}
    if len(data) < 8:
        return out
    header = struct.unpack_from("<I", data, 0)[0]

    if header in (WIN10_HEADER, WIN81_HEADER):
        out["format"] = "Windows 10" if header == WIN10_HEADER else "Windows 8.1"
        pos = header
        order = 0
        while pos + 12 <= len(data):
            sig = data[pos:pos + 4]
            if sig not in (ENTRY_WIN10, ENTRY_WIN8):
                break
            cell_size = struct.unpack_from("<I", data, pos + 8)[0]
            p = pos + 12
            if p + 2 > len(data):
                break
            path_len = struct.unpack_from("<H", data, p)[0]
            p += 2
            path = data[p:p + path_len].decode("utf-16-le", "replace")
            p += path_len
            if p + 8 > len(data):
                break
            modified = struct.unpack_from("<Q", data, p)[0]
            p += 8
            data_size = struct.unpack_from("<I", data, p)[0] if p + 4 <= len(data) else 0
            p += 4 + data_size
            out["entries"].append({
                "path": path,
                "modified": filetime(modified),
                "order": order,
            })
            order += 1
            pos = pos + 12 + cell_size if cell_size else p
            if cell_size and pos <= p - cell_size:
                break
        return out

    if header == WIN7_HEADER:
        out["format"] = "Windows 7"
        count = struct.unpack_from("<I", data, 4)[0]
        pos = WIN7_HEADER
        entry_size = 48
        for i in range(min(count, 4096)):
            if pos + entry_size > len(data):
                break
            path_len, _path_max, path_off = struct.unpack_from("<HHI", data, pos)
            modified = struct.unpack_from("<Q", data, pos + 8)[0]
            path = ""
            if path_off and path_off + path_len <= len(data):
                path = data[path_off:path_off + path_len].decode("utf-16-le",
                                                                 "replace")
            out["entries"].append({"path": path, "modified": filetime(modified),
                                   "order": i})
            pos += entry_size
        return out

    out["findings"].append(
        "Unrecognised AppCompatCache header 0x%08X — this parser handles "
        "Windows 7, 8.1 and 10. The value is present but not decoded." % header)
    return out

def shimcache_from_system(hive):
    out = []
    for cs in ("ControlSet001", "ControlSet002", "ControlSet003",
               "CurrentControlSet"):
        k = hive.open_path(cs + r"\Control\Session Manager\AppCompatCache")
        if not k:
            continue
        for val in hive.values(k, inline=False):
            if val["name"] != "AppCompatCache":
                continue
            raw = hive.value_bytes(val["offset"])
            parsed = parse_shimcache(raw)
            parsed["control_set"] = cs
            parsed["bytes"] = len(raw)
            if parsed["entries"]:
                parsed["findings"].append(SHIMCACHE_CAVEAT)
            out.append(parsed)
    return out

SHIMCACHE_CAVEAT = (
    "An AppCompatCache/ShimCache entry proves the file was present and "
    "examined by the compatibility subsystem -- typically at execution, but "
    "also on some file-open and file-copy operations. It is not proof the "
    "program ran; Amcache records execution more directly and is not "
    "cleared by ShimCache-clearing tools.")

LEGACY_FILE_FIELDS = {
    "0": "product_name", "1": "company_name", "5": "product_version",
    "6": "file_version", "c": "file_description", "f": "link_date",
    "11": "modified", "12": "created", "15": "path", "17": "size",
    "100": "program_id", "101": "sha1",
}

def _clean_sha1(v):
    if not isinstance(v, str):
        return None
    s = v.strip().lower()
    if s.startswith("0000") and len(s) == 44:
        return s[4:]
    return s or None

def parse_amcache(hive, limit=20000):
    out = {"files": [], "programs": [], "findings": [], "layout": None}
    root = hive.root()
    if not root:
        return out
    subs = hive.subkeys(root)
    if len(subs) == 1 and subs[0]["name"].lower() == "root":
        root = subs[0]
        subs = hive.subkeys(root)
    tops = {s["name"].lower(): s for s in subs}

    inv = tops.get("inventoryapplicationfile")
    if inv:
        out["layout"] = "InventoryApplicationFile"
        for k in hive.subkeys(inv)[:limit]:
            v = {x["name"]: x.get("value") for x in hive.values(k)}
            out["files"].append({
                "path": v.get("LowerCaseLongPath"),
                "name": v.get("Name"),
                "sha1": _clean_sha1(v.get("FileId")),
                "size": v.get("Size"),
                "publisher": v.get("Publisher") or v.get("ProductName"),
                "version": v.get("Version") or v.get("BinFileVersion"),
                "product": v.get("ProductName"),
                "linked_at": unix_time(v.get("LinkDate"))
                if isinstance(v.get("LinkDate"), int) else v.get("LinkDate"),
                "program_id": v.get("ProgramId"),
                "key_modified": k.get("modified"),
                "source": "InventoryApplicationFile",
            })

    app = tops.get("inventoryapplication")
    if app:
        for k in hive.subkeys(app)[:limit]:
            v = {x["name"]: x.get("value") for x in hive.values(k)}
            out["programs"].append({
                "name": v.get("Name"),
                "version": v.get("Version"),
                "publisher": v.get("Publisher"),
                "install_date": v.get("InstallDate"),
                "root": v.get("RootDirPath"),
                "source": v.get("Source"),
                "key_modified": k.get("modified"),
            })

    legacy = tops.get("file")
    if legacy and not out["files"]:
        out["layout"] = "File (legacy)"
        for volume in hive.subkeys(legacy):
            for k in hive.subkeys(volume)[:limit]:
                v = {}
                for x in hive.values(k):
                    field = LEGACY_FILE_FIELDS.get(str(x["name"]).lower())
                    if field:
                        v[field] = x.get("value")
                if not v:
                    continue
                out["files"].append({
                    "path": v.get("path"),
                    "name": (v.get("path") or "").replace("/", "\\").rsplit("\\", 1)[-1],
                    "sha1": _clean_sha1(v.get("sha1")),
                    "size": v.get("size"),
                    "publisher": v.get("company_name"),
                    "version": v.get("file_version"),
                    "product": v.get("product_name"),
                    "linked_at": v.get("link_date"),
                    "volume": volume["name"],
                    "key_modified": k.get("modified"),
                    "source": "File (legacy)",
                })

    if not out["files"] and not out["programs"]:
        out["findings"].append(
            "No recognised Amcache layout — the hive parsed but neither "
            "InventoryApplicationFile nor File was present.")
    if hive.dirty:
        out["findings"].append(
            "Amcache hive was not cleanly unmounted; its .LOG files may hold "
            "entries missing here.")
    return out
