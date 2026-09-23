import struct

TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8,
             11: 4, 12: 8, 13: 4}

MAX_ENTRIES = 4096
MAX_IFDS = 32

IFD0 = {
    0x010F: "Make",
    0x0110: "Model",
    0x0112: "Orientation",
    0x011A: "XResolution",
    0x011B: "YResolution",
    0x0131: "Software",
    0x0132: "DateTime",
    0x013B: "Artist",
    0x8298: "Copyright",
    0x9C9B: "XPTitle",
    0x9C9C: "XPComment",
    0x9C9D: "XPAuthor",
    0x9C9E: "XPKeywords",
    0x9C9F: "XPSubject",
}

EXIF_IFD = {
    0x829A: "ExposureTime",
    0x829D: "FNumber",
    0x8827: "ISOSpeedRatings",
    0x9000: "ExifVersion",
    0x9003: "DateTimeOriginal",
    0x9004: "DateTimeDigitized",
    0x9201: "ShutterSpeedValue",
    0x9202: "ApertureValue",
    0x920A: "FocalLength",
    0xA002: "PixelXDimension",
    0xA003: "PixelYDimension",
    0xA402: "ExposureMode",
    0xA403: "WhiteBalance",
    0xA430: "CameraOwnerName",
    0xA431: "BodySerialNumber",
    0xA432: "LensSpecification",
    0xA433: "LensMake",
    0xA434: "LensModel",
    0xA435: "LensSerialNumber",
}

GPS_IFD = {
    0x0000: "GPSVersionID",
    0x0001: "GPSLatitudeRef",
    0x0002: "GPSLatitude",
    0x0003: "GPSLongitudeRef",
    0x0004: "GPSLongitude",
    0x0005: "GPSAltitudeRef",
    0x0006: "GPSAltitude",
    0x0007: "GPSTimeStamp",
    0x0008: "GPSSatellites",
    0x0009: "GPSStatus",
    0x0010: "GPSImgDirectionRef",
    0x0011: "GPSImgDirection",
    0x001B: "GPSProcessingMethod",
    0x001D: "GPSDateStamp",
}

TAG_EXIF_IFD = 0x8769
TAG_GPS_IFD = 0x8825
TAG_THUMB_OFFSET = 0x0201
TAG_THUMB_LENGTH = 0x0202
MAX_THUMB_BYTES = 1 << 20

def _clean(s):
    s = s.split("\x00", 1)[0].strip()
    return "".join(c for c in s if c == "\t" or ord(c) >= 0x20)

def _decode(buf, at, endian, typ, count):
    e = "<" if endian == "II" else ">"
    size = TYPE_SIZE[typ]
    if at + size * count > len(buf):
        return None
    if typ == 2:
        return _clean(buf[at:at + count].decode("latin-1", "replace"))
    if typ == 7:
        return buf[at:at + count]
    out = []
    for i in range(count):
        o = at + i * size
        if typ == 1:
            out.append(buf[o])
        elif typ == 6:
            out.append(struct.unpack_from(e + "b", buf, o)[0])
        elif typ == 3:
            out.append(struct.unpack_from(e + "H", buf, o)[0])
        elif typ == 8:
            out.append(struct.unpack_from(e + "h", buf, o)[0])
        elif typ == 4 or typ == 13:
            out.append(struct.unpack_from(e + "I", buf, o)[0])
        elif typ == 9:
            out.append(struct.unpack_from(e + "i", buf, o)[0])
        elif typ == 5:
            n, d = struct.unpack_from(e + "II", buf, o)
            out.append((n, d))
        elif typ == 10:
            n, d = struct.unpack_from(e + "ii", buf, o)
            out.append((n, d))
        elif typ == 11:
            out.append(struct.unpack_from(e + "f", buf, o)[0])
        elif typ == 12:
            out.append(struct.unpack_from(e + "d", buf, o)[0])
        else:
            return None
    return out[0] if count == 1 else out

def _entry_value(buf, base, endian, typ, count, raw4):
    size = TYPE_SIZE.get(typ)
    if not size:
        return None
    total = size * count
    if total <= 4:
        return _decode(raw4, 0, endian, typ, count)
    e = "<" if endian == "II" else ">"
    off, = struct.unpack(e + "I", raw4)
    at = base + off
    if at < 0 or total > (1 << 20) or at + total > len(buf):
        return None
    return _decode(buf, at, endian, typ, count)

def _read_ifd(buf, base, at, endian, names, seen):
    e = "<" if endian == "II" else ">"
    if at in seen or at < 0 or at + 2 > len(buf):
        return {}, 0, {}
    seen.add(at)
    n, = struct.unpack_from(e + "H", buf, at)
    if n == 0 or n > MAX_ENTRIES or at + 2 + n * 12 > len(buf):
        return {}, 0, {}
    out, ptrs = {}, {}
    for i in range(n):
        o = at + 2 + i * 12
        tag, typ, count = struct.unpack_from(e + "HHI", buf, o)
        raw4 = buf[o + 8:o + 12]
        if count > (1 << 20):
            continue
        if tag in (TAG_EXIF_IFD, TAG_GPS_IFD, TAG_THUMB_OFFSET, TAG_THUMB_LENGTH):
            v = _entry_value(buf, base, endian, typ, count, raw4)
            if isinstance(v, int):
                ptrs[tag] = v
            continue
        name = names.get(tag)
        if not name:
            continue
        v = _entry_value(buf, base, endian, typ, count, raw4)
        if v is not None:
            out[name] = v
    nxt = 0
    end = at + 2 + n * 12
    if end + 4 <= len(buf):
        nxt, = struct.unpack_from(e + "I", buf, end)
    return out, nxt, ptrs

def _rational(v):
    if isinstance(v, tuple) and len(v) == 2 and v[1]:
        return v[0] / v[1]
    return None

def _dms(v, ref):
    if not isinstance(v, list) or len(v) != 3:
        return None, "Coordinate is not three rationals; not decoded."
    parts = [_rational(x) for x in v]
    if any(p is None for p in parts):
        return None, "Coordinate has a zero denominator; not decoded."
    deg = parts[0] + parts[1] / 60.0 + parts[2] / 3600.0
    if deg > 180.0:
        return None, "Coordinate out of range; not decoded."
    r = (ref or "").strip().upper()[:1]
    if r in ("S", "W"):
        return -deg, None
    if r in ("N", "E"):
        return deg, None
    return deg, ("No hemisphere reference recorded, so the sign is unknown. "
                 "The magnitude is as stored.")

def _tiff(buf, base=0, want_thumb=False):
    if base + 8 > len(buf):
        return None
    endian = buf[base:base + 2].decode("latin-1", "replace")
    if endian not in ("II", "MM"):
        return None
    e = "<" if endian == "II" else ">"
    magic, first = struct.unpack_from(e + "HI", buf, base + 2)
    if magic != 42:
        return None

    seen = set()
    ifd0, nxt, ptrs = _read_ifd(buf, base, base + first, endian, IFD0, seen)
    out = {"byte_order": "little-endian" if endian == "II" else "big-endian",
           "image": ifd0, "exif": {}, "gps": {}, "thumbnail": {}}

    if TAG_EXIF_IFD in ptrs:
        sub, _n, _p = _read_ifd(buf, base, base + ptrs[TAG_EXIF_IFD], endian,
                                EXIF_IFD, seen)
        out["exif"] = sub
    if TAG_GPS_IFD in ptrs:
        sub, _n, _p = _read_ifd(buf, base, base + ptrs[TAG_GPS_IFD], endian,
                                GPS_IFD, seen)
        out["gps"] = sub

    hops = 0
    while nxt and hops < MAX_IFDS:
        hops += 1
        thumb, nxt, tptrs = _read_ifd(buf, base, base + nxt, endian, IFD0, seen)
        if thumb and not out["thumbnail"]:
            out["thumbnail"] = thumb
        if (want_thumb and "thumbnail_jpeg" not in out
                and TAG_THUMB_OFFSET in tptrs and TAG_THUMB_LENGTH in tptrs):
            t_off = base + tptrs[TAG_THUMB_OFFSET]
            t_len = tptrs[TAG_THUMB_LENGTH]
            if (0 <= t_off and 0 < t_len <= MAX_THUMB_BYTES
                    and t_off + t_len <= len(buf)):
                out["thumbnail_jpeg"] = bytes(buf[t_off:t_off + t_len])
    return out

def _from_jpeg(data, want_thumb=False):
    if data[:2] != b"\xff\xd8":
        return None
    i = 2
    n = len(data)
    while i + 4 <= n:
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        if marker == 0xDA or marker == 0xD9:
            break
        seg_len, = struct.unpack_from(">H", data, i + 2)
        if seg_len < 2 or i + 2 + seg_len > n:
            break
        if marker == 0xE1 and data[i + 4:i + 10] == b"Exif\x00\x00":
            return _tiff(data, i + 10, want_thumb)
        i += 2 + seg_len
    return None

def _from_png(data, want_thumb=False):
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    i = 8
    n = len(data)
    while i + 8 <= n:
        length, = struct.unpack_from(">I", data, i)
        kind = data[i + 4:i + 8]
        if length > n:
            break
        if kind == b"eXIf":
            return _tiff(data, i + 8, want_thumb)
        if kind == b"IDAT":
            break
        i += 12 + length
    return None

def parse(data):
    if not data or len(data) < 16:
        return None
    got = None
    if data[:2] == b"\xff\xd8":
        got = _from_jpeg(data)
    elif data[:8] == b"\x89PNG\r\n\x1a\n":
        got = _from_png(data)
    elif data[:2] in (b"II", b"MM"):
        got = _tiff(data, 0)
    if not got:
        return None
    got["coordinates"] = coordinates(got.get("gps") or {})
    got["summary"] = summarise(got)
    return got

def thumbnail(data):
    """The embedded thumbnail JPEG's raw bytes (JPEGInterchangeFormat /
    JPEGInterchangeFormatLength on the IFD1 thumbnail entry), or None
    when there isn't one. A narrower read than parse(): a caller that
    wants to serve or preview the thumbnail image doesn't need the whole
    metadata tree, and parse() itself never carries these bytes -- only
    asking for them here decodes them, so every existing parse() caller
    is unaffected."""
    if not data or len(data) < 16:
        return None
    got = None
    if data[:2] == b"\xff\xd8":
        got = _from_jpeg(data, want_thumb=True)
    elif data[:8] == b"\x89PNG\r\n\x1a\n":
        got = _from_png(data, want_thumb=True)
    elif data[:2] in (b"II", b"MM"):
        got = _tiff(data, 0, want_thumb=True)
    return (got or {}).get("thumbnail_jpeg")

def coordinates(gps):
    if not gps:
        return None
    lat_raw, lon_raw = gps.get("GPSLatitude"), gps.get("GPSLongitude")
    if lat_raw is None or lon_raw is None:
        return None
    lat, lat_note = _dms(lat_raw, gps.get("GPSLatitudeRef"))
    lon, lon_note = _dms(lon_raw, gps.get("GPSLongitudeRef"))
    if lat is None or lon is None:
        return {"decoded": False,
                "note": lat_note or lon_note or "Coordinate not decoded."}
    out = {"decoded": True, "latitude": round(lat, 7),
           "longitude": round(lon, 7)}
    alt = _rational(gps.get("GPSAltitude"))
    if alt is not None:
        if gps.get("GPSAltitudeRef") == 1:
            alt = -alt
        out["altitude_m"] = round(alt, 2)
    if gps.get("GPSDateStamp") or gps.get("GPSTimeStamp"):
        t = gps.get("GPSTimeStamp")
        hms = None
        if isinstance(t, list) and len(t) == 3:
            vals = [_rational(x) for x in t]
            if all(v is not None for v in vals):
                hms = "%02d:%02d:%06.3f" % (vals[0], vals[1], vals[2])
        out["fix_utc"] = " ".join(
            x for x in ((gps.get("GPSDateStamp") or "").replace(":", "-"), hms)
            if x) or None
        out["fix_note"] = ("The GPS timestamp is UTC as the receiver had it, "
                           "which is independent of the camera's own clock.")
    notes = [n for n in (lat_note, lon_note) if n]
    if notes:
        out["note"] = " ".join(dict.fromkeys(notes))
    return out

def summarise(got):
    img, ex = got.get("image") or {}, got.get("exif") or {}
    made = img.get("Make")
    model = img.get("Model")
    device = " ".join(x for x in (made, model) if x) or None
    when = (ex.get("DateTimeOriginal") or ex.get("DateTimeDigitized")
            or img.get("DateTime"))
    return {
        "device": device,
        "serial": ex.get("BodySerialNumber") or None,
        "owner": ex.get("CameraOwnerName") or img.get("Artist") or None,
        "lens": ex.get("LensModel") or None,
        "software": img.get("Software") or None,
        "taken": when or None,
        "note": ("EXIF timestamps carry no time zone and are written by the "
                 "device's own clock, which may be wrong or deliberately set. "
                 "They are not independent of the person holding the camera."),
    }
