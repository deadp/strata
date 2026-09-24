import io
import os
import struct
import threading

from .text import t as _t

# The "Conectix" hard disk footer format used by Virtual PC, Virtual
# Server and Hyper-V (VHD, not VHDX). The footer is always the last 512
# bytes of the file; a dynamic or differencing disk also carries an
# identical copy at the very start, but the copy at the end is the one
# the format itself treats as authoritative, so that is the one read
# here regardless of disk type.
SIGNATURE = b"conectix"
FOOTER_SIZE = 512

DISK_TYPE_FIXED = 2
DISK_TYPE_DYNAMIC = 3
DISK_TYPE_DIFFERENCING = 4

_DISK_TYPE_NAMES = {
    0: "none",
    1: "reserved",
    2: "fixed",
    3: "dynamic",
    4: "differencing",
    5: "reserved",
    6: "reserved",
}

class VhdError(Exception):

    def __init__(self, message, advice=""):
        Exception.__init__(self, message)
        self.message = message
        self.advice = advice

def looks_like_vhd(path):
    """Whether the last 512 bytes of `path` carry a VHD footer cookie.
    A fixed VHD's footer only exists at the end of the file, so unlike
    every other container here this has to look at the tail, not the
    head."""
    try:
        size = os.path.getsize(path)
        if size < FOOTER_SIZE:
            return False
        with open(path, "rb") as fh:
            fh.seek(size - FOOTER_SIZE)
            return fh.read(8) == SIGNATURE
    except OSError:
        return False

def _checksum(footer):
    # One's complement of the sum of every footer byte, with the stored
    # checksum field itself (bytes 64-67) treated as zero.
    total = sum(footer[:64]) + sum(footer[68:FOOTER_SIZE])
    return (~total) & 0xFFFFFFFF

def parse_footer(footer):
    """Parse and validate a 512-byte VHD footer, returning its fields.
    Raises VhdError if the cookie is missing or the checksum does not
    match -- it does not judge the disk type, so a caller can still see
    what a footer with a bad checksum claims to be."""
    if len(footer) < FOOTER_SIZE:
        raise VhdError(_t("vhd.footer_short"))
    if footer[:8] != SIGNATURE:
        raise VhdError(_t("vhd.footer_missing_cookie"))
    disk_type, = struct.unpack_from(">I", footer, 60)
    current_size, = struct.unpack_from(">Q", footer, 48)
    original_size, = struct.unpack_from(">Q", footer, 40)
    stored_checksum, = struct.unpack_from(">I", footer, 64)
    return {
        "disk_type": disk_type,
        "current_size": current_size,
        "original_size": original_size,
        "checksum_ok": stored_checksum == _checksum(footer),
    }

class VhdImage:
    """A fixed VHD: raw disk data followed by a 512-byte Conectix footer.
    Only the disk data is exposed -- the footer is trailing container
    metadata, not part of the disk the guest OS saw."""

    def __init__(self, path):
        self.path = path
        self.segment_paths = [path]
        self.findings = []
        self._pos = 0
        self._io_lock = threading.Lock()

        file_size = os.path.getsize(path)
        if file_size < FOOTER_SIZE:
            raise VhdError(_t("vhd.footer_short"))

        self._fh = open(path, "rb")
        try:
            self._fh.seek(file_size - FOOTER_SIZE)
            info = parse_footer(self._fh.read(FOOTER_SIZE))

            if info["disk_type"] in (DISK_TYPE_DYNAMIC, DISK_TYPE_DIFFERENCING):
                name = _DISK_TYPE_NAMES[info["disk_type"]]
                raise VhdError(
                    _t("vhd.disk_type_not_fixed") % name,
                    "Only a fixed VHD -- raw data with the footer appended "
                    "-- is read directly. A %s VHD stores its data through "
                    "a block allocation table this reader does not walk. "
                    "Convert it to fixed or raw first." % name)

            if info["disk_type"] != DISK_TYPE_FIXED:
                raise VhdError(
                    _t("vhd.disk_type_unrecognised")
                    % _DISK_TYPE_NAMES.get(info["disk_type"],
                                           "0x%08X" % info["disk_type"]))

            if not info["checksum_ok"]:
                raise VhdError(_t("vhd.footer_checksum_mismatch"))

            data_size = file_size - FOOTER_SIZE
            self.size = min(info["current_size"], data_size)
            if info["current_size"] != data_size:
                self.findings.append(
                    "The footer's current size (%d bytes) does not match "
                    "the data before the footer (%d bytes); the smaller of "
                    "the two is exposed." % (info["current_size"], data_size))
        except Exception:
            self._fh.close()
            raise

        self.bytes_per_sector = 512
        self.original_size = info["original_size"]

    def read_at(self, offset, length):
        if offset < 0 or offset >= self.size or length <= 0:
            return b""
        length = min(length, self.size - offset)
        with self._io_lock:
            self._fh.seek(offset)
            data = self._fh.read(length)
        if len(data) < length:
            data = data + bytes(length - len(data))
        return data

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
        self._fh.close()

    def verify(self, progress=None):
        import hashlib
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
        return {"computed_md5": md5.hexdigest(), "computed_sha1": sha1.hexdigest(),
                "stored_md5": None, "stored_sha1": None,
                "md5_match": None, "sha1_match": None,
                "note": _t("vhd.vhd_stores_acquisition_hash")}

    def info(self):
        return {
            "format": "Virtual PC / Hyper-V disk (VHD, fixed)",
            "segments": [os.path.basename(self.path)],
            "size": self.size,
            "bytes_per_sector": self.bytes_per_sector,
            "chunk_size": 1 << 20,
            "acquisition": {
                "original size": self.original_size,
                "container size on disk": os.path.getsize(self.path),
            },
            "findings": list(self.findings),
        }
