"""Unit tests for the Conectix VHD footer (engine.vhd): a fixed VHD opens
directly with the footer excluded from the exposed disk; dynamic and
differencing VHDs, and a footer that fails to validate, are refused
explicitly rather than misread."""

import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import ewf, vhd                                       # noqa: E402

DISK_TYPE_FIXED = 2
DISK_TYPE_DYNAMIC = 3
DISK_TYPE_DIFFERENCING = 4


def build_footer(disk_type=DISK_TYPE_FIXED, current_size=0, original_size=None,
                  cookie=b"conectix", bad_checksum=False):
    footer = bytearray(512)
    struct.pack_into(">8s", footer, 0, cookie)
    struct.pack_into(">I", footer, 8, 2)                  # features
    struct.pack_into(">I", footer, 12, 0x00010000)        # file format version
    struct.pack_into(">Q", footer, 16, 0xFFFFFFFFFFFFFFFF)  # data offset
    struct.pack_into(">I", footer, 24, 0)                 # timestamp
    struct.pack_into(">4s", footer, 28, b"stra")           # creator app
    struct.pack_into(">I", footer, 32, 0x00010000)        # creator version
    struct.pack_into(">4s", footer, 36, b"Wi2k")           # creator host OS
    struct.pack_into(">Q", footer, 40,
                     current_size if original_size is None else original_size)
    struct.pack_into(">Q", footer, 48, current_size)
    struct.pack_into(">I", footer, 56, 0)                 # disk geometry
    struct.pack_into(">I", footer, 60, disk_type)
    total = sum(footer[:64]) + sum(footer[68:512])
    checksum = (~total) & 0xFFFFFFFF
    if bad_checksum:
        checksum ^= 0xFFFFFFFF
    struct.pack_into(">I", footer, 64, checksum)
    return bytes(footer)


MEDIA = bytes((i * 37 + 11) % 256 for i in range(4096))


def fixed_vhd_bytes(data=MEDIA):
    return data + build_footer(DISK_TYPE_FIXED, current_size=len(data))


class VhdCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="strata-vhd-test-")
        self.addCleanup(self._tmp.cleanup)

    def write(self, data, name="disk.vhd"):
        path = os.path.join(self._tmp.name, name)
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def open(self, data, name="disk.vhd"):
        img = ewf.open_image(self.write(data, name))
        self.addCleanup(img.close)
        return img


class FixedVhd(VhdCase):
    def setUp(self):
        super(FixedVhd, self).setUp()
        self.img = self.open(fixed_vhd_bytes())

    def test_opens_as_fixed_vhd(self):
        self.assertIsInstance(self.img, vhd.VhdImage)
        self.assertEqual(self.img.findings, [])

    def test_exposes_only_the_virtual_disk_bytes(self):
        self.assertEqual(self.img.size, len(MEDIA))
        self.assertEqual(self.img.read_at(0, len(MEDIA)), MEDIA)

    def test_footer_is_not_readable_as_disk_data(self):
        # Asking for more than the disk holds must not spill into the
        # footer that follows it in the file.
        got = self.img.read_at(0, len(MEDIA) + 512)
        self.assertEqual(len(got), len(MEDIA))
        self.assertEqual(got, MEDIA)

    def test_read_past_end_is_empty(self):
        self.assertEqual(self.img.read_at(len(MEDIA), 100), b"")

    def test_info_reports_fixed_vhd(self):
        info = self.img.info()
        self.assertIn("VHD", info["format"])
        self.assertIn("fixed", info["format"])
        self.assertEqual(info["size"], len(MEDIA))
        self.assertEqual(info["findings"], [])

    def test_verify_hashes_only_the_disk_bytes(self):
        import hashlib
        result = self.img.verify()
        self.assertEqual(result["computed_md5"], hashlib.md5(MEDIA).hexdigest())


class UnsupportedTypes(VhdCase):
    def test_dynamic_vhd_is_refused_by_name(self):
        data = MEDIA + build_footer(DISK_TYPE_DYNAMIC, current_size=len(MEDIA))
        with self.assertRaises(ewf.UnsupportedContainer) as cm:
            ewf.open_image(self.write(data))
        self.assertIn("dynamic", str(cm.exception))

    def test_differencing_vhd_is_refused_by_name(self):
        data = MEDIA + build_footer(DISK_TYPE_DIFFERENCING, current_size=len(MEDIA))
        with self.assertRaises(ewf.UnsupportedContainer) as cm:
            ewf.open_image(self.write(data))
        self.assertIn("differencing", str(cm.exception))

    def test_unrecognised_disk_type_is_refused(self):
        data = MEDIA + build_footer(5, current_size=len(MEDIA))
        with self.assertRaises(ewf.UnsupportedContainer):
            ewf.open_image(self.write(data))


class Malformed(VhdCase):
    def test_bad_checksum_fails_safely(self):
        data = MEDIA + build_footer(DISK_TYPE_FIXED, current_size=len(MEDIA),
                                    bad_checksum=True)
        with self.assertRaises(ewf.UnsupportedContainer):
            ewf.open_image(self.write(data))

    def test_size_mismatch_is_reported_and_clamped(self):
        # The footer claims a virtual disk 100 bytes smaller than the data
        # actually in front of it.
        data = MEDIA + build_footer(DISK_TYPE_FIXED, current_size=len(MEDIA) - 100)
        img = ewf.open_image(self.write(data))
        self.addCleanup(img.close)
        self.assertEqual(img.size, len(MEDIA) - 100)
        self.assertTrue(img.findings)

    def test_truncated_footer_falls_back_to_raw_without_crashing(self):
        # Cut into the footer itself: the tail no longer carries a whole,
        # valid footer, so this cannot be confirmed as a VHD at all and is
        # read as a raw file instead of raising or hanging.
        data = fixed_vhd_bytes()[:-100]
        img = ewf.open_image(self.write(data))
        self.addCleanup(img.close)
        self.assertIsInstance(img, ewf.RawImage)
        self.assertEqual(img.size, len(data))

    def test_file_too_small_for_a_footer_is_refused_not_crashed(self):
        # Too short for a full 512-byte footer to be confirmed at the tail,
        # but it still starts with the cookie, so the coarse head-based
        # check still recognises and refuses it explicitly.
        with self.assertRaises(ewf.UnsupportedContainer):
            ewf.open_image(self.write(b"conectix" + bytes(50)))

    def test_empty_file_does_not_crash(self):
        img = ewf.open_image(self.write(b""))
        self.addCleanup(img.close)
        self.assertIsInstance(img, ewf.RawImage)
        self.assertEqual(img.size, 0)


if __name__ == "__main__":
    unittest.main()
