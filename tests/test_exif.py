import struct
import unittest

from engine import exif


def _le16(v):
    return struct.pack("<H", v)


def _le32(v):
    return struct.pack("<I", v)


def _ifd_entry(tag, typ, count, value_bytes):
    return struct.pack("<HHI", tag, typ, count) + value_bytes.ljust(4, b"\x00")[:4]


def build_jpeg_with_thumbnail(thumb_jpeg=b"\xff\xd8\xff\xd9\xaa\xbb\xcc",
                              include_thumb_tags=True, thumb_length=None):
    """A minimal JPEG with an APP1/Exif TIFF block: IFD0 (one harmless
    Orientation entry) -> IFD1 carrying JPEGInterchangeFormat/Length
    pointing at thumb_jpeg, which is appended right after the IFDs."""
    header_len = 8  # "II" + magic(2) + ifd0 offset(4)
    ifd0_entries = [_ifd_entry(0x0112, 3, 1, _le16(1))]
    ifd0_size = 2 + 12 * len(ifd0_entries) + 4
    ifd0_at = header_len
    ifd1_at = ifd0_at + ifd0_size

    ifd1_entries = []
    ifd1_count = 2 if include_thumb_tags else 0
    ifd1_size = 2 + 12 * ifd1_count + 4
    thumb_at = ifd1_at + ifd1_size

    if include_thumb_tags:
        ifd1_entries.append(_ifd_entry(0x0201, 4, 1, _le32(thumb_at)))
        ifd1_entries.append(_ifd_entry(
            0x0202, 4, 1, _le32(len(thumb_jpeg) if thumb_length is None
                                else thumb_length)))

    ifd0 = (struct.pack("<H", len(ifd0_entries)) + b"".join(ifd0_entries)
            + struct.pack("<I", ifd1_at))
    ifd1 = (struct.pack("<H", len(ifd1_entries)) + b"".join(ifd1_entries)
            + struct.pack("<I", 0))

    tiff = b"II" + struct.pack("<HI", 42, ifd0_at) + ifd0 + ifd1 + thumb_jpeg
    app1_payload = b"Exif\x00\x00" + tiff
    app1 = struct.pack(">HH", 0xFFE1, len(app1_payload) + 2) + app1_payload
    return b"\xff\xd8" + app1 + b"\xff\xd9"


class Thumbnail(unittest.TestCase):

    def test_extracts_the_embedded_thumbnail_bytes_exactly(self):
        data = build_jpeg_with_thumbnail()
        self.assertEqual(exif.thumbnail(data), b"\xff\xd8\xff\xd9\xaa\xbb\xcc")

    def test_none_when_there_are_no_thumbnail_pointer_tags(self):
        data = build_jpeg_with_thumbnail(include_thumb_tags=False)
        self.assertIsNone(exif.thumbnail(data))

    def test_none_when_the_claimed_length_runs_past_the_data(self):
        data = build_jpeg_with_thumbnail(thumb_length=10_000_000)
        self.assertIsNone(exif.thumbnail(data))

    def test_none_for_data_with_no_exif_at_all(self):
        self.assertIsNone(exif.thumbnail(b"\xff\xd8\xff\xd9" + b"\x00" * 20))

    def test_none_for_short_or_empty_input(self):
        self.assertIsNone(exif.thumbnail(b""))
        self.assertIsNone(exif.thumbnail(b"\xff\xd8"))

    def test_parse_never_carries_the_thumbnail_bytes(self):
        # thumbnail() is a separate, narrower read -- parse()'s own
        # output must be exactly as before this existed.
        data = build_jpeg_with_thumbnail()
        got = exif.parse(data)
        self.assertNotIn("thumbnail_jpeg", got)
        self.assertEqual(got["image"]["Orientation"], 1)


if __name__ == "__main__":
    unittest.main()
