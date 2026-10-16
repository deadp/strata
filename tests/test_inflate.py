"""Unit tests for engine.inflate: how a zlib stream that does not finish is
told apart from one that does."""

import os
import random
import sys
import unittest
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import inflate                                        # noqa: E402

PLAIN = bytes(random.Random(7).getrandbits(8) for _ in range(200_000))


class InflateEnded(unittest.TestCase):

    def test_complete_stream_ends(self):
        data, over, status = inflate.inflate_ended(zlib.compress(PLAIN))
        self.assertEqual((data, over, status), (PLAIN, False, inflate.ENDED))

    def test_truncated_stream_stops_with_a_true_prefix(self):
        blob = zlib.compress(PLAIN)
        data, over, status = inflate.inflate_ended(blob[:len(blob) // 2])
        self.assertEqual(status, inflate.STOPPED)
        self.assertFalse(over)
        self.assertTrue(data)
        self.assertEqual(data, PLAIN[:len(data)])

    def test_missing_checksum_stops(self):
        data, _, status = inflate.inflate_ended(zlib.compress(PLAIN)[:-4])
        self.assertEqual(status, inflate.STOPPED)
        self.assertEqual(data, PLAIN)

    def test_stream_damaged_after_output_is_damaged(self):
        # Longer than one feed, so output from earlier feeds survives the
        # error; the status is what tells a caller not to trust it.
        blob = bytearray(zlib.compress(PLAIN))
        blob[-2] ^= 0xFF
        data, _, status = inflate.inflate_ended(bytes(blob))
        self.assertEqual(status, inflate.DAMAGED)

    def test_inflate_capped_is_unchanged(self):
        blob = zlib.compress(PLAIN)
        self.assertEqual(inflate.inflate_capped(blob), (PLAIN, False))
        self.assertEqual(inflate.inflate_capped(blob, 1000)[0], PLAIN[:1000])
        self.assertTrue(inflate.inflate_capped(blob, 1000)[1])


if __name__ == "__main__":
    unittest.main()
