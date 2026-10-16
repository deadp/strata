"""Times recorded with no zone (FAT, DOS times, exFAT without a valid UTC
offset) carry no "Z", and are shown as recorded rather than as UTC."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import report, shellbags                              # noqa: E402
from engine.fs import exfat                                       # noqa: E402

# 2023-11-05 08:30:44 as a packed DOS timestamp.
PACKED = ((2023 - 1980) << 25) | (11 << 21) | (5 << 16) | (8 << 11) \
    | (30 << 5) | 22
NZ = {"offset_minutes": 780}


class ExfatOffsets(unittest.TestCase):

    def test_no_valid_offset_claims_no_zone(self):
        for tz in (0x00, 0x30, 0x7F):          # OffsetValid bit clear
            self.assertEqual(exfat._ts(PACKED, tz=tz), "2023-11-05T08:30:44")

    def test_valid_offset_is_converted_to_utc(self):
        self.assertEqual(exfat._ts(PACKED, tz=0x80), "2023-11-05T08:30:44Z")
        self.assertEqual(exfat._ts(PACKED, tz=0x80 | 4),   # +01:00
                         "2023-11-05T07:30:44Z")


class DosTimes(unittest.TestCase):

    def test_shellbag_dos_time_claims_no_zone(self):
        self.assertEqual(shellbags.dos_datetime(PACKED),
                         "2023-11-05T08:30:44")


class ReportTimes(unittest.TestCase):

    def test_zoneless_time_is_shown_as_recorded(self):
        for tz in (None, NZ):
            self.assertEqual(report._when("2023-11-05T08:30:44", tz),
                             "2023-11-05 08:30:44")

    def test_utc_time_is_still_labelled_and_converted(self):
        self.assertEqual(report._when("2023-11-05T08:30:44Z"),
                         "2023-11-05 08:30:44 UTC")
        self.assertIn("2023-11-05 21:30:44 +13:00",
                      report._when("2023-11-05T08:30:44Z", NZ))


if __name__ == "__main__":
    unittest.main()
