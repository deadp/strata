"""Unit tests for engine.pdfdoc active-content detection."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import pdfdoc                                         # noqa: E402


class NameEscapes(unittest.TestCase):

    def test_hex_escaped_name_is_still_detected_and_neutralised(self):
        data = (b"%PDF-1.4\n1 0 obj\n"
                b"<< /Type /Page /S /Java#53cript >>\nendobj\n")
        pdf = pdfdoc.Pdf(data)
        self.assertIn("/JavaScript", [a["key"] for a in pdf.active])
        clean = pdf.sanitised()
        self.assertIsNotNone(clean)
        self.assertEqual(len(clean), len(data))
        self.assertNotIn(b"Java#53cript", clean)
        self.assertFalse(pdfdoc._name_positions(clean, b"/JavaScript"))


if __name__ == "__main__":
    unittest.main()
