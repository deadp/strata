"""Unit tests for engine.mbox: message splitting and, since #93, reducing an
HTML-only message to visible text without ever treating it as markup."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import mbox                                           # noqa: E402


def build_message(headers, body):
    lines = ["From sender@example.com Mon Jan  1 00:00:00 2024"]
    for k, v in headers.items():
        lines.append("%s: %s" % (k, v))
    return ("\n".join(lines) + "\n\n" + body + "\n").encode("utf-8")


class HtmlToText(unittest.TestCase):

    def test_strips_tags_keeps_text(self):
        got = mbox._html_to_text("<p>Hello <b>World</b></p>")
        self.assertEqual(got, "Hello\nWorld")

    def test_drops_script_and_style_content(self):
        got = mbox._html_to_text(
            "<style>.x{color:red}</style><p>Visible</p>"
            "<script>alert(1)</script>")
        self.assertEqual(got, "Visible")
        self.assertNotIn("alert", got)
        self.assertNotIn("color:red", got)

    def test_empty_or_none_gives_none(self):
        self.assertIsNone(mbox._html_to_text(None))
        self.assertIsNone(mbox._html_to_text(""))
        self.assertIsNone(mbox._html_to_text("<p></p>"))

    def test_malformed_markup_does_not_raise(self):
        # Unclosed tags, stray angle brackets: the parser must degrade
        # rather than crash the whole mail listing over one message.
        got = mbox._html_to_text("<p>Unterminated <b>bold and <i>italic")
        self.assertIn("Unterminated", got)

    def test_truncated_to_limit(self):
        got = mbox._html_to_text("<p>%s</p>" % ("x" * 100), limit=10)
        self.assertEqual(len(got), 10)


class ParseMessageBody(unittest.TestCase):

    def test_plain_text_message_has_no_html_text(self):
        raw = build_message({"Content-Type": "text/plain"}, "plain body")
        got = mbox.parse_message(raw, 0)
        self.assertEqual(got["text"].strip(), "plain body")
        self.assertIsNone(got["html_text"])

    def test_html_only_message_gets_html_text(self):
        raw = build_message(
            {"Content-Type": "text/html; charset=utf-8"},
            "<html><body><script>alert(1)</script>"
            "<p>Hello <b>Bob</b></p></body></html>")
        got = mbox.parse_message(raw, 0)
        self.assertIsNone(got["text"])
        self.assertGreater(got["html_bytes"], 0)
        self.assertIn("Hello", got["html_text"])
        self.assertNotIn("alert", got["html_text"])
        self.assertNotIn("<", got["html_text"])

    def test_multipart_alternative_prefers_plain_text(self):
        body = ("--X\nContent-Type: text/plain\n\nplain part\n"
                "--X\nContent-Type: text/html\n\n<p>html part</p>\n--X--")
        raw = build_message(
            {"Content-Type": 'multipart/alternative; boundary="X"'}, body)
        got = mbox.parse_message(raw, 0)
        self.assertEqual(got["text"].strip(), "plain part")
        self.assertIsNone(got["html_text"])
        self.assertGreater(got["html_bytes"], 0)

    def test_message_with_neither_part_has_no_body_text(self):
        raw = build_message({"Content-Type": "application/octet-stream"}, "")
        got = mbox.parse_message(raw, 0)
        self.assertIsNone(got["text"])
        self.assertIsNone(got["html_text"])
        self.assertEqual(got["html_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
