"""Tests for legacy Office body text (engine.officedoc): the Word .doc
piece table, Excel .xls BIFF8 cell records, and PowerPoint .ppt slide
text atoms, fed images from imagebuild_office. The fixtures exist to be
read by this module only; malformed variants assert the proven-only
contract — a finding plus whatever text survives, never guessed bytes,
and the properties (metadata) always present."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests import imagebuild_office as ib                                # noqa: E402
from engine import ole2, officedoc                                       # noqa: E402

WORD_TEXT = "First compressed piece. Second uncompressed pièce. "


def parse(data, name):
    return officedoc.parse_ole2_document(data, name)


def rewrap(streams):
    """Rebuild a CFB around already-decoded streams (padded to the
    4096-byte floor the builder promises)."""
    out = []
    for name, data in streams:
        data = bytes(data)
        if len(data) < 4096:
            data += b"\x00" * (4096 - len(data))
        out.append((name, data))
    return ib.build_cfb(out)


class WordPieceTable(unittest.TestCase):
    """Text via the Clx piece table in the table stream ([MS-DOC])."""

    def test_decodes_compressed_and_utf16_pieces_in_order(self):
        res = parse(ib.build_doc(), "t.doc")
        self.assertEqual(res["kind"], "Word document (legacy .doc)")
        self.assertEqual(res["family"], "ole2")
        self.assertEqual(res["text"],
                         ib.FIB_TEXT_PIECES_A + ib.FIB_TEXT_PIECES_U)
        self.assertEqual(res["sections"],
                         [{"name": "document", "text": res["text"]}])
        self.assertEqual(res["characters"], len(res["text"]))
        self.assertEqual(res["findings"], [])
        self.assertEqual(res["note"],
                         "Document properties are written by the application "
                         "from whatever it was told and can be edited "
                         "afterwards. They are a record of what the file "
                         "claims, not of what happened.")

    def test_reads_the_table_stream_the_fib_names(self):
        # fWhichTblStm bit clear -> 0table. The piece table must be found
        # there, not in the 1table the default fixture writes.
        res = parse(ib.build_doc(table_stream="0table"), "t.doc")
        self.assertEqual(res["text"],
                         ib.FIB_TEXT_PIECES_A + ib.FIB_TEXT_PIECES_U)
        self.assertEqual(res["findings"], [])

    def test_carriage_returns_become_newlines(self):
        # \r (paragraph mark) and \x07 (cell/row mark) both become \n.
        # One piece keeps the byte offset arithmetic trivial.
        res = parse(ib.build_doc([("alpha\r beta\x07gamma", True)]), "t.doc")
        self.assertEqual(res["text"], "alpha\n beta\ngamma")

    def test_piece_pointing_outside_the_stream_is_dropped_with_a_finding(self):
        doc_bytes = ib.build_doc([("alpha ", True), ("beta", False)])
        o = ole2.Ole2(doc_bytes, "t.doc")
        wd = bytearray(o.read("WordDocument"))
        tbl = bytearray(o.read("1table"))
        plc = bytearray(tbl[5:5 + 0x1C])
        struct.pack_into("<HI", plc, 20, 0, 0x40000000 | 0x0FFFFFFF)
        tbl[5:5 + 0x1C] = plc
        res = parse(rewrap([("WordDocument", wd), ("1table", tbl)]), "t.doc")
        self.assertEqual(res["text"], "alpha ")
        self.assertEqual(res["findings"],
                         ["Word document (legacy .doc): piece 1 points "
                          "outside the WordDocument stream; it was "
                          "skipped."])
        self.assertIsInstance(res["metadata"], dict)

    def test_piece_beyond_the_2gb_limit_is_dropped_with_a_finding(self):
        doc_bytes = ib.build_doc([("alpha ", True), ("beta", False)])
        o = ole2.Ole2(doc_bytes, "t.doc")
        wd = bytearray(o.read("WordDocument"))
        tbl = bytearray(o.read("1table"))
        plc = bytearray(tbl[5:5 + 0x1C])
        struct.pack_into("<HI", plc, 20, 0, 0x80000000 | 0x123)
        tbl[5:5 + 0x1C] = plc
        res = parse(rewrap([("WordDocument", wd), ("1table", tbl)]), "t.doc")
        self.assertEqual(res["text"], "alpha ")
        self.assertEqual(res["findings"],
                         ["Word document (legacy .doc): piece 1 points past "
                          "the 2 GB text limit; it was skipped."])

    def test_corrupt_clx_yields_no_text_and_a_finding(self):
        res = parse(ib.build_doc(corrupt_clx=True), "t.doc")
        self.assertEqual(res["text"], "")
        self.assertEqual(res["findings"],
                         ["Word document (legacy .doc): the piece table's "
                          "size does not match its structure; no text was "
                          "read."])
        self.assertIsInstance(res["metadata"], dict)

    def test_missing_pcdt_yields_no_text_and_a_finding(self):
        res = parse(ib.build_doc(drop_pcdt=True), "t.doc")
        self.assertEqual(res["text"], "")
        self.assertEqual(res["findings"],
                         ["Word document (legacy .doc): the Clx holds no "
                          "piece table descriptor (Pcdt); no text was "
                          "read."])

    def test_nonmonotonic_character_positions_are_rejected(self):
        res = parse(ib.build_doc(nonmonotonic=True), "t.doc")
        self.assertEqual(res["text"], "")
        self.assertEqual(res["findings"],
                         ["Word document (legacy .doc): the piece table's "
                          "character positions are not strictly increasing; "
                          "no text was read."])


class XlsCellRecords(unittest.TestCase):
    """Text via the SST and per-sheet BIFF8 cell records ([MS-XLS])."""

    SHEETS = [
        ("Prices", [("s", 0, 0, "Item"), ("s", 0, 1, "Cost"),
                    ("s", 1, 0, "Hammer"), ("n", 1, 1, 42),
                    ("s", 2, 0, "pi"), ("n", 2, 1, 7)]),
        ("Grid", [("n", 0, 0, 8), ("n", 0, 1, 9)]),
    ]

    def test_reads_sheets_cells_and_numbers(self):
        res = parse(ib.build_xls(self.SHEETS), "t.xls")
        self.assertEqual(res["kind"], "Excel workbook (legacy .xls)")
        self.assertEqual(res["text"],
                         "Prices\nItem\tCost\nHammer\t42\npi\t7\n"
                         "Grid\n8\t9")
        self.assertEqual(res["sections"],
                         [{"name": "workbook", "text": res["text"]}])
        self.assertEqual(res["findings"], [])
        self.assertIsInstance(res["metadata"], dict)

    def test_unicode_strings_survive(self):
        sheets = [("S", [("s", 0, 0, "pi\u00e8ce"), ("n", 1, 0, 2)])]
        res = parse(ib.build_xls(sheets), "t.xls")
        self.assertEqual(res["text"], "S\npi\u00e8ce\n2")

    def test_sst_index_past_the_end_gives_an_empty_cell(self):
        base = ole2.Ole2(ib.build_xls(
            [("S", [("s", 0, 0, "alpha"), ("s", 0, 1, "beta")])]), "t.xls")
        wb = bytearray(base.read("Workbook"))
        # SST body starts at 24 (cstTotal, cstUnique); raise cstUnique
        # past the strings the record actually holds.
        struct.pack_into("<I", wb, 28, 99)
        res = parse(rewrap([("Workbook", wb)]), "t.xls")
        self.assertEqual(res["findings"],
                         ["Excel workbook (legacy .xls): the shared-string "
                          "table names more strings than it holds; the rest "
                          "read as empty."])
        self.assertEqual(res["text"], "S\nalpha\tbeta")

    def test_record_running_past_the_stream_stops_parsing(self):
        base = ole2.Ole2(ib.build_xls(
            [("S", [("s", 0, 0, "alpha"), ("s", 0, 1, "beta")])]), "t.xls")
        wb = bytearray(base.read("Workbook"))
        # inflate the sheet substream's EOF (the last record in the
        # stream) so it claims past the stream end
        at, last = 0, None
        while at + 4 <= len(wb):
            rid, rlen = struct.unpack_from("<HH", wb, at)
            if rid == 0x000A:
                last = at
            if at + 4 + rlen > len(wb):
                break
            at += 4 + rlen
        at = last
        struct.pack_into("<H", wb, at + 2, 0xFFFF)
        res = parse(rewrap([("Workbook", wb)]), "t.xls")
        self.assertIn("Excel workbook (legacy .xls): the record stream is "
                      "cut short inside a record; parsing stops here.",
                      res["findings"])
        self.assertIn("Excel workbook (legacy .xls): sheet 0's record "
                      "stream is cut short; parsing stops here.",
                      res["findings"])

    def test_boundsheet_offset_outside_the_stream_is_skipped(self):
        base = ole2.Ole2(ib.build_xls(
            [("S", [("s", 0, 0, "alpha")])]), "t.xls")
        wb = bytearray(base.read("Workbook"))
        at = 20
        while struct.unpack_from("<H", wb, at)[0] != 0x0085:
            at += 4 + struct.unpack_from("<HH", wb, at)[1]
        struct.pack_into("<I", wb, at + 4, 0xFFFFFF)
        res = parse(rewrap([("Workbook", wb)]), "t.xls")
        self.assertEqual(res["text"], "")
        self.assertEqual(res["findings"],
                         ["Excel workbook (legacy .xls): sheet 0 starts "
                          "outside the workbook stream; it was skipped."])
        self.assertIsInstance(res["metadata"], dict)

    def test_sheet_not_starting_at_a_bof_is_skipped(self):
        base = ole2.Ole2(ib.build_xls(
            [("S", [("s", 0, 0, "alpha")])]), "t.xls")
        wb = bytearray(base.read("Workbook"))
        at = 20
        while struct.unpack_from("<HH", wb, at)[0] != 0x0085:
            at += 4 + struct.unpack_from("<HH", wb, at)[1]
        struct.pack_into("<I", wb, at + 4, 20)   # point at the SST record
        res = parse(rewrap([("Workbook", wb)]), "t.xls")
        self.assertEqual(res["text"], "")
        self.assertEqual(res["findings"],
                         ["Excel workbook (legacy .xls): sheet 0 does not "
                          "start at a BOF record; it was skipped."])


class PptSlideText(unittest.TestCase):
    """Text via the UserEdit chain, persist directories and slide text
    atoms ([MS-PPT]); newest-wins persist semantics."""

    SLIDES = [["Hello title.", "Body text here."],
              ["Second slide", "caf\u00e9 utf16"]]

    def setUp(self):
        self.raw = ib.build_ppt(self.SLIDES)

    def doc_and_user(self, data=None):
        o = ole2.Ole2(data if data is not None else self.raw, "t.ppt")
        return o.read("PowerPoint Document"), o.read("Current User")

    def test_reads_the_newest_edit_only(self):
        res = parse(self.raw, "t.ppt")
        self.assertEqual(res["kind"],
                         "PowerPoint presentation (legacy .ppt)")
        self.assertEqual(res["text"],
                         "Hello title.\nBody text here.\n\n"
                         "Second slide\ncaf\u00e9 utf16")
        self.assertEqual(res["sections"],
                         [{"name": "slides", "text": res["text"]}])
        self.assertEqual(res["findings"], [])
        self.assertNotIn("Outdated stale text.", res["text"])
        self.assertIsInstance(res["metadata"], dict)

    def test_unicode_runs_decode_as_utf16(self):
        res = parse(ib.build_ppt([["pi\u00e8ce unicode", "Body B."]]), "t.ppt")
        self.assertEqual(res["text"], "pi\u00e8ce unicode\nBody B.")
        self.assertEqual(res["findings"], [])

    def test_current_user_offset_outside_the_stream(self):
        doc, cu = self.doc_and_user(self.raw)
        cu = bytearray(cu)
        struct.pack_into("<I", cu, 16, 0xFFFF00)
        res = parse(ib.build_cfb([("PowerPoint Document", doc),
                                  ("Current User", bytes(cu))]), "t.ppt")
        self.assertEqual(res["text"], "")
        self.assertEqual(res["findings"],
                         ["PowerPoint presentation (legacy .ppt): the "
                          "Current User stream does not point at a "
                          "UserEditAtom inside the PowerPoint stream; no "
                          "text was read."])
        self.assertIsInstance(res["metadata"], dict)

    def test_current_user_stream_too_short(self):
        # build_cfb floors streams at 4096 bytes, so a genuinely short
        # Current User stream is exercised on the extractor directly.
        doc, _cu = self.doc_and_user(self.raw)
        findings = []
        text = officedoc._ppt_body(doc, b"\x00\x01\x02", findings,
                                   "PowerPoint presentation (legacy .ppt)")
        self.assertEqual(text, "")
        self.assertEqual(findings,
                         ["PowerPoint presentation (legacy .ppt): the "
                          "Current User stream is too short to hold a "
                          "CurrentUserAtom; no text was read."])

    def test_persist_directory_not_reachable(self):
        doc, cu = self.doc_and_user(self.raw)
        doc = bytearray(doc)
        # the newest UserEditAtom's persist-pointer offset -> outside
        struct.pack_into("<I", doc, 0x1CD + 20, 0xFFFF00)
        res = parse(rewrap([("PowerPoint Document", doc),
                            ("Current User", cu)]), "t.ppt")
        self.assertEqual(res["text"], "")
        self.assertEqual(res["findings"],
                         ["PowerPoint presentation (legacy .ppt): a persist "
                          "directory sits outside the PowerPoint stream; "
                          "the remaining edits were skipped.",
                          "PowerPoint presentation (legacy .ppt): no persist "
                          "directory could be read; no text was read."])

    def test_persist_record_outside_the_stream_is_skipped(self):
        doc, cu = self.doc_and_user(self.raw)
        doc = bytearray(doc)
        # newest directory maps persist id 2 (the second offset after
        # the info u32) -> offset 0, outside any record
        struct.pack_into("<I", doc, 0x199 + 4 + 4, 0)
        res = parse(rewrap([("PowerPoint Document", doc),
                            ("Current User", cu)]), "t.ppt")
        # the stale slide at offset 0 is not proven to be the right one;
        # its record is skipped, the other slide survives.
        self.assertEqual(res["text"], "Second slide\ncaf\u00e9 utf16")
        self.assertEqual(res["findings"],
                         ["PowerPoint presentation (legacy .ppt): a persist "
                          "record sits outside the PowerPoint stream; it "
                          "was skipped."])
        self.assertNotIn("Outdated stale text.", res["text"])

    def test_slide_container_overrun_keeps_the_proven_prefix(self):
        doc, cu = self.doc_and_user(self.raw)
        doc = bytearray(doc)
        # slide 1's record length shrunk so its children run past it
        struct.pack_into("<I", doc, 0x8C + 4, 60)
        res = parse(rewrap([("PowerPoint Document", doc),
                            ("Current User", cu)]), "t.ppt")
        self.assertEqual(res["text"], "Second slide\ncaf\u00e9 utf16")
        self.assertEqual(res["findings"],
                         ["PowerPoint presentation (legacy .ppt): a nested "
                          "record runs past its parent container; the rest "
                          "of the slide was skipped."])
        self.assertNotIn("Hello title.", res["text"])

    def test_text_run_overrun_yields_no_garbage_bytes(self):
        doc, cu = self.doc_and_user(self.raw)
        doc = bytearray(doc)
        # slide 1's TextBytesAtom claims 200 bytes, past the slide's end
        struct.pack_into("<I", doc, 0xD4, 200)
        res = parse(rewrap([("PowerPoint Document", doc),
                            ("Current User", cu)]), "t.ppt")
        self.assertEqual(res["text"], "Second slide\ncaf\u00e9 utf16")
        self.assertEqual(res["findings"],
                         ["PowerPoint presentation (legacy .ppt): a byte "
                          "text run is cut short; it was skipped.",
                          "PowerPoint presentation (legacy .ppt): a nested "
                          "record runs past its parent container; the rest "
                          "of the slide was skipped."])
        self.assertNotIn("\x9f\x0f", res["text"])

    def test_self_referential_edit_history_keeps_proven_slides(self):
        doc, cu = self.doc_and_user(self.raw)
        doc = bytearray(doc)
        # newest UserEditAtom's prev pointer loops back to itself
        struct.pack_into("<I", doc, 0x1CD + 16, 0x1CD)
        res = parse(rewrap([("PowerPoint Document", doc),
                            ("Current User", cu)]), "t.ppt")
        self.assertEqual(res["text"],
                         "Hello title.\nBody text here.\n\n"
                         "Second slide\ncaf\u00e9 utf16")
        self.assertEqual(res["findings"],
                         ["PowerPoint presentation (legacy .ppt): the edit "
                          "history is cut short; the remaining edits were "
                          "skipped."])


class Ole2Framing(unittest.TestCase):
    """Kind selection, notes, and the raw-bytes entry contract."""

    def test_generic_compound_document_keeps_the_old_note(self):
        plain = ib.build_cfb([("SomeStream", b"\x00" * 4096)])
        res = parse(plain, "t")
        self.assertEqual(res["kind"], "OLE2 compound document")
        self.assertEqual(res["text"], "")
        self.assertEqual(res["sections"], [])
        self.assertEqual(res["note"],
                         "The body of a legacy Office document is a binary "
                         "format of its own \u2014 Word's piece table, "
                         "Excel's BIFF record stream \u2014 and is not "
                         "decoded here, so no text is offered rather than "
                         "text that might be wrong. The properties below "
                         "are from the document's own property set: they "
                         "are written by the application from whatever it "
                         "was told and can be edited.")

    def test_msg_kind_keeps_the_old_note(self):
        res = parse(ib.build_cfb(
            [("__properties_version1.0", b"\x00" * 4096)]), "m.msg")
        self.assertEqual(res["kind"], "Outlook message (.msg)")
        self.assertEqual(res["text"], "")
        self.assertTrue(res["note"].startswith(
            "The body of a legacy Office document"))

    def test_non_ole2_input_returns_none(self):
        self.assertIsNone(parse(b"not an ole2 file at all", "x"))

    def test_word_beats_other_kinds_when_streams_coexist(self):
        data = ib.build_cfb([
            ("WordDocument", b"\x00" * 4096),
            ("Workbook", b"\x00" * 4096),
            ("PowerPoint Document", b"\x00" * 4096)])
        res = parse(data, "t")
        self.assertEqual(res["kind"], "Word document (legacy .doc)")


if __name__ == "__main__":
    unittest.main()