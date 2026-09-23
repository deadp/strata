import unittest

from engine import pst
from tests import imagebuild_pst as build


class PstAttachments(unittest.TestCase):

    def setUp(self):
        raw, self.node, self.nids = build.build_pst()
        self.pst = pst.open_pst(raw)
        self.assertIsNotNone(self.pst)

    def test_attachments_lists_the_nid_and_content_type(self):
        atts = self.pst.attachments(self.node)
        self.assertEqual(len(atts), 1)
        att = atts[0]
        self.assertEqual(att["nid"], self.nids[0])
        self.assertEqual(att["name"], build.ATTACHMENT_NAME)
        self.assertEqual(att["size"], len(build.ATTACHMENT_BYTES))
        self.assertEqual(att["content_type"], build.ATTACHMENT_MIME)

    def test_attachment_bytes_returns_the_exact_content(self):
        data = self.pst.attachment_bytes(self.node, self.nids[0])
        self.assertEqual(data, build.ATTACHMENT_BYTES)

    def test_attachment_bytes_is_none_for_an_id_not_in_this_message(self):
        data = self.pst.attachment_bytes(
            self.node, build.MISSING_ATTACHMENT_NID)
        self.assertIsNone(data)

    def test_attachment_bytes_rejects_a_non_attachment_nid(self):
        # A nid that resolves in the subnode tree but isn't an attachment
        # (wrong low 5 bits) must not be treated as one.
        folder_like_nid = (self.nids[0] & ~0x1F) | 0x02
        data = self.pst.attachment_bytes(self.node, folder_like_nid)
        self.assertIsNone(data)

    def test_attachments_are_reachable_through_a_real_nbt_lookup(self):
        # attachments()/attachment_bytes() are exercised above against a
        # hand-built node dict; the server endpoint instead resolves the
        # message through Pst.nbt(), so confirm that path resolves to the
        # same subnode tree and attachment.
        node = self.pst.nbt().get(build.MESSAGE_NID)
        self.assertIsNotNone(node)
        self.assertEqual(node["sub"], self.node["sub"])
        atts = self.pst.attachments(node)
        self.assertEqual(atts[0]["nid"], self.nids[0])
        self.assertEqual(self.pst.attachment_bytes(node, self.nids[0]),
                         build.ATTACHMENT_BYTES)

    def test_multiple_attachments_are_each_independently_addressable(self):
        raw, node, nids = build.build_pst(attachment_count=2)
        p = pst.open_pst(raw)
        atts = p.attachments(node)
        self.assertEqual(len(atts), 2)
        self.assertEqual({a["nid"] for a in atts}, set(nids))
        for nid in nids:
            self.assertEqual(p.attachment_bytes(node, nid),
                             build.ATTACHMENT_BYTES)


if __name__ == "__main__":
    unittest.main()
