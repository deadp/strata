"""A flat VMDK's extent must sit beside its descriptor (engine.vmdk).

The extent name comes from the descriptor, which is evidence. A name that
leads anywhere else must be refused before anything on that path is touched:
not read as the disk, and not even checked for existence, since doing that to
a network path already reaches the network.
"""

import builtins
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import vmdk                                           # noqa: E402

SECTORS = 4
CONTENT = bytes(range(256)) * 8                                   # 2048 bytes
SECRET = b"NOT PART OF ANY EXHIBIT " * 100


def descriptor(extent_name):
    return ('# Disk DescriptorFile\nversion=1\nCID=fffffffe\n'
            'parentCID=ffffffff\ncreateType="monolithicFlat"\n\n'
            '# Extent description\nRW %d FLAT "%s" 0\n\n'
            'ddb.adapterType = "ide"\n' % (SECTORS, extent_name))


def is_network(p):
    s = str(p)
    return s.startswith(("//", "\\\\"))


class Probe:
    """Records filesystem calls vmdk.py makes, never touching a network path."""

    def __init__(self, base):
        self.base = os.path.normcase(os.path.abspath(base))
        self.outside = []
        self._exists = os.path.exists
        self._getsize = os.path.getsize
        self._islink = os.path.islink
        self._open = builtins.open

    def _note(self, fn, p):
        full = os.path.normcase(os.path.abspath(str(p))) if not is_network(p) \
            else str(p)
        if is_network(p) or not full.startswith(self.base + os.sep):
            self.outside.append((fn, str(p)))
        return is_network(p)

    def exists(self, p):
        return False if self._note("exists", p) else self._exists(p)

    def getsize(self, p):
        if self._note("getsize", p):
            raise FileNotFoundError(p)
        return self._getsize(p)

    def islink(self, p):
        return False if self._note("islink", p) else self._islink(p)

    def open(self, p, *a, **k):
        if self._note("open", p):
            raise FileNotFoundError(p)
        return self._open(p, *a, **k)

    def __enter__(self):
        self._patches = [
            mock.patch.object(vmdk.os.path, "exists", self.exists),
            mock.patch.object(vmdk.os.path, "getsize", self.getsize),
            mock.patch.object(vmdk.os.path, "islink", self.islink),
            mock.patch.object(vmdk, "open", self.open, create=True),
        ]
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in reversed(self._patches):
            p.stop()


class ExtentPath(unittest.TestCase):

    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="strata-vmdk-")
        self.addCleanup(lambda: shutil.rmtree(self.work, ignore_errors=True))
        self.secret = os.path.join(self.work, "host-secret.txt")
        with open(self.secret, "wb") as fh:
            fh.write(SECRET)
        self.exhibit = os.path.join(self.work, "case", "exhibit")
        os.makedirs(self.exhibit)
        self.desc = os.path.join(self.exhibit, "disk.vmdk")

    def write_descriptor(self, extent_name):
        with open(self.desc, "w", newline="\n") as fh:
            fh.write(descriptor(extent_name))

    def open_image(self):
        img = vmdk.VmdkImage(self.desc)
        self.addCleanup(lambda: getattr(img, "_fh", None) and img._fh.close())
        return img

    def test_extent_beside_the_descriptor_still_reads(self):
        with open(os.path.join(self.exhibit, "disk-flat.vmdk"), "wb") as fh:
            fh.write(CONTENT)
        self.write_descriptor("disk-flat.vmdk")
        img = self.open_image()
        self.assertEqual(img.size, SECTORS * vmdk.SECTOR)
        self.assertEqual(img.read_at(0, len(CONTENT)), CONTENT)

    def assert_refused_untouched(self, extent_name):
        self.write_descriptor(extent_name)
        with Probe(self.exhibit) as probe:
            with self.assertRaises(vmdk.VmdkError) as caught:
                img = vmdk.VmdkImage(self.desc)
                self.addCleanup(img._fh.close)
        self.assertIn("did not follow", str(caught.exception))
        touched = [c for c in probe.outside
                   if os.path.normcase(c[1]) != os.path.normcase(self.desc)]
        self.assertEqual(touched, [], "touched paths outside the exhibit")

    def test_relative_path_out_of_the_folder(self):
        self.assert_refused_untouched(os.path.join("..", "..", "host-secret.txt"))

    def test_absolute_path(self):
        self.assert_refused_untouched(self.secret)

    def test_forward_slash_network_path(self):
        self.assert_refused_untouched("//203.0.113.7/share/disk-flat.vmdk")

    def test_backslash_network_path(self):
        self.assert_refused_untouched("\\\\203.0.113.7\\share\\disk-flat.vmdk")

    def test_subfolder(self):
        sub = os.path.join(self.exhibit, "sub")
        os.makedirs(sub)
        with open(os.path.join(sub, "disk-flat.vmdk"), "wb") as fh:
            fh.write(CONTENT)
        self.write_descriptor("sub/disk-flat.vmdk")
        with self.assertRaises(vmdk.VmdkError) as caught:
            vmdk.VmdkImage(self.desc)
        self.assertIn("did not follow", str(caught.exception))

    @unittest.skipUnless(os.name == "nt", "drive-relative names exist on Windows")
    def test_drive_relative_name(self):
        self.assert_refused_untouched("C:host-secret.txt")

    def test_symlink_beside_the_descriptor(self):
        link = os.path.join(self.exhibit, "disk-flat.vmdk")
        try:
            os.symlink(self.secret, link)
        except (OSError, NotImplementedError):
            self.skipTest("cannot create symlinks here")
        self.write_descriptor("disk-flat.vmdk")
        with self.assertRaises(vmdk.VmdkError) as caught:
            vmdk.VmdkImage(self.desc)
        self.assertIn("did not follow", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
