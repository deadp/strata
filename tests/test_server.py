import unittest

from engine.server import FileRegion


class FakeFsWithRange:
    """A filesystem whose backend supports read_range() -- every real
    engine.fs.* implementation does."""

    def __init__(self, content):
        self.content = content
        self.read_file_calls = 0
        self.read_range_calls = []

    def read_file(self, entry, max_bytes=None, stream=""):
        self.read_file_calls += 1
        return self.content[:max_bytes] if max_bytes else self.content

    def read_range(self, entry, off, length, stream=""):
        self.read_range_calls.append((off, length))
        return self.content[off:off + length]


class FakeFsWithoutRange:
    """A filesystem with no read_range() -- FileRegion must fall back to
    read_file() rather than fail."""

    def __init__(self, content):
        self.content = content
        self.read_file_calls = 0

    def read_file(self, entry, max_bytes=None, stream=""):
        self.read_file_calls += 1
        return self.content[:max_bytes] if max_bytes else self.content


class FileRegionReadAt(unittest.TestCase):

    def test_uses_read_range_and_never_reads_the_whole_file(self):
        # The point of #78: a Range request must not read the whole file
        # from the image just to serve a small slice of it.
        content = bytes(range(256)) * 100  # 25,600 bytes
        fs = FakeFsWithRange(content)
        region = FileRegion(fs, {"name": "big.bin"}, len(content))
        got = region.read_at(1000, 64)
        self.assertEqual(got, content[1000:1064])
        self.assertEqual(fs.read_range_calls, [(1000, 64)])
        self.assertEqual(fs.read_file_calls, 0)

    def test_repeated_reads_each_seek_directly_rather_than_re_reading(self):
        content = bytes(range(256)) * 100
        fs = FakeFsWithRange(content)
        region = FileRegion(fs, {"name": "big.bin"}, len(content))
        for off in (0, 5000, 12000, 20000):
            region.read_at(off, 32)
        self.assertEqual(fs.read_file_calls, 0)
        self.assertEqual(len(fs.read_range_calls), 4)

    def test_small_file_without_read_range_is_cached_after_first_read(self):
        content = b"hello world" * 10
        fs = FakeFsWithoutRange(content)
        cache = {}
        r1 = FileRegion(fs, {"name": "small.txt"}, len(content), cache=cache)
        r2 = FileRegion(fs, {"name": "small.txt"}, len(content), cache=cache)
        self.assertEqual(r1.read_at(0, 5), content[0:5])
        self.assertEqual(r2.read_at(5, 5), content[5:10])
        # Both FileRegions share the session-scoped cache (as two separate
        # HTTP requests for the same file would), so the underlying file
        # is only actually read once.
        self.assertEqual(fs.read_file_calls, 1)

    def test_a_different_file_evicts_the_previous_ones_cache_entry(self):
        cache = {}
        fs_a = FakeFsWithoutRange(b"AAAA")
        fs_b = FakeFsWithoutRange(b"BBBB")
        FileRegion(fs_a, {"name": "a.txt"}, 4, cache=cache).read_at(0, 4)
        FileRegion(fs_b, {"name": "b.txt"}, 4, cache=cache).read_at(0, 4)
        self.assertEqual(fs_a.read_file_calls, 1)
        self.assertEqual(fs_b.read_file_calls, 1)
        # Re-reading "a" now has to hit the filesystem again -- a single-
        # entry cache, not unbounded growth across every file touched.
        FileRegion(fs_a, {"name": "a.txt"}, 4, cache=cache).read_at(0, 4)
        self.assertEqual(fs_a.read_file_calls, 2)

    def test_out_of_bounds_reads_return_nothing(self):
        fs = FakeFsWithRange(b"12345")
        region = FileRegion(fs, {"name": "f"}, 5)
        self.assertEqual(region.read_at(-1, 2), b"")
        self.assertEqual(region.read_at(5, 2), b"")
        self.assertEqual(region.read_at(0, 0), b"")

    def test_a_request_past_the_end_is_clamped_to_what_remains(self):
        fs = FakeFsWithRange(b"12345")
        region = FileRegion(fs, {"name": "f"}, 5)
        self.assertEqual(region.read_at(3, 100), b"45")
        self.assertEqual(fs.read_range_calls, [(3, 2)])


if __name__ == "__main__":
    unittest.main()
