"""Unit tests for LUKS volume handling (engine.luks): LUKS2 with Argon2
keyslots, LUKS2 with PBKDF2 keyslots, backup-header fallback, clean
refusals, and the LUKS1 regression path, fed images from
imagebuild_luks.  Argon2 correctness itself is pinned by the RFC 9106
section 5 test vectors."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import imagebuild_luks as build                     # noqa: E402
from engine.crypto import argon2                    # noqa: E402
from engine.crypto.argon2 import derive             # noqa: E402
from engine.crypto.argon2 import OutOfMemory          # noqa: E402
from engine.luks import Luks                        # noqa: E402

PW = "correct horse"
BAD_PW = "wrong horse"


class MemSource:
    def __init__(self, data):
        self.data = data

    def read_at(self, offset, size):
        return self.data[offset:offset + size]


class RfcVectors(unittest.TestCase):
    """RFC 9106 section 5 tags (32 KiB, t=3, p=4, secret, ad)."""

    VECTORS = {
        "argon2d": "512b391b6f1162975371d30919734294"
                   "f868e3be3984f3c1a13a4db9fabe4acb",
        "argon2i": "c814d9d1dc7f37aa13f0d77f2494bda1"
                   "c8de6b016dd388d29952a4c4672b6ce8",
        "argon2id": "0d640df58d78766c08c037a34a8b53c9"
                    "d01ef0452d75b65eb52520e96b01e659",
    }

    def test_rfc_9106_section_5(self):
        for kind, want in self.VECTORS.items():
            with self.subTest(kind=kind):
                got = derive(b"\x01" * 32, b"\x02" * 16, t=3, m_kib=32,
                             p=4, out_len=32, kind=kind, version=0x13,
                             secret=b"\x03" * 8, associated=b"\x04" * 12)
                self.assertEqual(got.hex(), want)


class Luks2Argon2id(unittest.TestCase):
    def setUp(self):
        self.blob, self.mk = build.build_luks2(PW)

    def open(self, blob=None):
        return Luks(MemSource(self.blob if blob is None else blob),
                    len(self.blob if blob is None else blob))

    def test_unlock_roundtrip(self):
        vol = self.open()
        res = vol.unlock(PW)
        self.assertTrue(res["unlocked"])
        self.assertEqual(res["slot"], 0)
        self.assertTrue(res["verified"])
        self.assertEqual(vol.master_key, self.mk)
        self.assertEqual(vol.read(0, 23), b"STRATA-LUKS2-PLAINTEXT-")

    def test_wrong_password_refused(self):
        vol = self.open()
        res = vol.unlock(BAD_PW)
        self.assertFalse(res["unlocked"])
        self.assertIsNone(vol.master_key)

    def test_bytes_password_matches_str(self):
        vol = self.open()
        res = vol.unlock(PW.encode("utf-8"))
        self.assertTrue(res["unlocked"])

    def test_slot_cache_hits(self):
        import engine.luks as luks_mod
        vol = self.open()
        calls = []
        real = argon2.derive

        def spy(password, salt, **kwargs):
            calls.append(1)
            return real(password, salt, **kwargs)

        try:
            luks_mod.argon2.derive = spy
            self.assertTrue(vol.unlock(PW)["unlocked"])
            self.assertEqual(len(calls), 1)
            self.assertTrue(vol.unlock(PW)["unlocked"])
            self.assertEqual(len(calls), 1)      # served from cache
            self.assertTrue(vol.unlock(BAD_PW)["unlocked"] is False)
            self.assertEqual(len(calls), 2)      # wrong pw derived once
        finally:
            luks_mod.argon2.derive = real

    def test_progress_is_per_slot_scaled(self):
        vol = self.open()
        frames = []
        self.assertTrue(vol.unlock(PW, progress=frames.append)["unlocked"])
        self.assertEqual(frames[0], 0.0)
        self.assertEqual(frames[-1], 1.0)
        self.assertTrue(all(a < b for a, b in zip(frames, frames[1:])))

    def test_out_of_memory_refused_cleanly(self):
        import engine.luks as luks_mod
        vol = self.open()
        real = argon2.derive

        def boom(password, salt, **kwargs):
            raise OutOfMemory("cannot allocate 2097152 KiB for Argon2")

        try:
            luks_mod.argon2.derive = boom
            res = vol.unlock(PW)
        finally:
            luks_mod.argon2.derive = real
        self.assertFalse(res["unlocked"])
        self.assertIn("cannot allocate", res["reason"])


class Luks2Pbkdf2(unittest.TestCase):
    def test_pbkdf2_slot_unlocks(self):
        blob, mk = build.build_luks2(PW, kdf="pbkdf2")
        vol = Luks(MemSource(blob), len(blob))
        res = vol.unlock(PW)
        self.assertTrue(res["unlocked"])
        self.assertEqual(vol.master_key, mk)
        self.assertEqual(vol.read(0, 23), b"STRATA-LUKS2-PLAINTEXT-")
        res = vol.unlock(BAD_PW)
        self.assertFalse(res["unlocked"])


class Luks1Regression(unittest.TestCase):
    def test_luks1_unlock_roundtrip(self):
        blob, mk = build.build_luks1(PW)
        vol = Luks(MemSource(blob), len(blob))
        self.assertEqual(vol.version, 1)
        res = vol.unlock(PW)
        self.assertTrue(res["unlocked"])
        self.assertEqual(vol.master_key, mk)
        self.assertEqual(vol.read(0, 23), b"STRATA-LUKS1-PLAINTEXT-")
        res = vol.unlock(BAD_PW)
        self.assertFalse(res["unlocked"])


class MalformedHeaders(unittest.TestCase):
    def setUp(self):
        self.blob, _ = build.build_luks2(PW)

    def test_truncated_primary_uses_backup(self):
        blob = bytearray(self.blob)
        blob[4096:4200] = b"\x00" * 104
        vol = Luks(MemSource(bytes(blob)), len(blob))
        self.assertTrue(vol.unlock(PW)["unlocked"])
        self.assertTrue(any("backup" in f.lower() for f in vol.findings))

    def test_both_headers_corrupt_refused(self):
        blob = bytearray(self.blob)
        blob[4096:4256] = b"\x00" * 160          # primary JSON
        blob[8192:8256] = b"\x00" * 64           # backup binary header
        blob[8192 + 4096:8192 + 4256] = b"\x00" * 160   # backup JSON
        vol = Luks(MemSource(bytes(blob)), len(blob))
        res = vol.unlock(PW)
        self.assertFalse(res["unlocked"])
        self.assertFalse(vol.info()["valid"])

    def test_unknown_kdf_refused_with_finding(self):
        vol = Luks(MemSource(self.blob), len(self.blob))
        vol.slots[0].kdf_type = "yescrypt"
        res = vol.unlock(PW)
        self.assertFalse(res["unlocked"])
        self.assertTrue(any("yescrypt" in f for f in vol.findings))

    def test_key_material_outside_image_refused(self):
        vol = Luks(MemSource(self.blob), len(self.blob))
        vol.slots[0].area["offset"] = len(self.blob) * 2
        res = vol.unlock(PW)
        self.assertFalse(res["unlocked"])
        self.assertIn("outside the image", res["reason"])


if __name__ == "__main__":
    unittest.main()