"""Build synthetic LUKS volumes in memory for tests.

Standard library only.  The LUKS2 fixture mirrors what cryptsetup writes:
a 4 KiB binary header, a JSON metadata area, a keyslot area holding the
AF-split master key encrypted with a KDF-derived key (AES-XTS), and a
payload encrypted with the master key.  Parameters are kept small
(af stripes=16, m_kib=64, t=1) so the suite stays fast; the JSON records
the values actually used, exactly as cryptsetup would.

`build_luks2` calls `engine.crypto.argon2.derive` directly, so the
fixture exercises the same code the unlock path runs.
"""

import base64
import hashlib
import json
import struct

MAGIC = b"LUKS\xba\xbe"
SECTOR = 512
BINARY_HDR = 4096
JSON_HDR = 4096
HDR_SIZE = BINARY_HDR + JSON_HDR
SLOT_AREA_OFFSET = 32 * 1024
STRIPES = 16
UUID = "5f3a3cb0-7b6e-4f2a-9e5c-1d2b3a4c5d6e"
DIGEST_ITER = 1000
AREA_KEY_BITS = 512          # 512-bit XTS area key (2 x AES-256)
KEY_BYTES = 32               # master key (volume key) length


def _b64(data):
    return base64.b64encode(data).decode("ascii")


def _xts(key, sector, data, decrypt=False):
    from engine.crypto import aes as aes_mod
    half = len(key) // 2
    c1 = aes_mod.AES(key[:half])
    c2 = aes_mod.AES(key[half:])
    if decrypt:
        return aes_mod.xts_decrypt(c1, c2, sector, data)
    tweak = c2.encrypt_block(struct.pack("<Q", sector) + b"\x00" * 8)
    out = bytearray()
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        out += bytes(x ^ y for x, y in zip(
            c1.encrypt_block(bytes(x ^ y for x, y in zip(blk, tweak))),
            tweak))
        tweak = aes_mod._gf_mul_alpha(tweak)
    return bytes(out)


def _xts_encrypt(key, sector, data):
    return _xts(key, sector, data)


def _af_split(mk, stripes):
    """Inverse of engine.luks.af_merge.

    af_merge folds stripes 0..n-2 through diffuse and XORs the last
    stripe raw.  Zero stripes keep the chain deterministic, and the
    last stripe carries chain ^ master key, so merging the split
    returns the master key exactly.
    """
    from engine.luks import _diffuse
    bs = len(mk)
    zero = bytes(bs)
    d = zero
    for _ in range(stripes - 1):
        d = _diffuse(d, bs, "sha256")
    last = bytes(x ^ y for x, y in zip(d, mk))
    return (zero * (stripes - 1)) + last


def _metadata(kdf_fields, salt, mk_digest_b64, d_salt_b64, area_size):
    slot_id = "0"
    return {
        "keyslots": {
            slot_id: {
                "type": "luks2",
                "key_size": KEY_BYTES,
                "af": {"type": "luks1", "stripes": STRIPES,
                       "hash": "sha256"},
                "area": {"type": "raw", "offset": SLOT_AREA_OFFSET,
                         "size": area_size,
                         "encryption": "aes-xts-plain64",
                         "key_size": AREA_KEY_BITS},
                "kdf": dict(kdf_fields, salt=_b64(salt)),
            },
        },
        "digests": {
            "pbkdf2": {
                "type": "pbkdf2",
                "keyslots": [slot_id],
                "hash": "sha256",
                "iterations": DIGEST_ITER,
                "salt": d_salt_b64,
                "digest": mk_digest_b64,
            },
        },
        "segments": {
            "0": {
                "type": "crypt",
                "offset": str(SLOT_AREA_OFFSET + area_size),
                "size": "dynamic",
                "iv_tweak": "0",
                "encryption": "aes-xts-plain64",
                "sector_size": SECTOR,
            },
        },
    }


def build_luks2(password, kdf="argon2id", t=1, m_kib=64, p=1,
                payload_sectors=64, corrupt_primary_json=False,
                no_backup=False):
    """Return (image_bytes, master_key) for a LUKS2 volume with one
    active keyslot using `kdf`.  With `corrupt_primary_json` the primary
    metadata area is garbage; the backup copy (offset HDR_SIZE) holds
    the real JSON unless `no_backup` is also set."""
    from engine.crypto import argon2
    if isinstance(password, str):
        password = password.encode("utf-8")
    mk = hashlib.sha256(b"strata-luks2-mk:" + password).digest()
    if kdf == "pbkdf2":
        kdf_fields = {"type": "pbkdf2", "iterations": 1000,
                      "hash": "sha256"}
    else:
        kdf_fields = {"type": kdf, "time": t, "memory": m_kib, "cpus": p}
    salt = b"slot-salt-16b".ljust(16, b"0")
    area_size = (KEY_BYTES * STRIPES + SECTOR - 1) // SECTOR * SECTOR

    key_len = AREA_KEY_BITS // 8
    if kdf == "pbkdf2":
        slot_key = hashlib.pbkdf2_hmac("sha256", password, salt,
                                       1000, key_len)
    else:
        slot_key = argon2.derive(password, salt, t=t, m_kib=m_kib, p=p,
                                 out_len=key_len, kind=kdf)

    d_salt = b"digest-salt-16b".ljust(16, b"0")
    mk_digest = hashlib.pbkdf2_hmac("sha256", mk, d_salt, DIGEST_ITER, 32)
    meta = _metadata(kdf_fields, salt, _b64(mk_digest), _b64(d_salt),
                     area_size)

    material = _af_split(mk, STRIPES)
    material += bytes(area_size - len(material))
    enc_area = b"".join(
        _xts_encrypt(slot_key, (SLOT_AREA_OFFSET + i) // SECTOR,
                     material[i:i + SECTOR])
        for i in range(0, len(material), SECTOR))

    payload_offset = SLOT_AREA_OFFSET + area_size
    payload_plain = (b"STRATA-LUKS2-PLAINTEXT-" * 64)[:payload_sectors
                                                      * SECTOR]
    xts_mk = mk  # segment key: 32-byte volume key -> 2 x AES-128
    payload = b"".join(
        _xts_encrypt(xts_mk, i // SECTOR, payload_plain[i:i + SECTOR])
        for i in range(0, len(payload_plain), SECTOR))

    good = json.dumps(meta, sort_keys=True).encode("utf-8")
    bin_hdr = bytearray(BINARY_HDR)
    bin_hdr[0:6] = MAGIC
    struct.pack_into(">H", bin_hdr, 6, 2)
    struct.pack_into(">Q", bin_hdr, 8, HDR_SIZE)
    bin_hdr[168:208] = UUID.encode("ascii").ljust(40, b"\x00")

    primary = good
    if corrupt_primary_json:
        primary = b"not-json\x00" + bytes(64)
    backup = good if not no_backup else b"also-bad\x00" + bytes(64)

    blob = bytearray(payload_offset + len(payload))
    blob[0:BINARY_HDR] = bin_hdr
    blob[BINARY_HDR:BINARY_HDR + len(primary)] = primary
    blob[HDR_SIZE:HDR_SIZE + BINARY_HDR] = bin_hdr
    blob[HDR_SIZE + BINARY_HDR:HDR_SIZE + BINARY_HDR + len(backup)] = (
        backup)
    blob[SLOT_AREA_OFFSET:SLOT_AREA_OFFSET + len(enc_area)] = enc_area
    blob[payload_offset:payload_offset + len(payload)] = payload
    return bytes(blob), mk


def build_luks1(password, payload_sectors=64):
    """Return (image_bytes, master_key) for a minimal LUKS1 volume."""
    if isinstance(password, str):
        password = password.encode("utf-8")
    mk = hashlib.sha256(b"strata-luks1-mk:" + password).digest()
    mk_salt = b"mk-salt-32-chars".ljust(32, b"0")
    mk_iter = 1000
    mk_digest = hashlib.pbkdf2_hmac("sha256", mk, mk_salt, mk_iter, 20)
    salt = b"slot-salt-32-chars-pad".ljust(32, b"0")
    iterations = 1000
    stripes = 16
    key_material_offset = 4096 // SECTOR        # sector 8
    pk = hashlib.pbkdf2_hmac("sha256", password, salt, iterations,
                             KEY_BYTES)
    material = _af_split(mk, stripes)
    enc = b"".join(
        _xts_encrypt(pk, i // SECTOR, material[i:i + SECTOR])
        for i in range(0, len(material), SECTOR))
    payload_sector = (4096 + len(enc)) // SECTOR
    payload_plain = (b"STRATA-LUKS1-PLAINTEXT-" * 64)[:payload_sectors
                                                      * SECTOR]
    payload = b"".join(
        _xts_encrypt(mk, i // SECTOR, payload_plain[i:i + SECTOR])
        for i in range(0, len(payload_plain), SECTOR))

    hdr = bytearray(592)
    hdr[0:6] = MAGIC
    struct.pack_into(">H", hdr, 6, 1)
    hdr[8:40] = b"aes".ljust(32, b"\x00")
    hdr[40:72] = b"xts-plain64".ljust(32, b"\x00")
    hdr[72:104] = b"sha256".ljust(32, b"\x00")
    struct.pack_into(">II", hdr, 104, payload_sector, KEY_BYTES)
    hdr[112:132] = mk_digest
    hdr[132:164] = mk_salt
    struct.pack_into(">I", hdr, 164, mk_iter)
    hdr[168:208] = b"1f2e3d4c-5b6a-7988-9a0b-cdef01234567".ljust(40, b"\x00")
    base = 208
    struct.pack_into(">II", hdr, base, 0x00AC71F3, iterations)
    hdr[base + 8:base + 40] = salt
    struct.pack_into(">II", hdr, base + 40, key_material_offset, stripes)

    blob = bytearray(payload_sector * SECTOR + len(payload))
    blob[0:len(hdr)] = hdr
    blob[4096:4096 + len(enc)] = enc
    blob[payload_sector * SECTOR:] = payload
    return bytes(blob), mk