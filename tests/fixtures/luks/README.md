# LUKS2 fixtures from real cryptsetup

Other LUKS tests use images built by `tests/imagebuild_luks.py`, so reader and
builder share assumptions. These images are meant to be made by the real
`cryptsetup`.

**Status:** `make_fixtures.sh` has been written but not yet run (no
cryptsetup in the authoring sandbox), so the `.img.xz` files and
`expected.json` are not committed yet. Run the script and commit its output.

## Regenerate

    sh tests/fixtures/luks/make_fixtures.sh [output-dir]

Needs `cryptsetup` (2.4+), `xz` and `python3`. It works on plain files with
`--disable-locks --force-offline-reencrypt`, so root should not be needed.
If rootless fails on your system, run the same script as root
(`sudo sh ...`); no loop devices are used either way. The cryptsetup version
used is recorded in `expected.json` (`cryptsetup` field).

## Contents

Plaintext: a 768 KiB file where each 512-byte sector reads
`STRATA-FIXTURE sector N` (NUL-padded). The first 640 KiB are replaced by
the LUKS header (`--reduce-device-size`), leaving 128 KiB of payload.

| Image | KDF | Sector | Keyslots |
|---|---|---|---|
| `luks2-argon2id-4k.img.xz` | argon2id | 4096 | 0: passphrase 1 |
| `luks2-argon2i-512.img.xz` | argon2i | 512 | 0: passphrase 1 (argon2i), 1: passphrase 2 (pbkdf2, 1000 iterations) |

Common parameters: `aes-xts-plain64`, 512-bit key, sha256, metadata 16k,
keyslots area 512k, `--pbkdf-force-iterations 4 --pbkdf-memory 64
--pbkdf-parallel 1`.

Passphrases (public, no trailing newline): `strata-fixture-1`,
`strata-fixture-2`.

`expected.json` holds, per image, the `luksDump --dump-json-metadata` output
and the volume key (hex) from `--dump-volume-key`.

## License

MIT, same as the repository. The contents are public test data.
