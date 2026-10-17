#!/bin/sh
# Build the real-cryptsetup LUKS2 fixtures. See README.md.
# Usage: sh make_fixtures.sh [output-dir]   (default: this script's directory)
# Needs cryptsetup >= 2.4, xz, python3. Tries rootless first.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
out=${1:-$here}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

# Public passphrases (no trailing newline: --key-file reads raw bytes).
printf '%s' 'strata-fixture-1' > "$work/pw1"
printf '%s' 'strata-fixture-2' > "$work/pw2"

IMG_SIZE=786432      # 768 KiB plain file = 1536 sectors of 512 bytes
HDR_SIZE=655360      # 640 KiB reserved for header + keyslots area
HDR_SECTORS=$((HDR_SIZE / 512))
COMMON="--type luks2 --disable-locks --batch-mode"
PBKDF="--pbkdf-force-iterations 4 --pbkdf-memory 64 --pbkdf-parallel 1"

plain() {  # plain <file>: every 512-byte sector reads "STRATA-FIXTURE sector N"
    python3 -I - "$1" "$IMG_SIZE" <<'PY'
import sys
path, size = sys.argv[1], int(sys.argv[2])
with open(path, "wb") as f:
    for n in range(size // 512):
        f.write(("STRATA-FIXTURE sector %d" % n).encode().ljust(512, b"\0"))
PY
}

encrypt() {  # encrypt <file> <sector-size> <pbkdf>
    # shellcheck disable=SC2086
    cryptsetup reencrypt --encrypt $COMMON --force-offline-reencrypt \
        --reduce-device-size "$HDR_SIZE" --offset "$HDR_SECTORS" \
        --luks2-metadata-size 16k --luks2-keyslots-size 512k \
        --cipher aes-xts-plain64 --key-size 512 --hash sha256 \
        --sector-size "$2" --pbkdf "$3" $PBKDF --key-file "$work/pw1" "$1"
}

# A: argon2id, 4096-byte sectors
plain "$work/luks2-argon2id-4k.img"
encrypt "$work/luks2-argon2id-4k.img" 4096 argon2id

# B: argon2i, 512-byte sectors, plus a pbkdf2 keyslot (slot 1, passphrase 2)
plain "$work/luks2-argon2i-512.img"
encrypt "$work/luks2-argon2i-512.img" 512 argon2i
# shellcheck disable=SC2086
cryptsetup luksAddKey $COMMON --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
    --key-file "$work/pw1" "$work/luks2-argon2i-512.img" "$work/pw2"

# expected.json: header metadata + volume key per image, tool version
for img in luks2-argon2id-4k luks2-argon2i-512; do
    f=$work/$img.img
    cryptsetup luksDump --disable-locks --dump-json-metadata "$f" > "$work/$img.json"
    cryptsetup luksDump --disable-locks --dump-volume-key --batch-mode \
        --key-file "$work/pw1" "$f" > "$work/$img.vk"
done
cryptsetup --version > "$work/version"
python3 -I - "$work" "$out/expected.json" <<'PY'
import json, re, sys
work, dest = sys.argv[1], sys.argv[2]
res = {"cryptsetup": open(work + "/version").read().strip(),
       "passphrases": {"1": "strata-fixture-1", "2": "strata-fixture-2"},
       "plaintext": "every 512-byte sector N = 'STRATA-FIXTURE sector N' NUL-padded",
       "images": {}}
for name in ("luks2-argon2id-4k", "luks2-argon2i-512"):
    meta = json.load(open("%s/%s.json" % (work, name)))
    vk = open("%s/%s.vk" % (work, name)).read()
    m = re.search(r"([0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})*)\s*$", vk)
    hexkey = re.sub(r"\s+", "", m.group(1)).lower() if m else None
    res["images"][name + ".img.xz"] = {"volume_key_hex": hexkey, "metadata": meta}
with open(dest, "w") as f:
    json.dump(res, f, indent=2, sort_keys=True)
    f.write("\n")
PY

for img in luks2-argon2id-4k luks2-argon2i-512; do
    xz -9e -c "$work/$img.img" > "$out/$img.img.xz"
done
echo "wrote fixtures to $out"
