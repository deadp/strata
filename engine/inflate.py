import zlib

DEFAULT_MAX = 64 << 20

_FEED = 1 << 16

ENDED, STOPPED, DAMAGED = "ended", "stopped", "damaged"

def inflate_ended(blob, limit=DEFAULT_MAX, wbits=zlib.MAX_WBITS):
    """(data, over_limit, status). status is ENDED when the stream reached
    its end marker and checksum, STOPPED when the input ran out first, and
    DAMAGED when zlib rejected it partway; in the last two, data may be only
    a prefix of what was stored."""
    if limit <= 0:
        return b"", bool(blob), STOPPED
    d = zlib.decompressobj(wbits)
    out = bytearray()
    truncated = False
    try:
        for i in range(0, len(blob), _FEED):
            if len(out) >= limit:
                truncated = True
                break
            out += d.decompress(blob[i:i + _FEED], limit - len(out))
            if d.unconsumed_tail:
                truncated = True
                break
    except zlib.error:
        return bytes(out), truncated, DAMAGED
    return bytes(out), truncated, ENDED if d.eof else STOPPED

def inflate_capped(blob, limit=DEFAULT_MAX, wbits=zlib.MAX_WBITS):
    data, truncated, _ = inflate_ended(blob, limit, wbits)
    return data, truncated
