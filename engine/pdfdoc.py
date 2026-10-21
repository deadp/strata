import re

from .inflate import inflate_capped

MAX_STREAM_OUT = 32 << 20

MAGIC = b"%PDF-"

DANGEROUS = {
    b"/JavaScript": "JavaScript action",
    b"/JS": "JavaScript entry",
    b"/Launch": "launch an external application",
    b"/SubmitForm": "submit form data to a URL",
    b"/ImportData": "import data from a file",
    b"/RichMedia": "embedded Flash or rich media",
    b"/Movie": "embedded movie",
    b"/Sound": "embedded sound",
    b"/GoToR": "open a remote document",
    b"/GoToE": "open an embedded document",
    b"/EmbeddedFile": "embedded file",
    b"/EmbeddedFiles": "embedded file collection",
    b"/AA": "additional actions (fire on open, close, page change)",
    b"/AcroForm": "interactive form",
    b"/XFA": "XFA form (an XML application)",
}

NOTED_ONLY = {
    b"/OpenAction": "action or destination performed when the file opens",
    b"/URI": "link to a URL",
}

def looks_like_pdf(head):
    return head[:5] == MAGIC

def _same_length_replacement(length):
    return b"/X" + b"x" * (length - 2)

_NAME = re.compile(rb"/[0-9A-Za-z\-_.#]*")
_HEX_ESCAPE = re.compile(rb"#([0-9A-Fa-f]{2})")

def _decoded(name):
    return _HEX_ESCAPE.sub(lambda m: bytes([int(m.group(1), 16)]), name)

def _name_spans(buf, key):
    """(start, end) of every name in buf equal to key once #HH escapes are
    decoded, so /Java#53cript is found as /JavaScript."""
    return [m.span() for m in _NAME.finditer(buf)
            if _decoded(m.group()) == key]

def _name_positions(buf, key):
    return [i for i, _ in _name_spans(buf, key)]

def _streams(data):
    out = []
    for m in re.finditer(rb"stream\r?\n", data):
        start = m.end()
        end = data.find(b"endstream", start)
        if end < 0:
            continue
        blob = data[start:end]
        got, _ = inflate_capped(blob, MAX_STREAM_OUT)
        if got:
            out.append((start, got, True))
            continue
        out.append((start, blob, False))
    return out

def _text_between(data, key, limit=512):
    m = re.search(re.escape(key) + rb"\s*\((.{0,%d}?)\)" % limit, data, re.S)
    if not m:
        m = re.search(re.escape(key) + rb"\s*<([0-9A-Fa-f\s]{0,%d}?)>" % limit,
                      data, re.S)
        if not m:
            return None
        try:
            raw = bytes.fromhex(re.sub(rb"\s", b"", m.group(1)).decode("ascii"))
        except Exception:
            return None
    else:
        raw = re.sub(rb"\\([nrtbf()\\])", lambda x: {
            b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"\b",
            b"f": b"\f", b"(": b"(", b")": b")", b"\\": b"\\"}[x.group(1)], m.group(1))
    if raw[:2] in (b"\xfe\xff", b"\xff\xfe"):
        try:
            return raw.decode("utf-16").strip()
        except Exception:
            return None
    try:
        return raw.decode("latin-1").strip() or None
    except Exception:
        return None

class Pdf:

    def __init__(self, data):
        self.data = bytes(data)
        self.valid = looks_like_pdf(self.data[:5])
        self.findings = []
        self.active = []
        self.unpatchable = []
        self.version = None
        self.pages = 0
        self.encrypted = False
        self._clean = None
        if self.valid:
            self._examine()

    def _examine(self):
        m = re.match(rb"%PDF-(\d+\.\d+)", self.data[:16])
        self.version = m.group(1).decode() if m else None
        self.pages = len(re.findall(rb"/Type\s*/Page[^s]", self.data))
        if not self.pages:
            m = re.search(rb"/Count\s+(\d+)", self.data)
            self.pages = int(m.group(1)) if m else 0
        self.encrypted = bool(re.search(rb"/Encrypt\s", self.data))
        self.title = _text_between(self.data, b"/Title")
        self.author = _text_between(self.data, b"/Author")
        self.producer = _text_between(self.data, b"/Producer")
        self.creator = _text_between(self.data, b"/Creator")
        self.created = _text_between(self.data, b"/CreationDate")
        self.modified = _text_between(self.data, b"/ModDate")

        streams = _streams(self.data)
        for key, what in DANGEROUS.items():
            raw = len(_name_positions(self.data, key))
            inside = sum(len(_name_positions(blob, key))
                         for _, blob, packed in streams if packed)
            if raw:
                self.active.append({"key": key.decode(), "what": what,
                                    "count": raw, "location": "file",
                                    "neutralised": True})
            if inside:
                self.active.append({"key": key.decode(), "what": what,
                                    "count": inside, "location": "object stream",
                                    "neutralised": False})
                self.unpatchable.append(key.decode())
        for key, what in NOTED_ONLY.items():
            n = len(_name_positions(self.data, key))
            if n:
                self.active.append({"key": key.decode(), "what": what,
                                    "count": n, "location": "file",
                                    "neutralised": False})

        if self.encrypted:
            self.findings.append(
                "This PDF is encrypted. Its content cannot be extracted "
                "without the password, and it will not be rendered.")
        if self.unpatchable:
            self.findings.append(
                "Active content (%s) is inside a compressed object stream, "
                "where it cannot be removed without rewriting the file. This "
                "PDF will not be rendered." % ", ".join(sorted(set(self.unpatchable))))

    def sanitised(self):
        if not self.renderable:
            return None
        if self._clean is None:
            out = bytearray(self.data)
            for key in DANGEROUS:
                for i, j in _name_spans(bytes(out), key):
                    out[i:j] = _same_length_replacement(j - i)
            self._clean = bytes(out)
            left = [k.decode() for k in DANGEROUS
                    if _name_positions(self._clean, k)]
            if left:
                self.findings.append(
                    "Neutralisation left %s in place; refusing to render."
                    % ", ".join(left))
                self._clean = b""
        return self._clean or None

    @property
    def renderable(self):
        return bool(self.valid and not self.encrypted and not self.unpatchable)

    def text(self, limit=200000):
        out = []
        total = 0
        for _, blob, _packed in _streams(self.data):
            if b"BT" not in blob and b"Tj" not in blob and b"TJ" not in blob:
                continue
            for m in re.finditer(rb"\((?:[^()\\]|\\.)*\)", blob):
                s = m.group(0)[1:-1]
                s = re.sub(rb"\\([0-7]{1,3})",
                           lambda x: bytes([int(x.group(1), 8) & 0xFF]), s)
                s = re.sub(rb"\\(.)", lambda x: x.group(1), s)
                try:
                    piece = s.decode("latin-1")
                except Exception:
                    continue
                if piece.strip():
                    out.append(piece)
                    total += len(piece)
            if total > limit:
                break
        text = " ".join(out)
        text = re.sub(r"\s+", " ", text).strip()
        text = text[:limit]

        if text:
            sample = text[:4000]
            letters = sum(c.isalpha() or c.isspace() or c in ".,;:!?'\"-()"
                          for c in sample)
            if letters / len(sample) < 0.75:
                self.findings.append(
                    "Text could not be extracted: this PDF stores its text as "
                    "font glyph indices (CID-keyed fonts), which needs the "
                    "embedded font's character map to decode. The page still "
                    "renders correctly.")
                return ""
        return text

    def info(self):
        return {
            "type": "pdf", "valid": self.valid, "version": self.version,
            "pages": self.pages, "encrypted": self.encrypted,
            "title": getattr(self, "title", None),
            "author": getattr(self, "author", None),
            "producer": getattr(self, "producer", None),
            "creator": getattr(self, "creator", None),
            "created": getattr(self, "created", None),
            "modified": getattr(self, "modified", None),
            "active_content": self.active,
            "renderable": self.renderable,
            "findings": self.findings,
        }
