import datetime
import email
import email.policy
import email.utils
import re
from html.parser import HTMLParser

FROM_LINE = re.compile(rb"^From (\S*) +(.*)$")
ESCAPED = re.compile(rb"^(>+)From ", re.M)

MAX_HTML_TEXT = 256 * 1024

def _unescape(body):
    return ESCAPED.sub(lambda m: b">" * (len(m.group(1)) - 1) + b"From ", body)

class _VisibleText(HTMLParser):
    """The text a browser would show, not the markup: script/style content
    is dropped, everything else is kept as plain text -- no tag is ever
    interpreted, only its own textual content."""

    def __init__(self):
        super().__init__()
        self._skip = 0
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip and data.strip():
            self.parts.append(data.strip())

def _html_to_text(markup, limit=MAX_HTML_TEXT):
    """A message with no text/plain part is reduced to its visible text, so
    there is something to show that is not markup -- never rendered as
    HTML, and never returned at all if the parser cannot make sense of it."""
    if not markup:
        return None
    try:
        p = _VisibleText()
        p.feed(markup)
        p.close()
    except Exception:
        return None
    text = re.sub(r"[ \t]+", " ", "\n".join(p.parts)).strip()
    if not text:
        return None
    return text[:limit] if limit else text

def split_messages(data):
    out = []
    start = None
    pos = 0
    n = len(data)
    while pos < n:
        end = data.find(b"\n", pos)
        if end == -1:
            end = n
        line = data[pos:end]
        if line.startswith(b"From ") and (pos == 0 or data[pos - 1:pos] == b"\n"):
            if start is not None:
                out.append((start, pos))
            start = pos
        pos = end + 1
    if start is not None:
        out.append((start, n))
    return out

def _addresses(value):
    if not value:
        return []
    try:
        return [a for _n, a in email.utils.getaddresses([str(value)]) if a]
    except Exception:
        return []

def _date(value):
    if not value:
        return None
    try:
        dt = email.utils.parsedate_to_datetime(str(value))
    except (TypeError, ValueError):
        return None
    if dt is None:
        return None
    try:
        if dt.tzinfo is None:
            return dt.isoformat() + " (no timezone in header)"
        return dt.astimezone(datetime.timezone.utc).isoformat().replace(
            "+00:00", "Z")
    except (ValueError, OSError, OverflowError):
        return None

def parse_message(raw, offset=None):
    body = raw
    first_nl = raw.find(b"\n")
    envelope = None
    if raw.startswith(b"From ") and first_nl != -1:
        m = FROM_LINE.match(raw[:first_nl])
        if m:
            envelope = {
                "from": m.group(1).decode("latin-1", "replace"),
                "date": m.group(2).decode("latin-1", "replace").strip(),
            }
        body = raw[first_nl + 1:]
    body = _unescape(body)

    try:
        msg = email.message_from_bytes(body, policy=email.policy.default)
    except Exception:
        return {"offset": offset, "unparsed": True,
                "bytes": len(raw), "envelope": envelope}

    attachments = []
    text = None
    html = None
    try:
        for part in msg.walk():
            disp = (part.get_content_disposition() or "")
            ctype = part.get_content_type()
            if disp == "attachment" or part.get_filename():
                payload = part.get_payload(decode=True) or b""
                attachments.append({
                    "filename": part.get_filename(),
                    "content_type": ctype,
                    "bytes": len(payload),
                })
                continue
            if part.is_multipart():
                continue
            if ctype == "text/plain" and text is None:
                text = part.get_content()
            elif ctype == "text/html" and html is None:
                html = part.get_content()
    except Exception:
        pass

    html_text = _html_to_text(html) if html and text is None else None
    status = (msg.get("Status") or "") + (msg.get("X-Status") or "")
    return {
        "offset": offset,
        "bytes": len(raw),
        "subject": str(msg.get("Subject") or "") or None,
        "from": _addresses(msg.get("From")),
        "to": _addresses(msg.get("To")),
        "cc": _addresses(msg.get("Cc")),
        "bcc": _addresses(msg.get("Bcc")),
        "date": _date(msg.get("Date")),
        "date_raw": str(msg.get("Date") or "") or None,
        "message_id": str(msg.get("Message-ID") or "") or None,
        "in_reply_to": str(msg.get("In-Reply-To") or "") or None,
        "flags": status or None,
        "deleted_flag": "D" in status,
        "read_flag": "R" in status,
        "envelope": envelope,
        "attachments": attachments,
        "attachment_count": len(attachments),
        "text": text,
        "html_bytes": len(html) if html else 0,
        "html_text": html_text,
        "headers": {k: str(v) for k, v in msg.items()},
    }

def parse(data, limit=20000, progress=None):
    ranges = split_messages(data)
    out = {"messages": [], "count": len(ranges), "findings": []}
    if not ranges:
        out["findings"].append(
            "No 'From ' separator lines — this is not an mbox, or it holds a "
            "single bare RFC 5322 message.")
        one = parse_message(data, 0)
        if one.get("subject") or one.get("from"):
            out["messages"].append(one)
            out["count"] = 1
        return out
    total = max(1, len(ranges))
    for i, (start, end) in enumerate(ranges[:limit]):
        if progress and i % 64 == 0:
            progress(i / total)
        out["messages"].append(parse_message(data[start:end], start))
    bad = sum(1 for m in out["messages"] if m.get("unparsed"))
    if bad:
        out["findings"].append("%d message(s) could not be parsed as RFC 5322."
                               % bad)
    if progress:
        progress(1.0)
    return out

def looks_like_mbox(head):
    return head.startswith(b"From ")
