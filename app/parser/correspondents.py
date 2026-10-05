"""Correspondent extraction from the From/To/Cc headers of one message.

The index is keyed by the *normalized* (lower-cased) mailbox so case and
display-name variants of one address collapse onto a single entry. Parsing is
done on the **raw** header text (structure first, RFC2047-decoding of display
names afterwards) so encoded-words can never be misread as list separators;
the raw header text is stored next to every entry for traceability.

Extraction is segment-driven: the header is split on top-level commas
(quote/bracket/comment aware, group-syntax aware) and every segment is parsed
on its own. This matters because :func:`email.utils.getaddresses` applied to
a whole header can silently swallow tokens — one poisoned segment (``@@``)
can make it drop *valid* addresses elsewhere in the list, and tokens like
``broken@`` vanish without a trace. Malformed tokens are never promoted to
addresses: they become ``MalformedAddress`` defects (stage ``0:from`` /
``0:to`` / ``0:cc``) and are excluded from the index.
"""
from __future__ import annotations

import re
from email.header import decode_header, make_header
from email.message import Message
from email.utils import getaddresses

from .models import Correspondent, Defect

# A plausible mailbox: exactly one '@', non-empty local/domain, no whitespace
# or address-list punctuation inside either part. Anything else (stray text,
# empty local/domain, doubled '@') is reported as a defect, never indexed.
_MAILBOX_RE = re.compile(r"^[^@\s<>\[\](),;:'\"]+@[^@\s<>\[\](),;:'\"]+$")
# Quoted local part: "foo"@host — index it under the unquoted form (RFC 5321
# treats the quoting as transport syntax, not as part of the mailbox).
_QUOTED_LOCAL_RE = re.compile(r"^\"([^\"]+)\"(@[^@\s<>\[\](),;:'\"]+)$")

_ROLES = (("from", "From"), ("to", "To"), ("cc", "Cc"))


def normalize_address(address: str) -> str:
    """Canonical index key for a mailbox (case variants share one entry)."""
    return address.strip().lower()


def _normalize_mailbox(addr: str) -> str | None:
    """Return the normalized mailbox, or None when the token is malformed."""
    a = addr.strip()
    quoted = _QUOTED_LOCAL_RE.match(a)
    if quoted:
        a = quoted.group(1) + quoted.group(2)
    if not _MAILBOX_RE.match(a):
        return None
    return a.lower()


def _decode_display_name(raw_name: str) -> str:
    """RFC2047-decode a display name; keep the raw text when undecodable."""
    name = raw_name.strip()
    if not name:
        return ""
    try:
        return str(make_header(decode_header(name)))
    except (LookupError, ValueError, UnicodeDecodeError):
        return name


def _raw_headers(msg: Message, name: str) -> list[str]:
    """Every raw occurrence of header ``name``, in order of appearance."""
    return [v for k, v in msg.raw_items() if k.lower() == name.lower()]


def _segments(value: str) -> list[str]:
    """Split a header value on top-level commas (quote/bracket/comment aware)."""
    parts: list[str] = []
    buf: list[str] = []
    angle = paren = 0
    in_quote = escaped = False
    for ch in value:
        if escaped:
            buf.append(ch)
            escaped = False
            continue
        if ch == "\\" and in_quote:
            buf.append(ch)
            escaped = True
            continue
        if ch == '"':
            in_quote = not in_quote
            buf.append(ch)
            continue
        if in_quote:
            buf.append(ch)
            continue
        if ch == "<":
            angle += 1
        elif ch == ">":
            angle = max(0, angle - 1)
        elif ch == "(":
            paren += 1
        elif ch == ")":
            paren = max(0, paren - 1)
        if ch == "," and angle == 0 and paren == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    return parts


def _toplevel_colon(segment: str) -> int:
    """Index of the first colon outside quotes/angle brackets, or -1."""
    angle = 0
    in_quote = escaped = False
    for i, ch in enumerate(segment):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_quote:
            escaped = True
            continue
        if ch == '"':
            in_quote = not in_quote
            continue
        if in_quote:
            continue
        if ch == "<":
            angle += 1
        elif ch == ">":
            angle = max(0, angle - 1)
        elif ch == ":" and angle == 0:
            return i
    return -1


def _extract_from_header(
    raw: str,
    header: str,
    role: str,
    stage: str,
    seen: set[str],
    correspondents: list[Correspondent],
    defects: list[Defect],
) -> None:
    def add(mailbox: str, display_name: str) -> None:
        if mailbox in seen:
            return
        seen.add(mailbox)
        correspondents.append(
            Correspondent(role=role, address=mailbox, display_name=display_name, raw_header=raw)
        )

    in_group = False
    for seg in _segments(raw):
        s = seg.strip()
        if not s:
            continue
        if not in_group:
            colon = _toplevel_colon(s)
            if colon >= 0 and "@" not in s[:colon]:
                # group label: addresses follow until a ';' terminator
                in_group = True
                s = s[colon + 1 :].strip()
        if in_group and s.endswith(";"):
            s = s[:-1].strip()
            in_group = False
        if not s:
            continue  # empty group ("undisclosed-recipients:;") is legal

        pairs = getaddresses([s])
        if not any(name.strip() or addr.strip() for name, addr in pairs):
            # getaddresses swallowed the whole segment. A trailing ';' typo
            # hides a real mailbox ("alice@x.com;"): recover it, but record
            # the defect so the header problem stays visible.
            body = s.rstrip(";").strip()
            if "@" not in body:
                continue  # stray punctuation noise, not an address attempt
            salvaged: tuple[str, str] | None = None
            if body != s:
                for name2, addr2 in getaddresses([body]):
                    mailbox2 = _normalize_mailbox(addr2)
                    if mailbox2:
                        salvaged = (mailbox2, _decode_display_name(name2))
                        break
            if salvaged:
                defects.append(
                    Defect(
                        stage=stage,
                        level="MalformedAddress",
                        message=f"recovered {salvaged[0]!r} from malformed token {s!r} in {header} header"[:200],
                    )
                )
                add(salvaged[0], salvaged[1])
            else:
                defects.append(
                    Defect(
                        stage=stage,
                        level="MalformedAddress",
                        message=f"unparseable address token {body!r} in {header} header"[:200],
                    )
                )
            continue

        for name, addr in pairs:
            if not addr.strip() and not name.strip():
                continue  # separator noise
            mailbox = _normalize_mailbox(addr)
            if mailbox is None:
                token = f"{name.strip()} <{addr.strip()}>" if name.strip() else addr.strip()
                defects.append(
                    Defect(
                        stage=stage,
                        level="MalformedAddress",
                        message=f"invalid address {token!r} in {header} header"[:200],
                    )
                )
                continue
            add(mailbox, _decode_display_name(name))


def extract_correspondents(msg: Message) -> tuple[list[Correspondent], list[Defect]]:
    """Build the correspondent index for one parsed message.

    Only the top-level From/To/Cc headers are considered — never subjects,
    bodies or embedded messages. One entry per (role, normalized mailbox);
    duplicates within a role collapse onto the first occurrence.
    """
    correspondents: list[Correspondent] = []
    defects: list[Defect] = []
    for role, header in _ROLES:
        seen: set[str] = set()
        for raw in _raw_headers(msg, header):
            _extract_from_header(
                raw, header, role, f"0:{role}", seen, correspondents, defects
            )
    return correspondents, defects
