#!/usr/bin/env python3
"""A minimal YAML subset parser for dlp.config.yaml, reading only what's needed.

It supports only this config file's shape: `#` comments (at line start, or
` #` outside quotes), top-level flat `key: value` pairs, string/integer
scalars, and string lists (both flow `[a, b]` and block `- a` forms).
Full YAML features such as anchors, multiple documents, nested maps, or
multi-line strings are out of scope. This is self-contained using only the
standard library, to avoid depending on an external parser such as PyYAML.

Imported by both dlp-masker.py and dlp_scanner.py.
"""

from __future__ import annotations

import re

_KEY_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*):\s*(.*)$")
_ITEM_RE = re.compile(r"^\s+-\s*(.*)$")
_INT_RE = re.compile(r"^-?[0-9]+$")


def _strip_comment(s: str) -> str:
    """Drop everything from an unquoted ` #` onward as a comment."""
    quote = None
    for i, ch in enumerate(s):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch == "#" and (i == 0 or s[i - 1].isspace()):
            return s[:i]
    return s


def _scalar(raw: str) -> str | int:
    s = _strip_comment(raw).strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        return s[1:-1]
    if _INT_RE.match(s):
        return int(s)
    return s


def _flow_list(raw: str) -> list:
    s = _strip_comment(raw).strip()
    if not (s.startswith("[") and s.endswith("]")):
        raise ValueError(f"missing closing bracket for array: {raw!r}")
    inner = s[1:-1].strip()
    return [_scalar(part) for part in inner.split(",")] if inner else []


def parse(text: str) -> dict:
    """Return the top-level flat mapping. Raises ValueError if malformed."""
    lines = text.replace("\r\n", "\n").split("\n")
    data: dict = {}
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        i += 1
        if not stripped or stripped.startswith("#"):
            continue
        m = _KEY_RE.match(line)
        if not m:
            raise ValueError(f"cannot parse line {i}: {line!r}")
        key, rest = m.group(1), m.group(2)
        rest_stripped = _strip_comment(rest).strip()
        if not rest_stripped:
            # If `key:` has no value, collect the following `  - item` lines as a block list.
            items: list = []
            while i < len(lines):
                item_m = _ITEM_RE.match(lines[i])
                if item_m:
                    items.append(_scalar(item_m.group(1)))
                    i += 1
                    continue
                if not lines[i].strip() or lines[i].strip().startswith("#"):
                    i += 1
                    continue
                break
            data[key] = items
        elif rest_stripped.startswith("["):
            data[key] = _flow_list(rest)
        else:
            data[key] = _scalar(rest)
    return data
