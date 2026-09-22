#!/usr/bin/env python3
"""dlp's keyword-based confidential-information scanner (called from dlp-masker.py).

Usage: dlp_scanner.py <config file.json> <target file>

Detects "values" whose key name contains one of the config file's
`filter_words`, and writes findings to stdout as a JSON array. Each element
is {"rule_id": str, "start": int, "end": int, "secret": str}. start / end
are 0-based half-open offsets into the target file decoded as UTF-8
(surrogateescape).

Exits non-zero if the config cannot be read or `filter_words` is empty.
Callers treat "zero findings" as meaning safe, so an empty array must never
be returned when a determination cannot be made.
"""

from __future__ import annotations

import json
import re
import sys
from typing import Iterator

import yaml_lite

# One item per line (`key=value` / `key: value`) in properties / .env / YAML / INI / TOML.
# Also accepts YAML list items `- key: value` and shell `export KEY=value`.
LINE_RE = re.compile(
    r"^[ \t]*(?:-[ \t]+)?(?:export[ \t]+)?"
    r"(?P<key>[A-Za-z0-9_.\-\[\]]+)[ \t]*[:=][ \t]*(?P<value>[^\r\n]*)",
    re.MULTILINE,
)

# JSON `"key": "value"` / `"key": 123`.
JSON_RE = re.compile(
    r'"(?P<key>[^"\\\r\n]{1,256})"\s*:\s*'
    r'(?:"(?P<str>(?:[^"\\\r\n]|\\.)*)"|(?P<num>-?[0-9][0-9.eE+\-]*))'
)

# `key="value"` / `key='value'` in XML attributes or config files.
QUOTED_ASSIGN_RE = re.compile(
    r"""(?:^|(?<=[\s;&?,{(:/]))(?P<key>[A-Za-z_][\w.:\-]*)[ \t]*=[ \t]*"""
    r"""(?:"(?P<dq>[^"\r\n]*)"|'(?P<sq>[^'\r\n]*)')""",
    re.MULTILINE,
)

# Unquoted `key=value` in connection strings (`User ID=sa;Password=xxx`) or
# URL query strings (`?user=a&password=xxx`). Values run until `; & " ' < >`
# or end of line. Keys may be up to two words, e.g. `User ID`.
BARE_ASSIGN_RE = re.compile(
    r"""(?:^|(?<=[\s;&?,"'{(:/]))"""
    r"""(?P<key>[A-Za-z_][\w.\-]*(?: [A-Za-z_][\w.\-]*)?)[ \t]*=[ \t]*"""
    r"""(?P<value>[^\s;&"'<>][^;&"'<>\r\n]*)""",
    re.MULTILINE,
)

# Contents of an XML element (`<Password>xxx</Password>` / `<pw><![CDATA[xxx]]></pw>`).
ELEMENT_RE = re.compile(
    r"<(?P<tag>[A-Za-z_][\w:.\-]*)(?:\s[^<>]*)?(?<!/)>"
    r"(?:<!\[CDATA\[(?P<cdata>[\s\S]*?)\]\]>|(?P<text>[^<>]*))"
    r"</(?P=tag)\s*>"
)

# An XML opening tag, and the attributes within it.
TAG_RE = re.compile(r"<[A-Za-z_][^<>]*>")
ATTR_RE = re.compile(r"""(?P<name>[A-Za-z_:][\w:.\-]*)\s*=\s*(?:"(?P<dq>[^"]*)"|'(?P<sq>[^']*)')""")

# Notation where the key name is written as an attribute "value" and the
# secret lives in a different attribute, as in `<add key="ApiKey"
# value="xxx" />` (.NET appSettings) or `<property name="password"
# value="xxx" />` (Spring XML).
INDIRECT_NAME_ATTRS = ("key", "name")
INDIRECT_VALUE_ATTR = "value"


def normalize(s: str) -> str:
    """Normalize `api_key` / `api-key` / `apiKey` / `API.KEY` all to `apikey`."""
    return re.sub(r"[^a-z0-9]", "", s.lower())


def load_filter_words(config_path: str) -> list[str]:
    with open(config_path, "r", encoding="utf-8") as fh:
        data = yaml_lite.parse(fh.read())
    words = data.get("filter_words") if isinstance(data, dict) else None
    if not isinstance(words, list) or not all(isinstance(w, str) for w in words):
        raise ValueError("filter_words must be an array of strings")
    normalized = sorted({normalize(w) for w in words} - {""})
    if not normalized:
        raise ValueError("filter_words is empty")
    return normalized


# Filter words at or below this length are never matched as a substring.
# Short words cause too many accidental matches — e.g. stripping delimiters
# from `org.owasp.webwolf` gives `orgowaspwebwolf`, which contains `pw`.
SHORT_WORD_MAX_LEN = 3


def tokens(key: str) -> list[str]:
    """Split `cache.pw` / `user_pw` / `dbPw` / `APIKey` into words on delimiters and camelCase."""
    return [t.lower() for t in re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+", key)]


def matched_word(key: str, words: list[str]) -> str | None:
    """Long words match as a delimiter-insensitive substring (`api.key` matches `apikey`); short words require an exact word match."""
    k = normalize(key)
    key_tokens = set(tokens(key))
    for w in words:
        if (w in key_tokens) if len(w) <= SHORT_WORD_MAX_LEN else (w in k):
            return w
    return None


def _trim(text: str, start: int, end: int) -> tuple[int, int]:
    while start < end and text[start].isspace():
        start += 1
    while end > start and text[end - 1].isspace():
        end -= 1
    return start, end


def _unquote(text: str, start: int, end: int) -> tuple[int, int]:
    """If the value starts with a quote, keep only the contents up to the closing quote (dropping a trailing `# comment` etc.)."""
    start, end = _trim(text, start, end)
    if start < end and text[start] in "\"'":
        close = text.find(text[start], start + 1, end)
        if close != -1:
            return start + 1, close
    return start, end


def _group_span(m: re.Match, *names: str) -> tuple[int, int]:
    for name in names:
        if m.group(name) is not None:
            return m.start(name), m.end(name)
    raise AssertionError(names)


def candidates(text: str) -> Iterator[tuple[str, str, int, int]]:
    """Enumerate (rule, key name, start, end). Key-name judgment is left to the caller."""
    for m in LINE_RE.finditer(text):
        yield ("line", m.group("key"), *_unquote(text, m.start("value"), m.end("value")))
    for m in JSON_RE.finditer(text):
        yield ("json", m.group("key"), *_group_span(m, "str", "num"))
    for m in QUOTED_ASSIGN_RE.finditer(text):
        yield ("quoted", m.group("key"), *_group_span(m, "dq", "sq"))
    for m in BARE_ASSIGN_RE.finditer(text):
        yield ("inline", m.group("key"), *_trim(text, m.start("value"), m.end("value")))
    for m in ELEMENT_RE.finditer(text):
        yield ("xml-element", m.group("tag"), *_trim(text, *_group_span(m, "cdata", "text")))
    for tag in TAG_RE.finditer(text):
        attrs: dict[str, tuple[str, int, int]] = {}
        for a in ATTR_RE.finditer(tag.group()):
            s, e = _group_span(a, "dq", "sq")
            attrs.setdefault(a.group("name").lower(), (a.group("dq") or a.group("sq") or "",
                                                       tag.start() + s, tag.start() + e))
        value = attrs.get(INDIRECT_VALUE_ATTR)
        if value is None:
            continue
        for name_attr in INDIRECT_NAME_ATTRS:
            if name_attr in attrs:
                yield ("xml-key-value", attrs[name_attr][0], value[1], value[2])


def scan(text: str, words: list[str]) -> list[dict]:
    found: dict[tuple[int, int], str] = {}
    for rule, key, start, end in candidates(text):
        secret = text[start:end]
        # Empty values, and values that are only asterisks (e.g. an already-masked
        # `********`), are not secrets. Without this exclusion, re-scanning a masked
        # copy would detect its own mask and never pass verification.
        if not secret.strip() or set(secret) <= {"*"}:
            continue
        word = matched_word(key, words)
        if word is not None:
            found.setdefault((start, end), f"{rule}:{word}")
    return [
        {"rule_id": rule, "start": start, "end": end, "secret": text[start:end]}
        for (start, end), rule in sorted(found.items())
    ]


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: dlp_scanner.py <config.json> <file>", file=sys.stderr)
        return 2
    try:
        words = load_filter_words(argv[1])
    except (OSError, ValueError) as exc:
        print(f"cannot load config file: {exc}", file=sys.stderr)
        return 2
    try:
        with open(argv[2], "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        print(f"cannot read target file: {exc}", file=sys.stderr)
        return 2
    # Must use the same decoding scheme as masker.py, or the offsets won't line up.
    text = raw.decode("utf-8", "surrogateescape")
    json.dump(scan(text, words), sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
