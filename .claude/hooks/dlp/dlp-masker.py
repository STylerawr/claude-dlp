#!/usr/bin/env python3
"""PreToolUse(Read|Grep) / PostToolUse(Read|Grep) hook

If a protected file contains unencrypted confidential information, blocks the
read and redirects Claude to a safe copy with the detected spans replaced by
"********".

Configuration is read from dlp.config.yaml in the same directory; detection
is performed by calling dlp_scanner.py (which detects values whose key name
contains a filter word) as a subprocess.

Reads via Bash are **not handled by this hook**. Claude Code's `Bash(...)`
rules in `permissions.deny` parse compound commands, subshells, command
substitution, environment-variable prefixes, and wrappers (timeout/xargs,
etc.) before applying a deny, so that is left to them.
See README.md for a config example and the division of responsibility.

Design highlights (see README.md for details):
  - Masked copies are named via content addressing (a hash of the original file's content is embedded in the path)
  - Access to a masked copy is checked against a sidecar meta for freshness
  - Deletion is a sweeping GC triggered from PostToolUse (only the body is short-lived; the meta stays as an index)
  - Allowing is a silent exit 0 rather than returning permissionDecision:"allow" (an explicit allow would bypass the permission flow)
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import stat as statmod
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import NamedTuple

import yaml_lite

# ---------------------------------------------------------------------------
# Configuration (dlp.config.yaml; each item can be overridden via the
# environment variable CLAUDE_DLP_MASKER_<UPPERCASE_NAME>)
# ---------------------------------------------------------------------------

MASKER_VERSION = 3
MASK_TOKEN = "********"

# This hook assumes it lives under the repo (`<repo>/.claude/hooks/dlp/`);
# the config, scanner, and protected paths are all resolved from the
# script's own location. No absolute paths are embedded, so it still works
# if the clone path changes.
_HOOK_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _HOOK_DIR.parent.parent.parent
SCANNER_SCRIPT = _HOOK_DIR / "dlp_scanner.py"
CONFIG_PATH = Path(os.path.expanduser(
    os.environ.get("CLAUDE_DLP_MASKER_CONFIG") or str(_HOOK_DIR / "dlp.config.yaml")
))

# A config problem (missing file, broken, missing items). Without a valid
# config, the scope of protection can't even be determined, so main() stops
# Read/Grep fail-closed. Each constant is filled with an empty value on
# error so a problem never causes a NameError.
_config_error: str | None = None


def _config_problem(message: str) -> None:
    global _config_error
    if _config_error is None:
        _config_error = message


def _load_config(path: Path) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml_lite.parse(fh.read())
    except OSError as exc:
        _config_problem(f"cannot read config file {path}: {exc}")
        return {}
    except ValueError as exc:
        _config_problem(f"cannot parse config file {path}: {exc}")
        return {}
    if not isinstance(data, dict):
        _config_problem(f"top level of config file {path} is not a mapping")
        return {}
    return data


_CONFIG = _load_config(CONFIG_PATH)


def _cfg(key: str, kind: type, empty):
    value = _CONFIG.get(key)
    if kind is list:
        valid = isinstance(value, list) and all(isinstance(x, str) for x in value)
    elif kind is int:
        valid = isinstance(value, int) and not isinstance(value, bool)
    else:
        valid = isinstance(value, str) and value != ""
    if not valid:
        _config_problem(f"config file {CONFIG_PATH} is missing {key} or it has the wrong type (expected {kind.__name__})")
        return empty
    return value


def _env(name: str, default: str) -> str:
    return os.environ.get("CLAUDE_DLP_MASKER_" + name, default)


def _env_int(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)))
    except ValueError:
        return default


def _env_list(name: str, default: list[str], sep: str = ":") -> list[str]:
    raw = _env(name, "")
    return [x for x in raw.split(sep) if x] if raw else default


# Relative paths are resolved from the repo root. Machine-wide secrets such
# as `~/.ssh` are protected not by this hook but by `permissions.deny` in
# `~/.claude/settings.json` (see README for the division of responsibility).
TARGET_DIRS = _env_list(
    "TARGET_DIRS",
    [str(_REPO_ROOT / os.path.expanduser(p)) for p in _cfg("target_dirs", list, [])],
)
TARGET_EXTENSIONS = {
    x.lower() for x in _env_list("TARGET_EXTENSIONS", _cfg("target_extensions", list, []), sep=",")
}
ALWAYS_TARGET_GLOBS = _env_list("ALWAYS_TARGET_GLOBS", _cfg("always_target_globs", list, []), sep=",")
EXCLUDE_GLOBS = _env_list("EXCLUDE_GLOBS", _cfg("exclude_globs", list, []), sep=",")
# Unlike TARGET_DIRS, a relative path here is resolved from this script's
# location, so the default becomes an independent
# `<repo>/.claude/hooks/dlp/masked/` per project.
_mask_dir_raw = Path(os.path.expanduser(_env("MASK_DIR", _cfg("mask_dir", str, ""))))
MASK_DIR = _mask_dir_raw if _mask_dir_raw.is_absolute() else (_HOOK_DIR / _mask_dir_raw)
ON_SCANNER_ERROR = _env("ON_SCANNER_ERROR", _cfg("on_scanner_error", str, "deny"))  # deny | ask | allow
SCAN_TIMEOUT_SEC = _env_int("SCAN_TIMEOUT_SEC", _cfg("scan_timeout_sec", int, 0))
MAX_TARGET_MB = _env_int("MAX_TARGET_MB", _cfg("max_target_mb", int, 0))
BODY_TTL_SEC = _env_int("BODY_TTL_SEC", _cfg("body_ttl_sec", int, 0))    # masked body: since last access
META_TTL_SEC = _env_int("META_TTL_SEC", _cfg("meta_ttl_sec", int, 0))    # meta: since creation
CACHE_TTL_SEC = _env_int("CACHE_TTL_SEC", _cfg("cache_ttl_sec", int, 0))
GC_INTERVAL_SEC = _env_int("GC_INTERVAL_SEC", _cfg("gc_interval_sec", int, 0))
GC_LOCK_STALE_SEC = _env_int("GC_LOCK_STALE_SEC", _cfg("gc_lock_stale_sec", int, 0))
MAX_CANDIDATES = _env_int("MAX_CANDIDATES", _cfg("max_candidates", int, 0))
MAX_WALK_FILES = _env_int("MAX_WALK_FILES", _cfg("max_walk_files", int, 0))
SCAN_BUDGET_SEC = _env_int("SCAN_BUDGET_SEC", _cfg("scan_budget_sec", int, 0))
# Minimum length when cleaning up residual detected secrets from the full
# text. Below this length, replacement is skipped since it risks
# collaterally damaging unrelated spans.
MIN_SCRUB_LEN = _env_int("MIN_SCRUB_LEN", _cfg("min_scrub_len", int, 0))
AUDIT_MAX_BYTES = _env_int("AUDIT_MAX_BYTES", _cfg("audit_max_bytes", int, 0))
# filter_words is read by dlp_scanner.py from the same config file. Here we only confirm it exists.
_cfg("filter_words", list, [])


class ScannerError(RuntimeError):
    """Failed to run dlp_scanner.py or parse its output."""


class MaskerError(RuntimeError):
    """The masking process itself failed."""


class Decision(NamedTuple):
    action: str  # "allow" | "deny" | "scanner_error"
    reason: str = ""
    system_message: str = ""


ALLOW = Decision("allow")

# Whether the protected scope has been confirmed. An unexpected exception
# after confirmation is treated fail-closed.
_scope_confirmed = False
# Whether directory traversal was cut short. If so, some files remain
# unscanned, so "no secrets" cannot be claimed.
_scan_truncated = False
_started_at = time.monotonic()


def budget_exceeded() -> bool:
    return time.monotonic() - _started_at > SCAN_BUDGET_SEC


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def emit_allow_silently() -> None:
    """Don't intervene. Does not return permissionDecision:"allow".

    An explicit allow would bypass the normal permission flow (including
    permissions.deny), so "no objection" is expressed as a silent exit 0.
    """
    sys.exit(0)


def emit_decision(decision: str, reason: str, system_message: str | None = None) -> None:
    out = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }
    if system_message:
        out["systemMessage"] = system_message
    sys.stdout.write(json.dumps(out, ensure_ascii=False) + "\n")
    sys.exit(0)


def emit_deny(reason: str, system_message: str | None = None) -> None:
    emit_decision("deny", reason, system_message)


def emit_scanner_error(reason: str) -> None:
    """Behavior when the scanner is unusable. Defaults to fail-closed."""
    if ON_SCANNER_ERROR == "allow":
        emit_allow_silently()
    emit_decision(
        "ask" if ON_SCANNER_ERROR == "ask" else "deny",
        "[SECURITY WARNING] Could not scan for confidential information, so access\n"
        f"to the protected file cannot be allowed (fail-closed).\nReason: {reason}\n\n"
        f"Scanner: {SCANNER_SCRIPT}\n"
        f"Config file: {CONFIG_PATH}\n"
        "To temporarily disable this, set the environment variable CLAUDE_DLP_MASKER_DISABLE=1.",
        "Could not scan for confidential information",
    )


def emit_from(decision: Decision) -> None:
    if decision.action == "allow":
        emit_allow_silently()
    if decision.action == "scanner_error":
        emit_scanner_error(decision.reason)
    emit_deny(decision.reason, decision.system_message or None)


# ---------------------------------------------------------------------------
# Audit log (never writes secrets themselves — only paths and counts)
# ---------------------------------------------------------------------------


def audit(event: str, **fields) -> None:
    if _config_error:  # MASK_DIR has not been determined
        return
    try:
        MASK_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = MASK_DIR / "audit.log"
        record = {"ts": time.time(), "pid": os.getpid(), "event": event}
        record.update(fields)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        os.chmod(path, 0o600)
    except OSError:
        pass


def rotate_audit() -> None:
    path = MASK_DIR / "audit.log"
    try:
        if path.stat().st_size > AUDIT_MAX_BYTES:
            os.replace(path, MASK_DIR / "audit.log.1")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Paths / scope
# ---------------------------------------------------------------------------


def expand(p: str) -> Path:
    return Path(os.path.expanduser(os.path.expandvars(p)))


def target_dir_set() -> list[Path]:
    """Keep TARGET_DIRS in both expanded and realpath form (to prevent bypass via symlinks)."""
    out: list[Path] = []
    for raw in TARGET_DIRS:
        d = expand(raw)
        out.append(d)
        try:
            r = Path(os.path.realpath(d))
            if r != d:
                out.append(r)
        except OSError:
            pass
    return out


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def is_under(child: Path, parent: Path) -> bool:
    try:
        return child == parent or child.is_relative_to(parent)
    except (ValueError, OSError):
        return False


def _with_realpath(p: Path) -> set[Path]:
    out = {p}
    try:
        out.add(Path(os.path.realpath(p)))
    except OSError:
        pass
    return out


def is_in_mask_dir(p: Path) -> bool:
    try:
        mask_real = Path(os.path.realpath(MASK_DIR))
    except OSError:
        mask_real = MASK_DIR
    return any(
        is_under(c, MASK_DIR) or is_under(c, mask_real) for c in _with_realpath(p)
    )


def is_excluded(p: Path) -> bool:
    return any(
        fnmatch.fnmatch(str(c), g) for c in _with_realpath(p) for g in EXCLUDE_GLOBS
    )


def is_in_scope(p: Path) -> bool:
    """Whether this is protected. Filename globs are directory-independent; extensions only apply under TARGET_DIRS."""
    if is_excluded(p):
        return False
    # fnmatch is case-sensitive on POSIX, so lowercase both sides before
    # matching (otherwise .ENV or KEY.PEM would go unprotected).
    name = p.name.lower()
    if any(fnmatch.fnmatch(name, g.lower()) for g in ALWAYS_TARGET_GLOBS):
        return True
    if p.suffix.lower() not in TARGET_EXTENSIONS:
        return False
    dirs = target_dir_set()
    return any(is_under(c, d) for c in _with_realpath(p) for d in dirs)


# ---------------------------------------------------------------------------
# MASK_DIR / atomic write / locking
# ---------------------------------------------------------------------------


def ensure_mask_dir() -> Path:
    d = MASK_DIR
    if d.is_symlink():
        raise MaskerError(f"MASK_DIR is a symlink: {d}")
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = os.stat(d, follow_symlinks=False)
    if not statmod.S_ISDIR(st.st_mode):
        raise MaskerError(f"MASK_DIR is not a directory: {d}")
    if st.st_uid != os.getuid():
        raise MaskerError(f"MASK_DIR has the wrong owner: {d}")
    if st.st_mode & 0o077:
        os.chmod(d, 0o700)
    (d / ".cache").mkdir(mode=0o700, exist_ok=True)
    return d


def write_atomic(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Atomically replace via a temp file in the same directory.

    Because of content addressing, concurrent processes write the same
    content, so whichever one wins, the result is correct.
    """
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def unlink_quiet(path: Path) -> None:
    """Treated as normal even if another process already deleted it."""
    try:
        os.unlink(path)
    except OSError:
        pass


def acquire_lock(lock: Path, stale_sec: int, _depth: int = 0) -> int | None:
    try:
        fd = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.write(fd, f"{os.getpid()} {time.time()}\n".encode())
        return fd
    except FileExistsError:
        if _depth >= 1:
            return None
        try:
            if time.time() - lock.stat().st_mtime > stale_sec:
                unlink_quiet(lock)
                return acquire_lock(lock, stale_sec, _depth + 1)
        except OSError:
            pass
        return None
    except OSError:
        return None


def release_lock(fd: int, lock: Path) -> None:
    try:
        os.close(fd)
    except OSError:
        pass
    unlink_quiet(lock)


# ---------------------------------------------------------------------------
# Masked-copy path and meta
# ---------------------------------------------------------------------------


def masked_paths(source_real: Path, content_sha: str) -> tuple[Path, Path]:
    """The masked-copy path, via content addressing.

    If the original file's content changes, contenthash changes too, so the
    path is always different.
    """
    path_hash = hashlib.sha256(
        str(source_real).encode("utf-8", "surrogateescape")
    ).hexdigest()[:8]
    stem = re.sub(r"[^A-Za-z0-9._-]", "_", source_real.stem or source_real.name)[:64] or "file"
    suffix = source_real.suffix if len(source_real.suffix) <= 16 else ""
    body = MASK_DIR / f"{stem}.{path_hash}-{content_sha[:8]}.masked{suffix}"
    return body, meta_path_for(body)


def meta_path_for(body: Path) -> Path:
    return body.with_name(body.name + ".meta.json")


def body_path_for(meta: Path) -> Path:
    n = meta.name
    return meta.with_name(n[: -len(".meta.json")]) if n.endswith(".meta.json") else meta


def load_meta(meta_p: Path) -> dict | None:
    try:
        with open(meta_p, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and data.get("source_path"):
            return data
    except (OSError, json.JSONDecodeError, ValueError):
        pass
    return None


def save_meta(meta_p: Path, meta: dict) -> None:
    write_atomic(meta_p, json.dumps(meta, ensure_ascii=False, indent=2).encode("utf-8"), 0o600)


def touch_access(meta_p: Path, meta: dict) -> None:
    """Record the last-access time (atime is unreliable under relatime mounts)."""
    meta["last_access"] = time.time()
    try:
        save_meta(meta_p, meta)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Cache (only to avoid re-scanning files known to be clean; secrets are never stored)
# ---------------------------------------------------------------------------


def cache_key(source_real: Path, st: os.stat_result) -> str:
    raw = f"{source_real}\0{st.st_mtime_ns}\0{st.st_size}".encode("utf-8", "surrogateescape")
    return hashlib.sha256(raw).hexdigest()


def cache_get_clean(key: str) -> bool:
    try:
        with open(MASK_DIR / ".cache" / f"{key}.json", "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return (
            isinstance(data, dict)
            and bool(data.get("clean"))
            and time.time() - float(data.get("at", 0)) <= CACHE_TTL_SEC
        )
    except (OSError, json.JSONDecodeError, ValueError, TypeError):
        return False


def cache_put_clean(key: str) -> None:
    try:
        write_atomic(
            MASK_DIR / ".cache" / f"{key}.json",
            json.dumps({"clean": True, "at": time.time()}).encode("utf-8"),
            0o600,
        )
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


def scan_file(path: Path) -> list[dict]:
    """Scan with dlp_scanner.py and return the findings.

    To avoid freezing the whole hook from a regex backtracking blowup, this
    is launched as a subprocess rather than imported into the same process,
    and cut off after SCAN_TIMEOUT_SEC.
    """
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ScannerError(f"cannot stat file: {exc}")
    if size > MAX_TARGET_MB * 1_000_000:
        raise ScannerError(
            f"file size {size} bytes exceeds the scan limit of {MAX_TARGET_MB}MB, cannot scan"
        )
    cmd = [sys.executable, str(SCANNER_SCRIPT), str(CONFIG_PATH), str(path)]
    try:
        cp = subprocess.run(cmd, capture_output=True, timeout=SCAN_TIMEOUT_SEC, text=True)
    except subprocess.TimeoutExpired:
        raise ScannerError(f"scan timed out after {SCAN_TIMEOUT_SEC} seconds")
    except OSError as exc:
        raise ScannerError(f"cannot launch scanner: {exc}")
    if cp.returncode != 0:
        raise ScannerError(f"scanner exited with rc={cp.returncode}: {(cp.stderr or '').strip()[:400]}")
    try:
        data = json.loads(cp.stdout or "")
    except json.JSONDecodeError as exc:
        raise ScannerError(f"cannot parse scanner output as JSON: {exc}")
    if not isinstance(data, list):
        raise ScannerError("scanner output is not an array")
    return [f for f in data if isinstance(f, dict)]


# ---------------------------------------------------------------------------
# Mask generation (position-based)
# ---------------------------------------------------------------------------


def _replacement_for(segment: str) -> str:
    """The replacement string. Preserves any newlines within the range, so the original line count is kept."""
    return MASK_TOKEN + "\n" * segment.count("\n")


def _scrub_residual(text: str, findings: list[dict]) -> tuple[str, int, list[str]]:
    """If a detected secret still appears elsewhere in the file, clean that up too.

    Since the scanner judges by key name, it won't detect the same value
    appearing somewhere with no key-name clue (e.g. the same value from
    app.password= embedded in service.url=). Re-scanning the generated
    output only guarantees "what the scanner can find", so this second-pass
    cleanup is needed.
    """
    scrubbed = 0
    skipped: list[str] = []
    seen: set[str] = set()
    for f in findings:
        secret = f.get("secret") or ""
        if not secret or secret in seen:
            continue
        seen.add(secret)
        if len(secret) < MIN_SCRUB_LEN:
            skipped.append(str(f.get("rule_id") or "?"))
            continue
        if secret in text:
            scrubbed += text.count(secret)
            text = text.replace(secret, _replacement_for(secret))
    return text, scrubbed, skipped


def build_masked_text(text: str, findings: list[dict]) -> tuple[str, int]:
    """Replace only the confidential spans with MASK_TOKEN, based on the findings' offsets."""
    spans: list[tuple[int, int]] = []
    for f in findings:
        start, end = f.get("start"), f.get("end")
        if not (isinstance(start, int) and isinstance(end, int) and 0 <= start < end <= len(text)):
            raise MaskerError("scanner returned out-of-range position info")
        if text[start:end] != f.get("secret"):
            # Offsets are off, e.g. because the original file was rewritten
            # after scanning. Blank out the whole line (erring safe).
            start = text.rfind("\n", 0, start) + 1
            nl = text.find("\n", end)
            end = len(text) if nl == -1 else nl
        spans.append((start, end))

    out, count = text, 0
    if spans:
        merged: list[tuple[int, int]] = []
        for start, end in sorted(set(spans)):
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        # Must apply from the back, or replacement shifts the offsets ahead of it.
        for start, end in reversed(merged):
            out = out[:start] + _replacement_for(out[start:end]) + out[end:]
        count = len(merged)

    out, scrubbed, skipped = _scrub_residual(out, findings)
    count += scrubbed
    if skipped:
        audit("scrub_skipped", rules=sorted(set(skipped))[:20], min_len=MIN_SCRUB_LEN)
    return out, count


def generate_masked(source_real: Path, content_sha: str, findings: list[dict]) -> tuple[Path, int]:
    """Generate the masked copy and its meta. The output is re-scanned for verification."""
    ensure_mask_dir()
    body, meta_p = masked_paths(source_real, content_sha)
    raw = source_real.read_bytes()
    masked_text, span_count = build_masked_text(raw.decode("utf-8", "surrogateescape"), findings)

    write_atomic(body, masked_text.encode("utf-8", "surrogateescape"), 0o400)

    # If masking missed something, we'd get a loop of "read the masked copy
    # → detected again → blocked again". Even if re-scanning itself fails,
    # an unverified output must never be published.
    try:
        residual = scan_file(body)
    except ScannerError as exc:
        unlink_quiet(body)
        unlink_quiet(meta_p)
        raise MaskerError(f"could not verify the masking result (re-scan failed: {exc})")
    if residual:
        unlink_quiet(body)
        unlink_quiet(meta_p)
        raise MaskerError(
            f"{len(residual)} finding(s) of confidential information remained after masking, "
            "so a safe copy could not be provided"
        )

    st = source_real.stat()
    now = time.time()
    save_meta(meta_p, {
        "source_path": str(source_real),
        "source_sha256": content_sha,
        "source_mtime_ns": st.st_mtime_ns,
        "source_size": st.st_size,
        "created_at": now,
        "last_access": now,
        "findings_count": len(findings),
        "masked_spans": span_count,
        "masker_version": MASKER_VERSION,
    })
    return body, span_count


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------


def build_deny_reason(entries: list[tuple[Path, Path, int]], tool_name: str) -> str:
    lines = [
        "[SECURITY WARNING] Unencrypted confidential information was detected in the target file, so the original operation was blocked.",
        "",
        "A safe file with the confidential information masked was automatically generated at:",
    ]
    for source, masked, count in entries:
        lines.append(f"  - Original: {source}")
        lines.append(f"    Masked ({count} span(s)): {masked}")
    lines += [
        "",
        "From now on, to reference or search this file's content, continue working",
        "against the masked file above instead of the original.",
        "",
        "Notes:",
        "  - The masked file is a read-only reference copy. Do not edit it, commit it, or apply it back to the original file.",
        f"  - \"{MASK_TOKEN}\" is not the real value. Do not use it as-is as a config value or credential.",
        "  - If you need to edit the original file, Edit/Write are not restricted, so go ahead.",
    ]
    return "\n".join(lines)


def evaluate_source(source: Path) -> tuple[Path, Path, int] | None:
    """Evaluate a single protected file.

    A return value of None means "no secrets (safe to pass through)".
    Otherwise, returns (original path, masked-copy path, number of masked spans).
    """
    source_real = Path(os.path.realpath(source))
    try:
        st = source_real.stat()
    except OSError:
        return None
    if not statmod.S_ISREG(st.st_mode):
        return None

    # scan_file rejects at the same limit too, but reject here first as well
    # to avoid hashing a huge file.
    if st.st_size > MAX_TARGET_MB * 1_000_000:
        raise ScannerError(
            f"file size {st.st_size} bytes exceeds the scan limit of {MAX_TARGET_MB}MB, cannot scan"
        )

    ensure_mask_dir()

    # 1. mtime/size cache. If already known clean, neither hashing nor scanning is needed.
    key = cache_key(source_real, st)
    if cache_get_clean(key):
        return None

    # 2. The content hash determines the masked-copy path. If already generated, no re-scan is needed.
    content_sha = sha256_file(source_real)
    body, meta_p = masked_paths(source_real, content_sha)
    meta = load_meta(meta_p)
    if meta is not None and meta.get("source_sha256") == content_sha and body.exists():
        touch_access(meta_p, meta)
        return (source_real, body, int(meta.get("masked_spans") or meta.get("findings_count") or 0))

    findings = scan_file(source_real)
    if not findings:
        cache_put_clean(key)
        return None

    body, span_count = generate_masked(source_real, content_sha, findings)
    audit("masked", source=str(source_real), masked=str(body),
          findings=len(findings), spans=span_count)
    return (source_real, body, span_count)


def check_masked_access(masked: Path) -> Decision:
    """Access under MASK_DIR. Never unconditionally allowed — freshness is verified."""
    if masked.name.endswith(".meta.json") or masked.name.startswith("audit.log"):
        return ALLOW

    meta_p = meta_path_for(masked)
    meta = load_meta(meta_p)
    if meta is None:
        return Decision(
            "deny",
            "[SECURITY] Metadata for this masked file was not found (garbage-collected or corrupted).\n"
            "Blocked the read because content freshness cannot be guaranteed.\n"
            "Please Read the original file again; the latest masked path will be presented.",
            "No metadata for the masked file",
        )

    source = Path(meta["source_path"])
    try:
        st = source.stat()
    except OSError:
        return Decision(
            "deny",
            f"[SECURITY] The original file for this masked copy no longer exists: {source}\n"
            "Blocked the read because there is no guarantee the content reflects the current state.",
            "Original file does not exist",
        )

    fresh = st.st_mtime_ns == meta.get("source_mtime_ns") and st.st_size == meta.get("source_size")
    if not fresh:
        current_sha = sha256_file(source)
        if current_sha == meta.get("source_sha256"):
            # Only touched (mtime bumped, content unchanged).
            meta["source_mtime_ns"], meta["source_size"] = st.st_mtime_ns, st.st_size
            fresh = True
        else:
            audit("stale", masked=str(masked), source=str(source))
            try:
                findings = scan_file(source)
            except ScannerError as exc:
                return Decision("scanner_error", str(exc))
            if not findings:
                return Decision(
                    "deny",
                    f"[SECURITY] The original file {source} has been updated and currently contains no confidential information.\n"
                    "This masked file is stale. Please read the original file directly.",
                    "The masked file is stale",
                )
            try:
                new_body, span_count = generate_masked(source, current_sha, findings)
            except (MaskerError, OSError) as exc:
                return Decision("deny", f"[SECURITY] Failed to re-mask the original file: {exc}", "Re-masking failed")
            return Decision(
                "deny",
                "[SECURITY] This masked file is stale (the original file has been updated).\n"
                f"  Original file: {source}\n"
                f"  Stale masked copy (blocked): {masked}\n"
                f"  Latest masked copy ({span_count} span(s)): {new_body}\n\n"
                "Please refer to the latest masked copy from now on.",
                "Generated a new version because the masked file was stale",
            )

    if masked.exists():
        touch_access(meta_p, meta)
        return ALLOW

    # The body has been garbage-collected. Since this is content-addressed,
    # the path doesn't change ⇒ regenerate at the same path.
    try:
        findings = scan_file(source)
    except ScannerError as exc:
        return Decision("scanner_error", str(exc))
    if not findings:
        return Decision(
            "deny",
            f"[SECURITY] The original file {source} currently contains no confidential information. Please read the original file directly.",
            "The masked copy is no longer needed",
        )
    try:
        regenerated, _ = generate_masked(source, meta["source_sha256"], findings)
    except (MaskerError, OSError) as exc:
        return Decision("deny", f"[SECURITY] Failed to regenerate the masked copy: {exc}", "Regeneration failed")
    if regenerated == masked:
        audit("regenerated", masked=str(masked), source=str(source))
        return ALLOW
    return Decision(
        "deny",
        f"[SECURITY] The masked copy was regenerated, but the path changed.\n  Latest masked copy: {regenerated}",
        "The masked file's path has changed",
    )


# ---------------------------------------------------------------------------
# Collecting candidate paths (Read / Grep only; Bash is left to permissions.deny)
# ---------------------------------------------------------------------------


def _collect_from_dir(directory: Path, out: list[Path]) -> None:
    """Collect protected files under a directory.

    Without a cap on the amount walked, a $HOME-scale target would exhaust
    the hook's time limit. If cut short, the full set couldn't be checked,
    so `_scan_truncated` is set.
    """
    global _scan_truncated
    count = walked = 0
    for root, dirs, files in os.walk(directory, followlinks=False):
        if is_in_mask_dir(Path(root)):
            # Ignoring it entirely would let `grep -r <MASK_DIR>` bypass
            # freshness verification.
            for name in files:
                if ".masked" in name and not name.endswith(".meta.json"):
                    out.append(Path(root) / name)
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "target", "build")]
        for name in files:
            walked += 1
            if walked > MAX_WALK_FILES or budget_exceeded():
                _scan_truncated = True
                return
            p = Path(root) / name
            if is_in_scope(p):
                out.append(p)
                count += 1
                if count >= MAX_CANDIDATES:
                    _scan_truncated = True
                    return


def _resolve(raw: str, cwd: Path) -> Path:
    p = Path(os.path.expanduser(raw))
    if not p.is_absolute():
        p = cwd / p
    return Path(os.path.normpath(p))


def collect_candidates(tool_name: str, tool_input: dict, cwd: Path) -> list[Path]:
    if tool_name == "Read":
        raw = tool_input.get("file_path")
        return [_resolve(raw, cwd)] if isinstance(raw, str) and raw else []

    # Grep: content is only returned when output_mode is "content".
    # files_with_matches / count only return filenames or a count, so we don't intervene.
    if tool_input.get("output_mode") != "content":
        return []
    raw = tool_input.get("path")
    base = _resolve(raw, cwd) if isinstance(raw, str) and raw else cwd
    out: list[Path] = []
    if base.is_dir():
        _collect_from_dir(base, out)
    elif base.is_file():
        out.append(base)
    return out


# ---------------------------------------------------------------------------
# GC (deletion is a periodic sweep, not immediate)
# ---------------------------------------------------------------------------


def run_gc() -> None:
    """A sweeping GC that never deletes the generation currently being read."""
    try:
        d = ensure_mask_dir()
    except (MaskerError, OSError):
        return

    stamp = d / ".gc-stamp"
    now = time.time()
    try:
        if now - stamp.stat().st_mtime < GC_INTERVAL_SEC:
            return
    except OSError:
        pass

    lock = d / ".gc.lock"
    fd = acquire_lock(lock, GC_LOCK_STALE_SEC)
    if fd is None:
        return
    try:
        try:
            stamp.touch()
        except OSError:
            pass

        removed_bodies = removed_meta = 0
        for meta_p in d.glob("*.masked*.meta.json"):
            body = body_path_for(meta_p)
            meta = load_meta(meta_p)
            if meta is None:
                try:
                    if now - meta_p.stat().st_mtime > BODY_TTL_SEC:
                        unlink_quiet(body)
                        unlink_quiet(meta_p)
                        removed_meta += 1
                except OSError:
                    pass
                continue

            last = float(meta.get("last_access") or meta.get("created_at") or 0)
            created = float(meta.get("created_at") or 0)
            source = Path(meta.get("source_path") or "")

            if body.exists() and now - last > BODY_TTL_SEC:
                unlink_quiet(body)
                removed_bodies += 1
            if now - created > META_TTL_SEC or (not source.exists() and not body.exists()):
                unlink_quiet(body)
                unlink_quiet(meta_p)
                removed_meta += 1

        cache_dir = d / ".cache"
        if cache_dir.is_dir():
            for entry in cache_dir.glob("*.json"):
                try:
                    if now - entry.stat().st_mtime > CACHE_TTL_SEC:
                        unlink_quiet(entry)
                except OSError:
                    pass

        rotate_audit()
        if removed_bodies or removed_meta:
            audit("gc", bodies=removed_bodies, meta=removed_meta)
    finally:
        release_lock(fd, lock)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    if os.environ.get("CLAUDE_DLP_MASKER_DISABLE") == "1":
        emit_allow_silently()

    try:
        event = json.load(sys.stdin)
        if not isinstance(event, dict):
            raise ValueError("top level is not an object")
    except (json.JSONDecodeError, ValueError, OSError) as exc:
        # With unreadable input, there's no basis to intervene. Pass
        # through, only recording it.
        audit("bad_input", error=str(exc)[:200])
        emit_allow_silently()
        return

    if event.get("hook_event_name") == "PostToolUse":
        if not _config_error:
            run_gc()
        sys.exit(0)

    tool_name = event.get("tool_name") or ""
    if tool_name not in ("Read", "Grep"):
        emit_allow_silently()

    tool_input = event.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        emit_allow_silently()
    cwd = Path(event.get("cwd") or os.getcwd())

    if _config_error:
        # The config file itself contains no secrets. Blocking this too
        # would make it impossible to even read and fix a broken config.
        raw = tool_input.get("file_path")
        if tool_name == "Read" and isinstance(raw, str) and raw and \
                os.path.realpath(_resolve(raw, cwd)) == os.path.realpath(CONFIG_PATH):
            emit_allow_silently()
        emit_scanner_error(_config_error)
        return

    try:
        candidates = collect_candidates(tool_name, tool_input, cwd)
    except Exception as exc:  # Don't intervene on a failure during the collection stage
        audit("collect_error", tool=tool_name, error=str(exc)[:200])
        emit_allow_silently()
        return

    # If the walk was cut short, zero candidates doesn't mean "no secrets".
    if _scan_truncated:
        audit("scan_truncated", tool=tool_name, found=len(candidates))
        emit_deny(
            "[SECURITY WARNING] The target scope was too broad to scan every file within the time limit.\n"
            "Blocked, erring on the safe side, because unscanned files remain.\n"
            "Please re-run against a narrower scope (for Grep, narrow it with glob / type).",
            "Blocked because the scan scope was too broad",
        )
        return

    if not candidates:
        emit_allow_silently()

    # Since a single tool call can reference both a masked copy and a
    # protected file, don't stop after checking just one — evaluate both.
    for candidate in [c for c in candidates if is_in_mask_dir(c)]:
        try:
            decision = check_masked_access(candidate)
        except ScannerError as exc:
            if ON_SCANNER_ERROR == "allow":
                audit("masked_check_skipped", masked=str(candidate), error=str(exc)[:120])
                continue
            emit_scanner_error(str(exc))
            return
        except (MaskerError, OSError) as exc:
            emit_deny(f"[SECURITY] Failed to verify the masked file's freshness: {exc}",
                      "Freshness verification failed")
            return
        if decision.action == "scanner_error" and ON_SCANNER_ERROR == "allow":
            continue
        if decision.action != "allow":
            emit_from(decision)
            return

    in_scope = [p for p in candidates if not is_in_mask_dir(p) and is_in_scope(p)]
    if not in_scope:
        emit_allow_silently()

    # --- From here on, the scope is confirmed. Failures are treated fail-closed. ------------
    global _scope_confirmed
    _scope_confirmed = True

    entries: list[tuple[Path, Path, int]] = []
    seen: set[str] = set()
    for source in in_scope:
        real = str(os.path.realpath(source))
        if real in seen:
            continue
        seen.add(real)
        if budget_exceeded():
            audit("budget_exceeded", tool=tool_name, checked=len(seen), total=len(in_scope))
            emit_scanner_error(
                f"scanning exceeded the time budget of {SCAN_BUDGET_SEC} seconds"
                f" (checked {len(seen) - 1} of {len(in_scope)}). Please narrow the scope and re-run."
            )
            return
        try:
            result = evaluate_source(source)
        except ScannerError as exc:
            audit("scanner_error", source=str(source), error=str(exc)[:200])
            emit_scanner_error(str(exc))
            return
        except MaskerError as exc:
            audit("mask_failed", source=str(source), error=str(exc)[:200])
            emit_deny(
                f"[SECURITY WARNING] Confidential information was detected in {source}, but "
                f"a safe copy could not be generated.\nReason: {exc}\n"
                "Reading this file is blocked.",
                "Could not generate a masked copy",
            )
            return
        except OSError as exc:
            audit("io_error", source=str(source), error=str(exc)[:200])
            emit_deny(
                f"[SECURITY WARNING] Could not scan {source} ({exc}).\n"
                "Blocked because safety could not be confirmed.",
                "Could not scan the file",
            )
            return
        if result:
            entries.append(result)

    if not entries:
        emit_allow_silently()

    audit("deny", tool=tool_name, count=len(entries),
          sources=[str(s) for s, _, _ in entries][:20])
    emit_deny(
        build_deny_reason(entries, tool_name),
        f"Blocked {tool_name} because confidential information was detected ({len(entries)} file(s))",
    )


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        audit("unexpected_error", error=repr(exc)[:300], scope_confirmed=_scope_confirmed)
        if _scope_confirmed:
            # An unexpected exception while handling a protected file means
            # safety was never confirmed.
            emit_scanner_error(f"an unexpected error occurred during scanning: {exc!r}")
        sys.exit(0)
