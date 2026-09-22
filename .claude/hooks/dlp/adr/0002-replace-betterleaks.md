# 0002: Drop the external scanner betterleaks and replace it with a self-contained Python scanner

[← Back to ADR index](List-Of-ADR.md)

## Status

Accepted

## Background

Until now, the `dlp` hook called the gitleaks-compatible external binary
`betterleaks` via `subprocess` and masked confidential values based on its
findings (JSON: StartLine/EndLine/StartColumn/EndColumn/Match/Secret/RuleID).

This had two problems.

1. **Adoption cost**: the `betterleaks` command had to be on PATH, requiring
   a separate install in everyone's environment. Without it installed,
   fail-closed behavior blocked all access to protected files.
2. **Masking gaps with the default rules**: betterleaks judges by value
   shape (prefix, length, entropy), so values whose shape didn't match a
   rule passed through undetected. In practice, values like `api.key=sk-DUMMY...`
   and AWS keys containing `DUMMY` went undetected (already recorded in the
   old README's "Known limitations"). The combination of paying the
   adoption cost and still getting gaps was the core problem.

## Decision

Drop the dependency on `betterleaks` and replace it with the bundled
`dlp_scanner.py` (standard library only).

Secrets written in config files are almost always stored under a key named
something like `password` or `api_key`. So we switched to judging by "key
name" instead of "value shape" (see [0003](0003-keyword-only-detection.md)
for the details of the detection scope this implies).

The calling convention was kept as a subprocess, same as with
`betterleaks` (rather than importing into the same process), so that a
regex backtracking blowup or similar issue can still be cut off per-process
via `scan_timeout_sec` without freezing the whole hook.

## Consequences

- **Upside**: no external tool install is required anymore. Since detection
  gaps now live in our own code (Python regexes), we can fix, test, and
  extend it ourselves — extending detection is as simple as adding a word
  to `filter_words`.
- **Tradeoff**: the "value-shape"-based detection capability that
  betterleaks had is gone. This was a deliberate choice; see
  [0003](0003-keyword-only-detection.md) for the details and the cost.
- Since we could now define the findings schema ourselves, we redesigned it
  as the simple character-offset format `{"rule_id", "start", "end",
  "secret"}`, and were able to remove entirely the alignment logic (the
  ±1-column fallback search in `_locate_span`, etc.) that used to back-solve
  betterleaks' 1-based inclusive column numbers.
