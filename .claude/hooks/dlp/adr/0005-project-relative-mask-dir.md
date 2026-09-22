# 0005: Move masked-copy storage from `~/.claude/masked` to under the project

[← Back to ADR index](List-Of-ADR.md)

## Status

Accepted

## Background

The storage location for masked files and the audit log (`mask_dir`)
defaulted to `~/.claude/masked`. This was a single location under the home
directory, shared across whichever project on the machine was being worked
on.

A user requested being able to place it under the project directory being
worked in instead (e.g. `~/Projects/WebGoat/.claude/hooks/dlp/masked/`).

## Decision

Changed how a relative `mask_dir` path is resolved. An absolute path
(including one after `~/...` expansion) is still used as-is, but a relative
path is now resolved from `dlp-masker.py`'s own location
(`<repo>/.claude/hooks/dlp/`), and the default value was changed from
`~/.claude/masked` to `masked`. As a result, the default storage location
becomes `<repo>/.claude/hooks/dlp/masked/`.

Note that this differs from `target_dirs`, whose relative-path resolution
is based on the repo root: `mask_dir` is now based on the script's own
directory instead. `target_dirs` names "what to protect," so pointing at a
location inside the repo is natural; `mask_dir` is an accessory of the hook
itself, so tying it to the hook's own directory made more sense.

## Consequences

- **Upside**: each project gets its own independent mask cache, so working
  on multiple projects in parallel no longer mixes their caches. Deleting
  `<repo>/.claude/` now removes the masked copies along with it (previously,
  `rm -rf ~/.claude/masked` had to be run separately). Added `masked/` to
  `.gitignore` to prevent it from being committed by accident.
  - **Tradeoff**: when the same repository is checked out in multiple git
  worktrees, each worktree now gets a separate mask cache (previously, a
  single location under the home directory was shared). To share a cache
  across multiple checkouts, set `mask_dir` to an absolute path.
- Generation itself is performed directly by Claude Code's hook execution
  mechanism (PreToolUse/PostToolUse), so it is unaffected by the sandbox
  applied to the Bash tool in an interactive session (which can be
  configured to deny writes under `.claude/hooks/`). We confirmed that
  writes to `<repo>/.claude/hooks/dlp/masked/` work as expected in practice.
