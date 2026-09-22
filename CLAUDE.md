# claude-dlp

A collection of DLP (data-leak prevention) harnesses for Claude Code. See [`README.md`](README.md) (Japanese: [README_ja.md](README_ja.md)) for details.

## Structure

- `.claude/` — Implementation based on the official Claude Code hooks API. **latest**. This directory is the distributable: copying it into a project's root is all it takes to install (see "Installation" in `README.md`).
- `mods/` (`experimental` branch) — Implementation based on patching Claude Code itself. **experimental**. Not present in the `main` working tree.

## .claude/hooks/dlp

A hook that blocks `Read` / `Grep` when they try to read a file containing confidential information, and redirects to a safe copy with the detected spans masked. See [`.claude/hooks/dlp/README.md`](.claude/hooks/dlp/README.md) (Japanese: [README_ja.md](.claude/hooks/dlp/README_ja.md)) for the spec, configuration, and porting steps, and [`.claude/hooks/dlp/adr/List-Of-ADR.md`](.claude/hooks/dlp/adr/List-Of-ADR.md) for the history behind the design decisions.

**This repository applies its own `.claude/` to itself**, so while working here you are subject to it:

- `Read` / `Grep` of files that contain secrets — the samples under `.claude/hooks/dlp/samples/` and the expanded test inputs under `tests/work/` — is denied and redirected to a masked copy. This is expected.
- `Bash` commands whose text matches the `permissions.deny` baseline in `.claude/settings.json` (e.g. anything containing `.env` or `.pem`, such as `git add .claude/hooks/dlp/samples/.env.example`) are denied. Use a form that doesn't name the file (e.g. `git add -A`), or ask the user to run the command.
- Changes to `.claude/settings.json` change what every user who copies `.claude/` gets. Keep it limited to DLP-related rules.

Always run the regression tests after making a change.

```shell
python3 .claude/hooks/dlp/tests/runsuite.py
```

Expected: `regression` PASS=76 / `format_coverage` PASS=64 (all FAIL=0). `runsuite.py` also fails if a PASS count differs from `EXPECTED`, so update `EXPECTED` in `runsuite.py` whenever you add or remove a test.

## ⚠️ Warning: don't expect complete protection from this hook

`.claude/hooks/dlp` is **a best-effort defense, and must not be relied on as the sole safeguard against confidential-information leaks**. Understand the following limitations before using it (see "Known limitations" in [`.claude/hooks/dlp/README.md`](.claude/hooks/dlp/README.md) for details).

- **Detection is based solely on key-name/filter-word matching; value shape is not inspected.** The following can pass through undetected:
  - Credentials embedded in a URL (e.g. `redis://:PASS@host`)
  - Items whose value is a PEM / OpenSSH private-key block
  - **Key files themselves** (`*.pem` / `*.key` / `id_rsa`, etc. are put in scope, but since their contents have no `key=value` pairs, they can be read unscanned)
  - Tokens whose key name contains no filter word (e.g. `github.token`)
  - Values spanning multiple lines (properties line continuations, YAML block scalars)
  - Reads via an existing hard link
- **Reads via `Bash` (`cat` / `grep` / `head`, etc.) are not judged by this hook.** They are covered only by the `Bash(...)` rules in `permissions.deny`, which match on file-name patterns, so a secret file with a non-conventional name remains readable via `Bash`.
- **`Edit` / `Write` are out of scope.** Only the read path is protected; leaks via the write path are not prevented.

As a general principle: **don't put anything within reach of an agent harness like this unless you'd also be fine uploading it to a public internet archive.** This hook is one layer of defense in depth, not the last line.
