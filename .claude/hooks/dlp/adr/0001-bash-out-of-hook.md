# 0001: Remove Bash command parsing from the hook and delegate it to `permissions.deny`

[← Back to ADR index](List-Of-ADR.md)

## Status

Accepted

## Background

The `dlp` hook originally tried to statically analyze not only `Read` /
`Grep` but also command strings executed via `Bash` (reads like `cat
<protected file>`) itself, to prevent confidential file content from
leaking.

But it's fundamentally impossible to fully trace shell semantics
statically. Every round of verification turned up a new bypass: delimiter
smuggling, newlines, `#` comments, ANSI-C quoting, line continuations,
nested `bash -c` invocations, `bash script.sh`, `eval`, backticks, brace
expansion, `$IFS`, `BASH_ENV`, and more. The implementation grew past 2000
lines and still couldn't close every gap, and fixing one bypass repeatedly
opened another hole or caused a false positive.

## Decision

Remove Bash command parsing from the hook entirely, and delegate it to
Claude Code's own `permissions.deny`.

Per the official documentation, `Bash(...)` rules in `permissions.deny` are
"applied to whichever subcommand matches, including inside subshells,
command substitution, and control-flow bodies." Leading environment-variable
assignments like `FOO=bar rm -rf tmp/`, and wrappers like `timeout` /
`xargs`, are also stripped by Claude Code itself before matching. We
verified empirically that `cat <protected file>`, `echo hi && cat
<protected file>`, and `bash -c "cat <protected file>"` are all blocked.

The hook side now focuses only on what `permissions.deny` can't provide:
content-based judgment and serving a masked copy. Deny rules are written as
**naming-convention patterns, not file enumerations**, pairing the hook's
`always_target_globs` (`*.pem` `*.key` `id_rsa` `credentials` `.env`
`.netrc` `.pgpass`) with `Bash(*.pem*)` `Bash(*.env*)` `Bash(*id_rsa*)` …
set up in settings.json.

## Consequences

- **Upside**: delegating to Claude Code's own rules is more reliable than
  chasing shell semantics ourselves, and requires far less maintenance. The
  hook becomes slimmer and can focus entirely on content-based judgment for
  Read/Grep.
- **Tradeoff**: reads via `Bash` are no longer judged by the hook at all.
  Since `permissions.deny` matches on path/filename patterns, a filename
  built dynamically via a variable or `$(...)` output (e.g. `cat
  "$(echo <base64> | base64 -d)"`) won't match as a literal string on that
  side either. An asymmetry remains: content-based judgment only exists on
  the Read/Grep path.
- The only remaining gap is secret files with non-conventional names.
  Either add `Bash(*<name>*)` for that one file specifically, rename it to
  match the convention, or accept that `Bash cat` passes it through.
