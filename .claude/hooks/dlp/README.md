# dlp — Sensitive File Read-Masking Hook

[![English](https://img.shields.io/badge/lang-English-4c9aff?style=for-the-badge)](README.md) [![日本語](https://img.shields.io/badge/lang-日本語-e8618c?style=for-the-badge)](README_ja.md)

A hook that, when Claude Code's `Read` / `Grep` try to read a file containing confidential information, blocks the
read and redirects to a safe copy with the detected spans masked as `********`. It is project-agnostic — replacing
`target_dirs` in `dlp.config.yaml` lets it be ported to any repository.

The scripts embed no absolute paths; they resolve the config file, scanner, and repo root from their own location,
so copying `<repo>/.claude/hooks/dlp/` as a whole keeps working even if the clone path changes.

Detection is performed by the bundled `dlp_scanner.py`. It does not use an external secret scanner; instead it
detects values whose **key name contains a filter word** (`password` / `apikey` / `secret`, etc.) in properties,
YAML, .env, JSON, XML (including .NET `web.config` and Spring XML), connection strings, and URL query strings.

For the history behind this design (why betterleaks was dropped, why Bash is out of scope, why this config format,
etc.) see [`adr/List-Of-ADR.md`](adr/List-Of-ADR.md). This document only explains what it does and how to configure
it.

---

## What it can and can't do

See the sections below ("Known limitations," "Fail-closed policy," etc.) for details. This is the quick-reference version.

| Capability | Status | Notes |
|---|---|---|
| Key-name-based secret detection on `Read`/`Grep` | ✅ Yes | Detects `key=value` in properties/.env/YAML/JSON/XML/connection strings/URL query strings |
| Serving a masked safe copy | ✅ Yes | Detected spans are replaced with `********`, served with freshness verification |
| Automatic re-masking when the original file changes | ✅ Yes | Freshness is verified via a content hash and meta; regenerated once stale |
| Fail-closed on config or scanner failure | ✅ Yes | Blocks reads whenever safety can't be determined (default `deny`) |
| Blocking reads via `Bash` (`cat`/`grep`, etc.) | ❌ No | Requires a separate set of `Bash(...)` rules in `permissions.deny` |
| Preventing leaks via `Edit`/`Write` | ❌ No | Only the read path is protected; writes are out of scope |
| Value-shape-based detection (URL-embedded credentials, PEM/SSH key blocks) | ❌ No | Judges by key name only, so a secret with no shape-independent clue goes undetected |
| Scanning the contents of key files themselves (`*.pem`/`*.key`/`id_rsa`) | ❌ No | They contain no `key=value` to match; protect them separately with `Read(...)` in `permissions.deny` |
| Detecting tokens whose key name contains no filter word | ❌ No | e.g. `github.token`, unless a word is added to `filter_words` |
| Detecting values that span multiple lines | ❌ No | properties line continuations and YAML block scalars are only checked on their first line |
| Blocking reads via an existing hard link | ❌ No | Resolves to a different path even via realpath, so it slips past scope checks |
| Guaranteeing complete protection | ❌ No | A best-effort layer of defense in depth — never rely on it as the only safeguard |

---

## Prerequisite: required setup

This hook alone is **incomplete**. The following three pieces must be provided together. The first two are already
included in this repository's [`.claude/settings.json`](../../settings.json) (the distribution baseline), so copying
the whole `.claude/` directory covers them.

### 1. Hook registration in settings.json

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Read|Grep",
        "hooks": [{ "type": "command",
                    "command": "python3 \"$CLAUDE_PROJECT_DIR/.claude/hooks/dlp/dlp-masker.py\"",
                    "timeout": 30, "statusMessage": "Scanning for secrets..." }] }
    ],
    "PostToolUse": [
      { "matcher": "Read|Grep",
        "hooks": [{ "type": "command",
                    "command": "python3 \"$CLAUDE_PROJECT_DIR/.claude/hooks/dlp/dlp-masker.py\"",
                    "timeout": 20, "async": true }] }
    ]
  }
}
```

Uses `$CLAUDE_PROJECT_DIR`, so it does not depend on the clone path. It is launched via `python3` rather than
directly, so it still works if the executable bit was lost while copying (e.g. when downloading a zip archive).

### 2. Setting up `permissions.deny` (required)

**This hook only looks at the `Read` / `Grep` path.** It does not cover reads via `Bash` (`cat`, `grep`, `head`,
`awk`, …). Those must be blocked separately with `Bash(...)` rules in `permissions.deny`. Either one alone leaves a
gap.

| Path | Owner |
|---|---|
| `Read` / `Grep` tools | **This hook** (content scan + masked copy) |
| `Bash` commands | **`Bash(...)` rules in `permissions.deny`** (path/filename pattern match) |

Write deny rules as **naming-convention patterns, not file enumerations**. Pairing the config file's
`always_target_globs` (`*.pem` `*.key` `id_rsa` `credentials` `.env` `.netrc` `.pgpass`) with
`Bash(*.pem*)` `Bash(*.env*)` `Bash(*id_rsa*)` `Bash(*/.aws/credentials*)` … in settings.json means secret files
named per convention are protected on both paths without per-file handling. The only remaining gap is secret files
with non-conventional names — either add that one file specifically, rename it to match the convention, or accept
that `Bash cat` passes it through (the content-based hook still protects it).

The baseline in this repository's [`.claude/settings.json`](../../settings.json) contains only these DLP-related rules:
`Read(...)` for machine-wide credentials (`~/.ssh`, `~/.aws`, `~/.config/gcloud`, `~/.kube`), and `Bash(...)` for
secret files named by convention. Add rules for your own project's secret files on top of it.

### 3. Dependencies

- Python 3.9+ (standard library only). No external tools need to be installed.

---

## Porting to other projects

1. Copy this repository's whole `.claude/` directory into the project root (`hooks/dlp/tests/work/` and
   `hooks/dlp/samples/` are not needed). That is enough for the hook to work.
2. If the project already has `.claude/settings.json`, don't overwrite it — merge the `hooks` and `permissions.deny`
   entries from this repository's `.claude/settings.json` into it.
3. Narrow `target_dirs` in `dlp.config.yaml` to the directories where confidential files accumulate in that project
   (relative paths are resolved from the repo root).
   > ⚠️ **The default `.` (the whole repository) is meant for trying the hook out. Don't keep it in a real project.**
   > With `.`, every `.properties`/`.yml`/`.json`/`.xml`/… file in the repository is scanned on each `Read`. A `Grep`
   > content search over a large repository also easily exceeds `max_candidates`, so the search is cut off and denied.
   > Specify concrete directories instead (e.g. `src/main/resources`, `config/`).
4. If needed, add key-name words used by that project (e.g. `token`, `credential`) to `filter_words`.
5. Add `Bash(...)` rules to `permissions.deny` for the project's own secret files that don't follow the naming
   convention (see step 2 above).
6. Confirm the regression tests pass with `python3 .claude/hooks/dlp/tests/runsuite.py`.
7. Tune `exclude_globs` per project as an escape valve for false positives (e.g. in WebGoat, the UI label
   `password=Password` triggers a false positive, so `*/i18n/*` is excluded).

---

## Trying it with the samples

`samples/` contains one file per supported format, so you can see what gets detected and how it gets masked. All
values are fake, in the form `sample-...-NOT-REAL`. They deliberately avoid provider-specific shapes (such as `sk-` or
`AKIA`), so secret scanners like GitHub push protection won't flag them. The hook still detects them, because it
judges by key name. Keep new sample values in the same form, and never replace them with realistic tokens.

| File | Notations demonstrated |
|---|---|
| `application.properties` | `line` (`key=value`), `inline` (URL query and connection string), a placeholder false positive, and two known limitations that are **not** detected (`github.token`, a URL-embedded credential) |
| `.env.example` | `line` including `export` and quoted values. Always in scope via `always_target_globs` (`.env.*`), whatever the directory |
| `application.yml` | `line` for nested keys, a quoted value with a trailing comment, and a list item |
| `appsettings.json` | `json` (string and numeric values) and `inline` (a connection string inside a JSON string) |
| `web.config` | `xml-key-value` (`<add key=... value=...>`), `quoted` (attribute), `inline` (connection string), `xml-element` (including CDATA) |
| `settings.ini` | `line` in INI form (`key = value` under a section) |

Run the scanner by itself to list what it would detect (from the `dlp/` directory):

```shell
python3 dlp_scanner.py dlp.config.yaml samples/application.properties
```

In this repository, the hook is active and `target_dirs` defaults to `.`, so simply asking Claude Code to `Read` a
sample file shows the block message and the masked copy. To run the hook directly instead, point `target_dirs` at
`samples/` for a single run; that works regardless of your `target_dirs` setting. The masked copy is written to
`masked/`, which is gitignored:

```shell
printf '{"hook_event_name":"PreToolUse","tool_name":"Read","cwd":"%s","tool_input":{"file_path":"%s/samples/application.properties"}}' "$PWD" "$PWD" \
  | CLAUDE_DLP_MASKER_TARGET_DIRS="$PWD/samples" python3 dlp-masker.py
```

---

## Files included

| File | Event | Role | Enforcement level |
|---|---|---|---|
| `dlp-masker.py` | PreToolUse(Read\|Grep) | Blocks the read and redirects to a masked copy if the protected file contains confidential information | **Block** (`permissionDecision: "deny"`) |
| `dlp-masker.py` | PostToolUse(Read\|Grep) | Garbage-collects masked files | Side effect only (no decision) |
| `dlp_scanner.py` | — (launched as a subprocess by the masker) | Keyword-based confidential-information detection | — |
| `dlp.config.yaml` | — | All configuration (scope, filter words, TTLs, etc.) | — |
| `yaml_lite.py` | — | Self-contained minimal YAML-subset parser used to read the config file above | — |
| `tests/` | — | Full regression/attack test suite (see "Tests" at the end) | — |
| `samples/` | — | Sample config files with fake secrets, one per supported format (see "Trying it with the samples") | — |

---

## Key design decisions and their background

The following are deliberate design decisions; see the corresponding ADR for why.

| Decision | ADR |
|---|---|
| Bash command parsing is not done here; delegated to `permissions.deny` | [0001](adr/0001-bash-out-of-hook.md) |
| Dropped the external scanner betterleaks in favor of a self-contained Python scanner | [0002](adr/0002-replace-betterleaks.md) |
| Detection is limited to key-name/filter-word matching; value shape is not inspected | [0003](adr/0003-keyword-only-detection.md) |
| Config file uses a self-contained YAML subset instead of JSON | [0004](adr/0004-config-format-yaml-subset.md) |
| Masked-copy storage lives under the project (`<repo>/.claude/hooks/dlp/masked/`) | [0005](adr/0005-project-relative-mask-dir.md) |

---

## dlp-masker.py

### What it does

When `Read` / `Grep` try to read a protected file, `dlp_scanner.py` scans it. If confidential information is
detected, the original operation is blocked and a safe copy — with detected spans replaced by `********` — is
generated under `mask_dir` (default `<repo>/.claude/hooks/dlp/masked/`), and that path is presented to Claude.

### Configuration

Everything is written in `dlp.config.yaml`. It is not read as full YAML; instead it's read by a self-contained
subset parser (`yaml_lite.py`) that only supports comments, flat `key: value` pairs, and string arrays (both flow
`[a, b]` and block `- a` forms). Full YAML features such as anchors or nested maps are not supported (a deliberate
tradeoff to avoid depending on an external parser). Each item can be temporarily overridden via the environment
variable `CLAUDE_DLP_MASKER_<UPPERCASE_ITEM_NAME>` (e.g. `target_dirs` → `CLAUDE_DLP_MASKER_TARGET_DIRS`).

| Item | Default | Meaning |
|---|---|---|
| `target_dirs` | `["."]` | Protected directories. Relative paths are resolved from the repo root (`:`-separated in the env var). **The default `.` (whole repository) is for trying the hook out; in a real project, narrow it to specific directories** (see "Porting to other projects") |
| `target_extensions` | `.properties .env .yml .yaml .json .ini .conf .cfg .toml .xml .config .pem .key .p12 .jks` | Files under `target_dirs` with these extensions are in scope (`,`-separated in the env var) |
| `always_target_globs` | `.env`, `.env.*`, `*.pem`, `*.key`, `id_rsa`, `credentials`, `.netrc`, `.pgpass`, etc. | Always in scope regardless of directory (case-insensitive) |
| `exclude_globs` | `*/i18n/*`, `*/node_modules/*`, `*/.git/*` | **Highest-priority exclusion.** Escape valve for when false positives block work |
| `filter_words` | `apikey`, `password`, `passwd`, `pwd`, `pw`, `secret` | Values whose key name contains one of these are treated as secrets (see "How detection works" below). Cannot be overridden via env var |
| `mask_dir` | `masked` | Where masked files are stored (mode 0700). A relative path is resolved from this file's location (`<repo>/.claude/hooks/dlp/`). Use an absolute path (e.g. `~/.claude/masked`) to share across projects |
| `on_scanner_error` | `deny` | Behavior when scanning cannot be performed (`deny` / `ask` / `allow`) |
| `scan_timeout_sec` | `15` | Time limit per scanner invocation |
| `max_target_mb` | `10` | Files larger than this are denied without scanning |
| `max_candidates` / `max_walk_files` | `200` / `20000` | Upper bounds for Grep directory traversal |
| `scan_budget_sec` | `18` | Overall time budget for scanning; denies if exceeded |
| `body_ttl_sec` / `meta_ttl_sec` / `cache_ttl_sec` | `600` / `86400` / `86400` | Retention (seconds) for masked bodies / metadata / clean cache |
| `gc_interval_sec` / `gc_lock_stale_sec` | `60` / `300` | GC sweep interval / age (seconds) after which a stale GC lock may be taken over |
| `min_scrub_len` | `8` | Minimum length for the second-pass residual-secret cleanup |
| `audit_max_bytes` | `1000000` | Size at which the audit log is rotated |

Besides the config file, the following environment variables exist.

| Env var | Meaning |
|---|---|
| `CLAUDE_DLP_MASKER_CONFIG` | Overrides the config file path (default: `dlp.config.yaml` in the same directory) |
| `CLAUDE_DLP_MASKER_DISABLE` | Set to `1` to disable the whole hook (emergency escape hatch) |

If the config file cannot be read, is syntactically broken, has missing items, or has items of the wrong type, the
scope of protection itself cannot be determined, so **all `Read` / `Grep` calls are stopped per
`on_scanner_error`** (default `deny` when the config is broken). The one exception is that `Read` of the config
file itself is always allowed — otherwise there would be no way to read and fix a broken config.

### How detection works (dlp_scanner.py)

It can also be run standalone: `python3 dlp_scanner.py <config> <target file>`. It writes findings to stdout as a
JSON array of `[{"rule_id", "start", "end", "secret"}, ...]` (`start` / `end` are 0-based, half-open offsets into
the string decoded as UTF-8 with `surrogateescape`; zero findings is `[]`).

#### Key-name matching

- Filter words of 4+ characters are matched by **substring match** against the key name lowercased with
  non-alphanumeric characters stripped. `api_key` / `api-key` / `apiKey` / `API.KEY` / `gcp.api_key` all match
  `apikey`, and `spring.datasource.password` and `clientSecretValue` match too.
- Short words of 3 characters or fewer (`pw` / `pwd`) are matched by **exact word match** after splitting the key
  name on delimiters and camelCase boundaries. Substring matching would cause massive false positives from keys
  that happen to contain `pw`, e.g. `org.owasp.webwolf` → `orgowaspwebwolf`. `cache.pw` / `DB_PWD` / `userPw`
  match; `spwn` does not.
- Empty values, and values that are only asterisks (an already-masked `********`), are not treated as secrets.
  Without this exclusion, re-scanning a masked copy would detect its own mask and verification would never pass.

#### Supported notations

| `rule_id` prefix | Notation | Example (masked portion shown as `[...]`) |
|---|---|---|
| `line` | Line-leading `key=value` / `key: value` (properties / .env / YAML / INI / TOML). YAML list items and `export` are also supported. If the value starts with a quote, only the contents are masked | `db.password=[...]`, `password: "[...]"   # comment`, `export DB_PASSWORD=[...]` |
| `json` | JSON `"key": "value"` / `"key": <number>` | `"Password": "[...]"`, `"pin_pw": [...]` |
| `quoted` | Quoted `key="value"` (e.g. XML attributes) | `<smtp user="mailer" password="[...]" />` |
| `xml-key-value` | The key name is written as an attribute **value**, with the secret in the `value` attribute (`key` / `name` attributes) | `<add key="ApiKey" value="[...]" />`, `<property name="db.passwd" value="[...]" />` |
| `xml-element` | Contents of an XML element (including CDATA) | `<Password>[...]</Password>`, `<pw><![CDATA[[...]]]></pw>` |
| `inline` | Unquoted `key=value` (connection strings, URL query strings). Values run until `; & " ' < >` or end of line | `User ID=sa;Password=[...];`, `?user=a&password=[...]` |

When multiple notations detect the same span, the ranges are merged for masking (the wider one wins, erring on the
safe side).

To avoid the whole hook freezing from a regex backtracking blowup, the scanner is launched as a subprocess rather
than imported into the same process as the masker, and is cut off after `scan_timeout_sec`. A 10 MB document takes
just under 2 seconds (even the max size stays within the time limit).

### Staleness handling (a core design point)

If masked copies stick around, they can be read even after the original file has been updated, serving stale
content. Three layers prevent this.

1. **Content addressing** — the masked-copy path includes a hash of the original file's content
   (`<stem>.<pathhash8>-<contenthash8>.masked<ext>`). Since any change to the original always produces a different
   path, reading even an old path still returns "the correct masked version as of that content" — never a lie.
2. **Freshness verification** — access to a masked copy is never passed through blindly; it's checked against the
   sidecar `*.meta.json`. If `(mtime, size)` match, it's allowed immediately; if the hash has changed, it's
   re-masked, the new path is presented, and the request is denied.
3. **Sweeping GC** — triggered from PostToolUse, only entries past their TTL are deleted.

**"Delete right after reading" was rejected.** `Read` only reads up to 2000 lines by default, so large files are
read multiple times with different `offset`s. Deleting immediately after the first read would make the second read
hit ENOENT. It would also risk deleting a file while a different process's agent is still reading it.

GC **keeps only the body short-lived, while the meta acts as a persistent index.** Even if the body is gone, the
path "no body + hash matches → regenerate at the same path and allow" keeps working, so ENOENT is normally never
seen. The meta contains no secrets, so keeping it around longer poses no risk.

### Concurrency

Multiple processes on the same machine, same user (subagents, sessions in other terminals, background jobs) are
assumed.

- Generation is atomic via `mkstemp` → `os.replace`. Because of content addressing, concurrent processes write the
  same content, so whichever one wins, the result is correct
- GC acquires `.gc.lock` via `O_CREAT|O_EXCL`. A stale lock older than 5 minutes may be taken over
- GC only deletes entries whose TTL has passed since last access, so the generation currently being read is never
  deleted
- `FileNotFoundError` from `unlink` is swallowed (normal if another process already deleted it)

Measured: with 10 processes launched simultaneously, all return the same path, with no leftover temp files or
errors.

### Fail-closed policy

Nothing passes through when safety cannot be confirmed. All of the following result in `deny`.

- Config file unreadable / broken / missing items (all `Read`/`Grep` except reading the config file itself)
- Scanner failed to launch / exited non-zero (including when `filter_words` is empty) / timed out / produced
  invalid output
- File exceeds `max_target_mb` and cannot be scanned
- Scanner returned out-of-range position info
- **Re-scanning the generated masked copy failed** (an unverified copy is never published)
- Grep's directory traversal hit its cap and was cut off (some files remain unscanned)
- An unexpected exception occurred after the file was determined to be protected

Conversely, failures that occur *before* a file is determined to be protected (e.g. malformed stdin JSON, an
exception during candidate collection) are passed through, since there is no basis for intervention.

### Known limitations

- **Secrets with no clue in the key name are not detected.** Detection is based solely on key-name/filter-word
  matching. The following pass through unless the same value also appears elsewhere in the file under a
  recognized key name (see residual cleanup below):
  - Credentials embedded in a URL (`redis.url=redis://:PASS@host`, `mongodb.uri=mongodb://user:PASS@host`)
  - Items whose value is a PEM / OpenSSH private-key block, e.g. `tls.private_key=-----BEGIN ...`
  - **Key files themselves.** `*.pem` / `*.key` / `id_rsa` are put in scope by `always_target_globs`, but since
    their contents have no `key=value` pairs, nothing is detected and **they can be read as-is**. These must be
    stopped with `Read(...)` rules in `permissions.deny` (e.g. `Read(~/.ssh/**)`)
  - Tokens whose key name doesn't contain a filter word (`github.token`, `slack.bot_token`,
    `aws.access_key_id`, etc.). Add words like `token` to `filter_words` if needed (a tradeoff against false
    positives)
- **Values spanning multiple lines are not handled.** properties line continuations (trailing `\`) and YAML block
  scalars (`|` / `>`) are read only on their first line. Multi-line support exists only for the contents of XML
  elements and for `key`/`name` + `value` attribute pairs.
- **Values that contain a filter word but aren't actually secrets are still masked.** A placeholder like
  `server.ssl.key-store-password=${ENV:default}` is also masked, redirecting reads of that file to the masked
  copy. Add the path to `exclude_globs` if this gets in the way.
- **Reads via `Bash` are not judged by this hook.** They're protected by `Bash(...)` rules in `permissions.deny`.
  Since those rules match on path/filename patterns, filenames built dynamically via variables or `$(...)` output
  (e.g. `cat "$(echo <base64> | base64 -d)"`) won't match as a literal string either. Content-based judgment only
  exists on the Read/Grep path.
- **Reads via an existing hard link are not detected.** A hard link resolves to a different path even via
  realpath, so a link placed outside the protected directory slips through scope checks.
- **`Edit` / `Write` are out of scope.** Blocking `Edit` would make `old_string` impossible to construct, making
  confidential files uneditable, so only the read path is protected. Leaks via the write path are not prevented.
- **Secrets shorter than `min_scrub_len` skip the second-pass cleanup.** This avoids the risk of collaterally
  damaging unrelated spans. If the same short value appears elsewhere without a recognized key name, it remains
  unmasked there.

### Operations

- Audit log: `mask_dir/audit.log` (default `<repo>/.claude/hooks/dlp/masked/audit.log`; mode 0600, rotated at
  `audit_max_bytes`). Secrets themselves are never logged
- If false positives are blocking work, add the path to `exclude_globs`
- If detection is missing something, add a word to `filter_words`. Running the scanner standalone —
  `python3 dlp_scanner.py dlp.config.yaml <file>` — shows exactly what would be detected
- Rollback: deleting `<repo>/.claude/hooks/dlp/` and removing the hook registration from settings.json also
  removes `mask_dir` (since the default lives under the repo). If `mask_dir` has been changed to an absolute path,
  `rm -rf` that separately

### Design notes

- To allow a request, the code does **a silent `exit 0`** rather than returning `permissionDecision: "allow"`. An
  explicit allow would bypass the normal permission flow, including `permissions.deny`.
- The scanner treats "zero findings" as meaning safe, so in situations where a determination cannot be made
  (config unreadable, `filter_words` empty), it never returns an empty array — it always exits non-zero. The
  masker treats that as a `ScannerError` and fails closed.
- Replacement is position-based (`start` / `end`) and preserves any newlines within the range, so the **original
  line count is preserved**. If the position no longer matches `secret` (e.g. the original file was rewritten
  after scanning), the entire line is blanked out instead.
- Since detection is keyed off the key name, only the value immediately following the key is masked; the
  destination in `db.url` or other non-secret items remain readable.
- After position-based replacement, if the detected `secret` still appears elsewhere in the file, that occurrence
  is cleaned up too — since detection is key-name based, the same value appearing somewhere without a recognized
  key name (e.g. the same password embedded in `service.url`) would otherwise go undetected.
- Every generated masked copy is re-scanned; if findings remain, the masked copy is not served — only a deny is
  returned.
- Since a single tool call can reference both a masked copy and a protected file, candidates from each are
  evaluated separately, **checking both**.

---

## Tests

The full test suite lives in `tests/`. Run everything and get a summary with one command:

```shell
python3 .claude/hooks/dlp/tests/runsuite.py
```

Expected results: `regression` PASS=76, `format_coverage` PASS=64 (all FAIL=0). Exit code is 0 if everything
passes, 1 if any suite fails, with the failing suite's output shown. `runsuite.py` also fails when a suite's PASS
count differs from its expected value (`EXPECTED` in `runsuite.py`), so a silently skipped test can't slip through —
update `EXPECTED` whenever you add or remove a test.

In projects with `sandbox.enabled`, tests run in a plain shell outside the sandbox (since Claude Code makes
`.claude/` read-only-protected and `tests/work/` cannot be created there). To verify inside the sandbox, copy the
entire `dlp/` directory to a writable location and run `tests/runsuite.py` there (all paths are resolved from the
script's own location).

| File | Role |
|---|---|
| `runsuite.py` | Entry point that runs every suite, aggregates PASS/FAIL, and checks PASS counts against `EXPECTED` |
| `regression.sh` | 76 cases for `dlp-masker.py` (detection, mask content, freshness verification including MASK_DIR walks, scope checks including symlinks / relative paths / `exclude_globs`, Grep and scan cutoff, clean-verdict cache, error paths including CRLF, fail-closed and escape hatches, 10-process concurrency, GC, audit log) |
| `format_coverage.sh` | 64 cases (XML / JSON / YAML / .env detection and post-mask structure, filter-word matching rules, the scanner's standalone I/O contract, `yaml_lite` unit tests) |
| `env.sh` | Defines the isolated environment; each suite `source`s it |
| `fixtures/*.gz.b64` | Seeds for test input and expected values; expanded into `work/` on every run |
| `work/` | Working directory created at run time; safe to delete, regenerated automatically |

`env.sh` resolves paths from its own location, so it keeps working even if the directory is moved. The `HOOK`
environment variable can override the hook's path in that case (default: `dlp-masker.py` in the parent directory;
the scanner and config file are also taken from the same directory as `HOOK`).

Tests swap in `tests/work/secrets` for `TARGET_DIRS` and `tests/work/masked` for `MASK_DIR`, so they never touch
the real environment (the actual `target_dirs` directories or the default `mask_dir`). Masked output, temp files,
and even the test input itself are all confined to `tests/work/`.

The contents of `work/` are as follows, recreated by `env.sh` on every run.

| Artifact | Role |
|---|---|
| `secrets/app.properties` | properties test input containing dummy secrets (the scanner detects 13 of them) |
| `secrets/clean.properties` | Control file containing no secrets |
| `secrets/cleanonly/{a,b}.properties` | A secret-free directory used solely to distinguish fail-closed behavior on scan cutoff |
| `secrets/formats/` | `web.config` / `appsettings.json` / `application.yml` / `deploy.env` (test input for notations other than properties) |
| `plaintext.list` / `formats.plaintext.list` | List of plaintext strings that must never remain in a masked copy |

**Test inputs are deliberately not stored as plaintext in the repository.** All values are fictional, but a secret
scanner like GitHub's push protection could still react to their shape and reject the push. So they're stored gzip
+ base64 encoded in `fixtures/*.gz.b64` and expanded at run time. The "list of plaintext strings that must never
remain in a masked copy" is stored the same way, in `fixtures/*plaintext.list.gz.b64`, and expanded into `work/`
before comparison. **This is obfuscation, not encryption.**

Base64 alone isn't enough. gitleaks-style scanners decode base64 before scanning, so plain base64 was detected as
`gitlab-pat` / `stripe-access-token`. Wrapping it in gzip turns the decoded result into binary data that isn't
detected. Conversely, since this is only this level of obfuscation, **never put a real secret in here.**

When regenerating fixtures, compress the plaintext with `gzip -n` before base64-encoding it (`-n` omits the
filename and timestamp, so identical content always produces identical output).

`tests/secrets/` is not kept as a permanent file that gets appended to and restored during tests. If a suite dies
partway through, it wouldn't be restored, risking a commit of a dirtied fixture. Anything under `work/` is already
`.gitignore`d, so permanent assets stay untouched no matter when execution is interrupted.
