#!/usr/bin/env bash
# Full regression tests for dlp-masker.py.
# Runs against isolated TARGET_DIRS / MASK_DIR and tallies PASS/FAIL.
set -uo pipefail
source "$(dirname "$0")/env.sh"

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
ng()   { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s (want=%s got=%s)\n' "$1" "$2" "$3"; }

payload() { # payload <tool> <tool_input_json>
  python3 - "$1" "$2" "$T" <<'PY'
import json, sys
print(json.dumps({"hook_event_name": "PreToolUse", "tool_name": sys.argv[1],
                  "cwd": sys.argv[3], "tool_input": json.loads(sys.argv[2])}))
PY
}

decide() { # decide <tool> <tool_input_json> -> allow|deny|ask|ERROR:...
  # Empty stdout is not assumed to mean "allow" — a hook crash also produces
  # empty output, so allow is only decided once rc, stderr, and whether
  # payload generation succeeded have all been checked.
  local out rc pl err="$W/decide.err"
  pl=$(payload "$1" "$2") || { echo "ERROR:payload generation failed"; return; }
  [ -z "$pl" ] && { echo "ERROR:payload is empty"; return; }
  : > "$err"
  out=$(printf '%s' "$pl" | python3 "$HOOK" 2>"$err"); rc=$?
  [ "$rc" -ne 0 ] && { echo "ERROR:rc=$rc"; return; }
  [ -s "$err" ] && { echo "ERROR:stderr=$(head -c 100 "$err")"; return; }
  [ -z "$out" ] && { echo "allow"; return; }
  printf '%s' "$out" | python3 -c 'import json,sys
try: print(json.load(sys.stdin)["hookSpecificOutput"]["permissionDecision"])
except Exception: print("ERROR:invalid output")'
}

expect() { # expect <label> <want> <tool> <tool_input_json>
  local got; got=$(decide "$3" "$4")
  [ "$got" = "$2" ] && ok "$1" || ng "$1" "$2" "$got"
}

masked_path_of() { # Extract the masked path from the most recent deny response
  payload "$1" "$2" | python3 "$HOOK" 2>/dev/null \
    | python3 -c 'import json,re,sys
r=json.load(sys.stdin)["hookSpecificOutput"]["permissionDecisionReason"]
m=re.findall(r"(/\S+\.masked[^\s]*)", r)
print(m[-1] if m else "")'
}

read_json() { printf '{"file_path":"%s"}' "$1"; }
# A dummy secret value taken from the fixtures-derived list rather than hardcoded here (see README "Tests")
SECRET=$(grep -m1 'DbPass' "$PLAIN")

rm -rf "$W/masked"; mkdir -p "$W/masked"
SRC="$S/app.properties"

echo "== 1. Basic detection and masking =="
expect "Read on target file -> deny"            deny  Read "$(read_json "$SRC")"
M=$(masked_path_of Read "$(read_json "$SRC")")
[ -n "$M" ] && [ -f "$M" ] && ok "masked copy was generated" || ng "masked copy was generated" "exists" "missing"
[ -f "$M.meta.json" ] && ok "meta was generated" || ng "meta was generated" "exists" "missing"
[ "$(stat -c %a "$M")" = "400" ] && ok "masked copy is 0400" || ng "masked copy is 0400" "400" "$(stat -c %a "$M")"
[ "$(stat -c %a "$W/masked")" = "700" ] && ok "MASK_DIR is 0700" || ng "MASK_DIR is 0700" "700" "$(stat -c %a "$W/masked")"

echo "== 2. Correctness of masked content =="
[ "$(wc -l < "$SRC")" = "$(wc -l < "$M")" ] && ok "line count is preserved" || ng "line count is preserved" "$(wc -l < "$SRC")" "$(wc -l < "$M")"
grep -q '^app.password=\*\*\*\*\*\*\*\*$' "$M" && ok "key stays, only the value is masked" || ng "key stays, only the value is masked" "app.password=********" "$(grep '^app.password' "$M")"
grep -q '^service.url=https://sample_admin:\*\*\*\*\*\*\*\*@sample-app-server' "$M" && ok "the same value elsewhere with no key-name clue is also scrubbed" || ng "scrubbing the same value" "masked inside URL too" "not masked"
grep -q '^report.jdbc.url=jdbc:mysql://sample-report-db.*&password=\*\*\*\*\*\*\*\*$' "$M" \
  && ok "only the password in a URL query is masked" || ng "URL query" "connection target stays, only value masked" "$(grep '^report.jdbc.url' "$M")"
grep -q ';User ID=sample_sql;Password=\*\*\*\*\*\*\*\*;Encrypt=True$' "$M" \
  && ok "only Password in a connection string is masked" || ng "connection string" "only Password masked" "$(grep '^sql.connection_string' "$M")"
# If $M is empty, `grep -qF -- "$s" ""` and the scanner both report "no
# match", which would pass even if masking did nothing at all. Fail
# explicitly when empty.
if [ -n "$M" ] && [ -f "$M" ]; then
  resid=0
  while IFS= read -r s; do
    [ -z "$s" ] && continue
    grep -qF -- "$s" "$M" && { echo "      residual: $s"; resid=1; }
  done < "$PLAIN"
  [ "$resid" = 0 ] && ok "no residual detected plaintext" || ng "no residual detected plaintext" "0" "found"
  n=$(scan_count "$M")
  [ "$n" = "0" ] && ok "re-scanning the masked copy finds 0" || ng "re-scanning the masked copy" "0" "$n"
else
  ng "no residual detected plaintext" "masked copy exists" "missing"
  ng "re-scanning the masked copy finds 0" "masked copy exists" "missing"
fi

echo "== 3. Freshness verification =="
expect "Read of masked copy -> allow"                allow Read "$(read_json "$M")"
rm -f "$M"
expect "Read after body GC -> allow (regenerated)"     allow Read "$(read_json "$M")"
[ -f "$M" ] && ok "regenerated at the same path" || ng "regenerated at the same path" "exists" "missing"
mv "$M.meta.json" "$W/meta.bak"
expect "missing meta -> deny"                       deny  Read "$(read_json "$M")"
mv "$W/meta.bak" "$M.meta.json"
cp "$SRC" "$W/src.bak"
echo 'extra.password=AnotherSecretValue!2024' >> "$SRC"
expect "old masked copy after original updated -> deny"     deny  Read "$(read_json "$M")"
NEW=$(ls -t "$W"/masked/*.masked.properties | head -1)
[ "$NEW" != "$M" ] && ok "a new path was issued" || ng "new path" "different path" "same"
expect "new masked copy -> allow"                  allow Read "$(read_json "$NEW")"
cp "$W/src.bak" "$SRC"; rm -f "$W/src.bak"
touch "$SRC"
expect "original only touched (content unchanged) -> masked copy allowed" allow Read "$(read_json "$M")"
cp "$SRC" "$S/gone.properties"
G=$(masked_path_of Read "$(read_json "$S/gone.properties")")
rm -f "$S/gone.properties"
expect "masked copy whose original was deleted -> deny" deny Read "$(read_json "$G")"
cp "$SRC" "$S/cleaned.properties"
C=$(masked_path_of Read "$(read_json "$S/cleaned.properties")")
printf 'greeting=hello\n' > "$S/cleaned.properties"
expect "stale masked copy whose original no longer has secrets -> deny" deny Read "$(read_json "$C")"
rm -f "$S/cleaned.properties"

echo "== 4. Freshness verification also works when walking MASK_DIR =="
rm -rf "$W/masked"; mkdir -p "$W/masked"
decide Read "$(read_json "$SRC")" > /dev/null
expect "Grep on a fresh masked copy -> allow"  allow Grep "{\"pattern\":\"pass\",\"path\":\"$W/masked\",\"output_mode\":\"content\"}"
cp "$SRC" "$W/src.bak"; echo 'later.password=AddedLaterSecret2024!' >> "$SRC"
expect "Grep on a stale masked copy -> deny"   deny  Grep "{\"pattern\":\"pass\",\"path\":\"$W/masked\",\"output_mode\":\"content\"}"
cp "$W/src.bak" "$SRC"; rm -f "$W/src.bak"

echo "== 5. Scope determination =="
expect "clean file -> allow"                  allow Read "$(read_json "$S/clean.properties")"
expect "out-of-scope directory -> allow"              allow Read "{\"file_path\":\"/etc/hostname\"}"
expect "nonexistent file -> allow"                allow Read "$(read_json "$S/nope.properties")"
expect "directory given -> allow"                allow Read "$(read_json "$S")"
expect "Bash is out of scope for the hook -> silent pass-through" allow Bash "{\"command\":\"cat $SRC\"}"
expect "relative file_path is resolved against cwd -> deny" deny Read "{\"file_path\":\"work/secrets/app.properties\"}"
expect "path containing .. -> deny"            deny  Read "$(read_json "$S/../secrets/app.properties")"
mkdir -p "$W/out"
ln -sf "$SRC" "$W/out/link.properties"
expect "symlink from outside scope -> deny"     deny  Read "$(read_json "$W/out/link.properties")"
cp "$SRC" "$S/upper.PROPERTIES"
expect "uppercase extension -> deny"            deny  Read "$(read_json "$S/upper.PROPERTIES")"
cp "$SRC" "$W/out/.ENV"
expect ".ENV (uppercase) in an out-of-scope directory -> deny" deny Read "$(read_json "$W/out/.ENV")"
cp "$SRC" "$S/notes.txt"
expect "non-target extension inside target_dirs -> allow" allow Read "$(read_json "$S/notes.txt")"
mkdir -p "$S/i18n"
cp "$SRC" "$S/i18n/messages.properties"
expect "exclude_globs match -> allow even with secrets" allow Read "$(read_json "$S/i18n/messages.properties")"
cp "$SRC" "$S/i18n/.env"
expect "exclude_globs takes priority over always_target_globs -> allow" allow Read "$(read_json "$S/i18n/.env")"
rm -rf "$W/out" "$S/upper.PROPERTIES" "$S/notes.txt" "$S/i18n"

echo "== 6. Grep =="
expect "Grep files_with_matches -> allow"        allow Grep "{\"pattern\":\"password\",\"path\":\"$S\",\"output_mode\":\"files_with_matches\"}"
expect "Grep count -> allow"                      allow Grep "{\"pattern\":\"password\",\"path\":\"$S\",\"output_mode\":\"count\"}"
expect "Grep content -> deny"                     deny  Grep "{\"pattern\":\"password\",\"path\":\"$S\",\"output_mode\":\"content\"}"
# Target cleanonly/, which contains no secrets. If a directory containing
# secrets were used instead, even a broken cutoff check would still land on
# "secret detected, so deny", and these cases couldn't verify the cutoff path.
CLEANONLY="{\"pattern\":\"x\",\"path\":\"$S/cleanonly\",\"output_mode\":\"content\"}"
expect "Grep on cleanonly with no cutoff -> allow" allow Grep "$CLEANONLY"
got=$(CLAUDE_DLP_MASKER_MAX_WALK_FILES=1 decide Grep "$CLEANONLY")
[ "$got" = "deny" ] && ok "exceeding MAX_WALK_FILES -> deny" || ng "exceeding MAX_WALK_FILES" "deny" "$got"
got=$(CLAUDE_DLP_MASKER_SCAN_BUDGET_SEC=0 decide Grep "$CLEANONLY")
[ "$got" = "deny" ] && ok "zero-second time budget -> deny" || ng "zero-second time budget" "deny" "$got"

echo "== 7. Clean-verdict cache =="
cp "$S/clean.properties" "$S/cached.properties"
decide Read "$(read_json "$S/cached.properties")" > /dev/null
printf 'late.password=%s\n' "$SECRET" >> "$S/cached.properties"
expect "secret added after a clean verdict was cached -> deny" deny Read "$(read_json "$S/cached.properties")"
rm -f "$S/cached.properties"

echo "== 8. Error paths =="
: > "$S/empty.properties"
expect "empty file -> allow"                      allow Read "$(read_json "$S/empty.properties")"
head -c 200000 /dev/urandom > "$S/binary.properties"
got=$(decide Read "$(read_json "$S/binary.properties")")
# `[ a ] || [ b ] && ok || ng` always "succeeds" due to operator precedence, so use case instead
case "$got" in
  allow|deny) ok "no exception on binary input ($got)" ;;
  *)          ng "no exception on binary input" "allow|deny" "$got" ;;
esac
head -c 20000000 /dev/zero | tr '\0' 'a' > "$S/huge.properties"
expect "oversized file -> deny (fail-closed)"  deny  Read "$(read_json "$S/huge.properties")"
rm -f "$S/huge.properties" "$S/binary.properties" "$S/empty.properties"
out=$(printf 'not json' | python3 "$HOOK" 2>&1); rc=$?
[ "$rc" = "0" ] && [ -z "$out" ] && ok "malformed stdin -> silent exit 0" || ng "malformed stdin" "silent rc=0" "rc=$rc out=$out"
printf 'db.password=%s\ninvalid=\xff\xfe\n' "$SECRET" > "$S/badenc.properties"
expect "invalid UTF-8 -> deny"                       deny  Read "$(read_json "$S/badenc.properties")"
B=$(ls -t "$W"/masked/badenc.*.masked.properties 2>/dev/null | head -1)
[ -n "$B" ] && [ "$(od -An -tx1 "$B" | tr -d ' \n' | grep -c 'fffe')" = "1" ] && ok "invalid bytes are preserved" || ng "invalid bytes are preserved" "preserved" "lost"
rm -f "$S/badenc.properties"
printf 'db.user=app\r\ndb.password=%s\r\nname=x\r\n' "$SECRET" > "$S/crlf.properties"
expect "CRLF file -> deny"                       deny  Read "$(read_json "$S/crlf.properties")"
CR=$(ls -t "$W"/masked/crlf.*.masked.properties 2>/dev/null | head -1)
got=$([ -n "$CR" ] && python3 -c 'import sys
d=open(sys.argv[1],"rb").read()
print("ok" if d.count(b"\r\n")==3 and b"db.password=********\r\n" in d else repr(d))' "$CR" || echo "missing")
[ "$got" = "ok" ] && ok "CRLF line endings and line count are preserved" || ng "CRLF preserved" "ok" "$got"
[ -n "$CR" ] && ! grep -qF -- "$SECRET" "$CR" && ok "no plaintext remains in the CRLF masked copy" || ng "CRLF plaintext" "none" "found or missing"
rm -f "$S/crlf.properties"

echo "== 9. Fail-closed and escape hatches =="
cp "$SRC" "$S/unknown.properties"
J=$(payload Read "$(read_json "$S/unknown.properties")")
perm() { python3 -c 'import json,sys
try: print(json.load(sys.stdin)["hookSpecificOutput"]["permissionDecision"])
except Exception: print("ERROR:invalid output")'; }
got=$(printf '%s' "$J" | CLAUDE_DLP_MASKER_CONFIG="$W/no-such-config.yaml" python3 "$HOOK" | perm)
[ "$got" = "deny" ] && ok "missing config file -> deny" || ng "missing config file" "deny" "$got"
{ cat "$CONFIG"; echo 'this line is not valid'; } > "$W/broken.yaml"
got=$(printf '%s' "$J" | CLAUDE_DLP_MASKER_CONFIG="$W/broken.yaml" python3 "$HOOK" | perm)
[ "$got" = "deny" ] && ok "config syntax error -> deny" || ng "config syntax error" "deny" "$got"
python3 -c 'import re,sys
t=open(sys.argv[1]).read()
t=re.sub(r"^scan_timeout_sec:.*$", "scan_timeout_sec: abc", t, count=1, flags=re.M)
open(sys.argv[2], "w").write(t)' "$CONFIG" "$W/badtype.yaml"
got=$(printf '%s' "$J" | CLAUDE_DLP_MASKER_CONFIG="$W/badtype.yaml" python3 "$HOOK" | perm)
[ "$got" = "deny" ] && ok "config item with the wrong type -> deny" || ng "config item with the wrong type" "deny" "$got"
# Read of the config file itself is not stopped (otherwise a broken config could never be read and fixed)
out=$(payload Read "$(read_json "$W/no-such-config.yaml")" | CLAUDE_DLP_MASKER_CONFIG="$W/no-such-config.yaml" python3 "$HOOK")
[ -z "$out" ] && ok "Read of the config file itself passes through even with a broken config" || ng "Read of the config file itself" "silent" "$out"
# The masker's own config is fine; only the scanner fails (filter_words is empty)
python3 -c 'import re,sys
t=open(sys.argv[1]).read()
t=re.sub(r"^filter_words:.*$", "filter_words: []", t, count=1, flags=re.M)
open(sys.argv[2], "w").write(t)' "$CONFIG" "$W/nofilter.yaml"
got=$(printf '%s' "$J" | CLAUDE_DLP_MASKER_CONFIG="$W/nofilter.yaml" python3 "$HOOK" | perm)
[ "$got" = "deny" ] && ok "scanner failure (empty filter_words) -> deny" || ng "scanner failure" "deny" "$got"
got=$(printf '%s' "$J" | CLAUDE_DLP_MASKER_CONFIG="$W/nofilter.yaml" CLAUDE_DLP_MASKER_ON_SCANNER_ERROR=ask python3 "$HOOK" | perm)
[ "$got" = "ask" ] && ok "ON_SCANNER_ERROR=ask -> ask" || ng "ON_SCANNER_ERROR=ask" "ask" "$got"
out=$(printf '%s' "$J" | CLAUDE_DLP_MASKER_CONFIG="$W/nofilter.yaml" CLAUDE_DLP_MASKER_ON_SCANNER_ERROR=allow python3 "$HOOK")
[ -z "$out" ] && ok "ON_SCANNER_ERROR=allow passes through" || ng "ON_SCANNER_ERROR=allow" "silent" "$out"
out=$(printf '%s' "$J" | CLAUDE_DLP_MASKER_DISABLE=1 python3 "$HOOK")
[ -z "$out" ] && ok "DISABLE=1 passes through" || ng "DISABLE=1" "silent" "$out"
rm -f "$S/unknown.properties" "$W/nofilter.yaml" "$W/broken.yaml" "$W/badtype.yaml"

echo "== 10. Concurrency =="
rm -rf "$W/masked"; mkdir -p "$W/masked"
J=$(payload Read "$(read_json "$SRC")")
for i in $(seq 1 10); do
  ( printf '%s' "$J" | python3 "$HOOK" > "$W/c$i.out" 2>"$W/c$i.err"; echo $? > "$W/c$i.rc" ) &
done
wait
[ "$(sort -u "$W"/c*.rc | tr -d '\n')" = "0" ] && ok "all 10 parallel runs exit rc=0" || ng "10 parallel rc" "0" "$(sort -u "$W"/c*.rc | tr '\n' ' ')"
[ "$(find "$W" -name 'c*.err' -size +0 | wc -l)" = "0" ] && ok "no stderr across 10 parallel runs" || ng "10 parallel stderr" "0" "found"
u=$(for i in $(seq 1 10); do python3 -c 'import json,re,sys
r=json.load(open(sys.argv[1]))["hookSpecificOutput"]["permissionDecisionReason"]
print(re.findall(r"(/\S+\.masked[^\s]*)", r)[-1])' "$W/c$i.out"; done | sort -u | wc -l)
[ "$u" = "1" ] && ok "all processes return the same path" || ng "same path" "1 distinct" "${u} distinct"
[ "$(ls "$W"/masked/*.masked.properties | wc -l)" = "1" ] && ok "only one body file" || ng "body count" "1" "$(ls "$W"/masked/*.masked.properties | wc -l)"
[ "$(ls -a "$W/masked" | grep -c '^\.tmp-')" = "0" ] && ok "no leftover temp files" || ng "leftover temp files" "0" "found"

echo "== 11. GC =="
M=$(ls "$W"/masked/*.masked.properties); META="$M.meta.json"
post() { printf '%s' '{"hook_event_name":"PostToolUse","tool_name":"Read","tool_input":{}}' | python3 "$HOOK"; }
age_meta() { # age_meta <seconds since last access> [seconds since creation]
  python3 -c 'import json,sys,time
p=sys.argv[1]; d=json.load(open(p)); d["last_access"]=time.time()-int(sys.argv[2])
if len(sys.argv) > 3: d["created_at"]=time.time()-int(sys.argv[3])
json.dump(d,open(p,"w"))' "$META" "$@"
}
# Checked by outcome, not by comparing .gc-stamp mtimes: two runs within the
# same second would give identical mtimes even if throttling were broken.
rm -f "$W/masked/.gc-stamp"; post
age_meta 700
post
[ -f "$M" ] && ok "GC is throttled while .gc-stamp is fresh" || ng "GC throttling" "expired body kept" "deleted"
rm -f "$W/masked/.gc-stamp"; post
[ ! -f "$M" ] && [ -f "$META" ] && ok "only the body is GC'd, meta is kept" || ng "only body GC'd" "body deleted + meta kept" "body=$([ -f "$M" ] && echo present || echo absent) meta=$([ -f "$META" ] && echo present || echo absent)"
expect "Read after GC -> allow (regenerated)"          allow Read "$(read_json "$M")"
age_meta 700 90000
rm -f "$W/masked/.gc-stamp"; post
[ ! -f "$M" ] && [ ! -f "$META" ] && ok "both deleted once meta TTL expires" || ng "meta TTL" "both deleted" "body=$([ -f "$M" ] && echo present || echo absent) meta=$([ -f "$META" ] && echo present || echo absent)"
printf '%s' "$(payload Read "$(read_json "$SRC")")" | python3 "$HOOK" > /dev/null
M2=$(ls "$W"/masked/*.masked.properties)
for i in $(seq 1 5); do
  ( rm -f "$W/masked/.gc-stamp"; post >/dev/null 2>"$W/gg$i.err" ) &
  ( printf '%s' "$(payload Read "$(read_json "$M2")")" | python3 "$HOOK" >/dev/null 2>"$W/rr$i.err" ) &
done
wait
[ -f "$M2" ] && ok "the current generation survives concurrent GC" || ng "concurrent GC" "current generation survives" "was deleted"
[ "$(find "$W" -name 'gg*.err' -size +0 -o -name 'rr*.err' -size +0 | wc -l)" = "0" ] && ok "no stderr during concurrent GC" || ng "concurrent GC stderr" "0" "found"
[ "$(ls -a "$W/masked" | grep -c 'gc.lock')" = "0" ] && ok "no leftover GC lock" || ng "leftover GC lock" "0" "found"

echo "== 12. Audit log =="
[ -f "$W/masked/audit.log" ] && ok "audit log is written" || ng "audit log" "exists" "missing"
[ "$(stat -c %a "$W/masked/audit.log")" = "600" ] && ok "audit log is 0600" || ng "audit log permissions" "600" "$(stat -c %a "$W/masked/audit.log")"
leak=0
while IFS= read -r s; do
  [ -z "$s" ] && continue
  grep -qF -- "$s" "$W/masked/audit.log" && leak=1
done < "$PLAIN"
[ "$leak" = 0 ] && ok "no secrets leaked into the audit log" || ng "secrets in audit log" "none" "found"

echo
printf 'Result: PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
