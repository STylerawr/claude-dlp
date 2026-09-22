#!/usr/bin/env bash
# Tests for dlp_scanner.py's per-notation detection (XML / JSON / YAML / .env),
# filter-word matching rules, and the scanner's standalone I/O contract.
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

# If Read is denied, returns the masked-copy path; otherwise returns the decision prefixed with ERROR:
read_masked() { # read_masked <file>
  payload Read "{\"file_path\":\"$1\"}" | python3 "$HOOK" 2>/dev/null | python3 -c 'import json,re,sys
try:
    o=json.load(sys.stdin)["hookSpecificOutput"]
except Exception:
    print("ERROR:allow"); sys.exit()
m=re.findall(r"(/\S+\.masked[^\s]*)", o["permissionDecisionReason"])
print(m[-1] if o["permissionDecision"]=="deny" and m else "ERROR:"+o["permissionDecision"])'
}

has() { # has <label> <file> <grep -E regex>
  grep -qE -- "$3" "$2" && ok "$1" || ng "$1" "$3" "no match"
}

rm -rf "$W/masked"; mkdir -p "$W/masked"
MASK='\*{8}'

for f in web.config appsettings.json application.yml deploy.env; do
  echo "== $f =="
  src="$FMT/$f"
  m=$(read_masked "$src")
  case "$m" in
    ERROR:*) ng "$f: Read -> deny and masked copy generated" "deny" "$m"; continue ;;
    *)       ok "$f: Read -> deny and masked copy generated" ;;
  esac
  [ "$(wc -l < "$src")" = "$(wc -l < "$m")" ] && ok "$f: line count is preserved" || ng "$f: line count" "$(wc -l < "$src")" "$(wc -l < "$m")"
  n=$(scan_count "$m")
  [ "$n" = "0" ] && ok "$f: re-scanning the masked copy finds 0" || ng "$f: re-scan" "0" "$n"
  eval "M_${f//[^A-Za-z]/_}=\"\$m\""
done

echo "== Residual plaintext =="
leak=0
while IFS= read -r s; do
  [ -z "$s" ] && continue
  if grep -qF -- "$s" "$W"/masked/*.masked.*; then echo "      residual: $s"; leak=1; fi
done < "$FPLAIN"
[ "$leak" = 0 ] && ok "no residual plaintext across all notations" || ng "no residual plaintext across all notations" "0" "found"

echo "== XML (web.config) structure is preserved =="
X="${M_web_config:-/dev/null}"
has "key/value attribute pair"            "$X" "<add key=\"ApiKey\" value=\"$MASK\" />"
has "non-secret key/value is preserved"       "$X" '<add key="ServiceName" value="sample-service" />'
has "Spring-style name/value attribute pair"  "$X" "<property name=\"db.passwd\" value=\"$MASK\" />"
has "attribute written directly"                     "$X" "user=\"mailer\" password=\"$MASK\" />"
has "Password in a connection string"         "$X" "User ID=sa;Password=$MASK\" />"
has "element contents"                     "$X" "<Password>$MASK</Password>"
has "CDATA contents"                   "$X" "<pw><!\[CDATA\[$MASK\]\]></pw>"
has "non-secret element is preserved"             "$X" '<username>sample_admin</username>'

echo "== JSON (appsettings.json) structure is preserved =="
J="${M_appsettings_json:-/dev/null}"
has "string value"                       "$J" "\"Password\": \"$MASK\","
has "numeric value"                           "$J" "\"pin_pw\": $MASK \}"
has "string value containing an escape"       "$J" "\"secret\": \"$MASK\" \}"
has "connection string inside a JSON string"      "$J" "Username=sample_admin;Password=$MASK\""
has "non-secret value is preserved"               "$J" '"Host": "sample-db.example.internal",'

echo "== YAML (application.yml) structure is preserved =="
Y="${M_application_yml:-/dev/null}"
has "double quotes with a trailing comment"       "$Y" "password: \"$MASK\"   # quoted, with a trailing comment"
has "single quotes"                     "$Y" "password: '$MASK'"
has "list item"                     "$Y" "- passwd: $MASK$"
has "non-secret value is preserved"               "$Y" 'username: sample_admin'

echo "== .env (deploy.env) structure is preserved =="
E="${M_deploy_env:-/dev/null}"
has "with export"                    "$E" "^export DB_PASSWORD=$MASK$"
has "quoted"                     "$E" "^API_KEY=\"$MASK\"$"
has "non-secret value is preserved"               "$E" '^APP_NAME=sample-app$'

echo "== Filter-word matching rules =="
K="$W/keys.txt"
kw() { # kw <label> <want count> <line>
  printf '%s\n' "$3" > "$K"
  local n; n=$(scan_count "$K")
  [ "$n" = "$2" ] && ok "$1" || ng "$1" "$2" "$n"
}
kw "apikey"                          1 'apikey=Value123456'
kw "API_KEY (delimiter, uppercase)"      1 'API_KEY=Value123456'
kw "api-key"                         1 'api-key=Value123456'
kw "apiKey (camelCase)"        1 'apiKey=Value123456'
kw "api.key (dot-separated)"         1 'api.key=Value123456'
kw "key containing password"             1 'spring.datasource.password=Value123456'
kw "passwd"                          1 'db_passwd=Value123456'
kw "pwd"                             1 'DB_PWD=Value123456'
kw "pw (as a word)"                1 'cache.pw=Value123456'
kw "pw (camelCase word)"      1 'userPw=Value123456'
kw "key containing secret"               1 'clientSecretValue=Value123456'
kw "short words don't match across word boundaries" 0 'logging.level.org.owasp.webwolf=TRACE'
kw "short words don't match as a substring of a word"   0 'spwn=Value123456'
kw "key with no filter word"     0 'github.token=Value123456'
kw "empty value"                          0 'password='
kw "value of only asterisks"                    0 'password=********'

echo "== Standalone scanner contract =="
printf 'db.password=Value123456\n' > "$K"
got=$(python3 "$SCANNER" "$CONFIG" "$K" | python3 -c 'import json,sys
f=json.load(sys.stdin)[0]; t=open(sys.argv[1]).read()
print("ok" if t[f["start"]:f["end"]]==f["secret"]=="Value123456" else f)' "$K")
[ "$got" = "ok" ] && ok "start/end point at the secret's position" || ng "offsets" "ok" "$got"
printf 'greeting=hello\n' > "$K"
got=$(python3 "$SCANNER" "$CONFIG" "$K")
[ "$got" = "[]" ] && ok "zero findings is an empty array (not null)" || ng "zero-findings output" "[]" "$got"
python3 "$SCANNER" "$W/no-such-config.yaml" "$K" >/dev/null 2>&1
[ "$?" != "0" ] && ok "nonzero exit when the config file is missing" || ng "missing config file" "nonzero" "0"
python3 -c 'import re,sys
t=open(sys.argv[1]).read()
t=re.sub(r"^filter_words:.*$", "filter_words: []", t, count=1, flags=re.M)
open(sys.argv[2], "w").write(t)' "$CONFIG" "$W/nofilter.yaml"
python3 "$SCANNER" "$W/nofilter.yaml" "$K" >/dev/null 2>&1
[ "$?" != "0" ] && ok "nonzero exit when filter_words is empty" || ng "empty filter_words" "nonzero" "0"
python3 "$SCANNER" "$CONFIG" "$W/no-such-file.txt" >/dev/null 2>&1
[ "$?" != "0" ] && ok "nonzero exit when the target file is missing" || ng "missing target file" "nonzero" "0"
rm -f "$K" "$W/nofilter.yaml"

echo "== yaml_lite unit tests =="
YL="$(dirname "$HOOK")"
yl() { # yl <label> <expected repr(dict)> <YAML text>
  local got; got=$(python3 -c 'import sys; sys.path.insert(0, sys.argv[1])
import yaml_lite
print(yaml_lite.parse(sys.argv[2]))' "$YL" "$3" 2>&1)
  [ "$got" = "$2" ] && ok "$1" || ng "$1" "$2" "$got"
}
yl "ignores comment lines and blank lines"       "{'a': 1}" $'# comment\n\na: 1\n'
yl "block list"               "{'a': ['x', 'y']}" $'a:\n  - x\n  - y\n'
yl "flow list (unquoted)"   "{'a': ['x', 'y']}" 'a: [x, y]'
yl "flow list (empty)"           "{'a': []}" 'a: []'
yl "double quotes (surrounding whitespace preserved)" "{'a': ' x '}" 'a: " x "'
yl "integer"                         "{'a': 15}" 'a: 15'
yl "strips a trailing comment"           "{'a': 'x'}" 'a: x  # note'
yl "# inside quotes is not treated as a comment" "{'a': 'x#y'}" 'a: "x#y"'
yl "tilde is kept as a literal string"       "{'a': '~/.claude/masked'}" 'a: ~/.claude/masked'
got=$(python3 -c 'import sys; sys.path.insert(0, sys.argv[1])
import yaml_lite
try:
    yaml_lite.parse("not a valid line")
    print("no-error")
except ValueError:
    print("ValueError")' "$YL" 2>&1)
[ "$got" = "ValueError" ] && ok "a malformed line raises ValueError" || ng "malformed line" "ValueError" "$got"

echo
printf 'Result: PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
