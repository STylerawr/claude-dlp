# Common environment setup for the test suites. Sourced by each suite.
# Paths are resolved from this file's own location, so it still works if the directory is moved.
T="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The working directory at run time. Masked output and temp files are all confined here.
W="$T/work"
mkdir -p "$W"
# Defaults to the hook in the parent directory (hooks/). When run against a
# hook copied elsewhere, this can be overridden with the HOOK env var.
HOOK="${HOOK:-$(dirname "$T")/dlp-masker.py}"

# Fixtures are expanded from `fixtures/*.gz.b64` into work/ on every run.
# This is obfuscation, not encryption, to avoid storing plaintext dummy
# secrets in the repository. gzip is added because base64 alone would let a
# secret scanner decode and detect it.
# If a suite dies partway through, only work/ gets dirtied — permanent assets stay untouched.
S="$W/secrets"
rm -rf "$S"
mkdir -p "$S/cleanonly"
unb64() { base64 -d < "$T/fixtures/$1.gz.b64" | gunzip; }
unb64 app.properties   > "$S/app.properties"
unb64 clean.properties > "$S/clean.properties"
# A "no secrets" directory used to distinguish fail-closed behavior on scan cutoff.
# Testing against a directory containing secrets would give the same answer
# ("secret detected, so deny") even if the cutoff check were broken, making
# this case unable to verify the cutoff path.
# Two files are placed here to exceed MAX_WALK_FILES=1.
cp "$S/clean.properties" "$S/cleanonly/a.properties"
cp "$S/clean.properties" "$S/cleanonly/b.properties"
# List of plaintext strings that must never remain in a masked copy. Expanded the same way.
PLAIN="$W/plaintext.list"
unb64 plaintext.list > "$PLAIN"
# Fixtures for notations other than properties (XML / JSON / YAML / .env), and their plaintext list.
FMT="$S/formats"
mkdir -p "$FMT"
for f in web.config appsettings.json application.yml deploy.env; do
  unb64 "$f" > "$FMT/$f"
done
FPLAIN="$W/formats.plaintext.list"
unb64 formats.plaintext.list > "$FPLAIN"

# The scanner and config file, taken from the same directory as HOOK.
SCANNER="$(dirname "$HOOK")/dlp_scanner.py"
CONFIG="$(dirname "$HOOK")/dlp.config.yaml"
# Call the scanner directly and return the number of findings (used to verify masked-copy re-scans).
scan_count() {
  python3 "$SCANNER" "$CONFIG" "$1" 2>/dev/null \
    | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' 2>/dev/null || echo "ERROR"
}

# Isolation: never use the real environment's TARGET_DIRS / MASK_DIR.
export CLAUDE_DLP_MASKER_TARGET_DIRS="$S"
export CLAUDE_DLP_MASKER_MASK_DIR="$W/masked"
