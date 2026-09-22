#!/usr/bin/env python3
"""Runs every test suite and aggregates the results.

Bash command parsing was removed from the hook and delegated to
permissions.deny, so the Bash-parsing suites (vfix2-vfix6, bashcases, vgit)
were retired, and vfix_core was merged into regression.

Each suite's PASS count is also checked against EXPECTED, so a test that is
silently skipped (or added without updating EXPECTED) fails the run instead
of passing with FAIL=0.
"""
import os
import re
import subprocess
import sys

# Suites are resolved from this script's own location, so it still works if the directory is moved.
T = os.path.dirname(os.path.abspath(__file__))
EXPECTED = {"regression": 76, "format_coverage": 64}
ok_all = True

for s, want in EXPECTED.items():
    r = subprocess.run(["bash", os.path.join(T, f"{s}.sh")], capture_output=True, text=True)
    m = re.search(r"Result: PASS=(\d+) FAIL=(\d+)", r.stdout)
    print(f"{s:17s}{m.group(0) if m else '(no result line)'}")
    if m and int(m.group(1)) != want:
        print(f"  expected PASS={want}: a test was skipped, or one was added/removed without updating EXPECTED")
    if not m or int(m.group(2)) != 0 or int(m.group(1)) != want:
        ok_all = False
        print(r.stdout[-3000:])
        print(r.stderr[-1000:])

sys.exit(0 if ok_all else 1)
