"""Convert gitleaks' provider rule set (MIT licence, (c) 2019 Zachary Rice) into rules/secret_patterns.json.

Only data is taken (id, description, regular expression, keywords, minimum entropy); the regexes are adapted from Go syntax to
Python's `re` (inline flags moved to the front, \z -> \Z).  Rules that still do not compile are skipped.
    python scripts/import_gitleaks.py <path to gitleaks/config/gitleaks.toml>
"""
import json
import os
import re
import sys
import tomllib

src = sys.argv[1]
d = tomllib.load(open(src, "rb"))
out, skipped = [], []
for r in d["rules"]:
    rx = r.get("regex")
    if not rx or r["id"] in ("generic-api-key",):
        continue
    flags = ""
    if "(?i)" in rx:
        rx = rx.replace("(?i)", "")
        flags = "i"
    rx = rx.replace("\z", "\Z")
    try:
        re.compile(rx, re.I if flags else 0)
    except re.error:
        skipped.append(r["id"])
        continue
    out.append({"id": r["id"], "description": r.get("description", ""), "regex": rx, "flags": flags, "keywords": [k.lower() for k in r.get("keywords", [])],
                "entropy": r.get("entropy", 0)})
dest = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules", "secret_patterns.json")
json.dump({"source": "gitleaks (MIT) https://github.com/gitleaks/gitleaks", "rules": out}, open(dest, "w", encoding="utf-8"), indent=0)
print(f"{len(out)} rules written, {len(skipped)} skipped: {skipped}")
