"""Scan-only evaluation on public detector test corpora cloned OUTSIDE this repo (never executed, never imported).
    python eval/external_eval.py <dir> [<dir> ...] [--json out.json]
Prints verdict/categories per file so missed behaviours can be triaged; nothing here changes the detector."""
import json
import os
import sys
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.stdout.reconfigure(encoding="utf-8")

from codeguard import pipeline  # noqa: E402


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    out_json = sys.argv[sys.argv.index("--json") + 1] if "--json" in sys.argv else None
    if out_json:
        args = [a for a in args if a != out_json]
    pipeline.warmup()
    rows = []
    for d in args:
        for dp, _dn, fns in os.walk(d):
            for fn in sorted(fns):
                if not fn.endswith((".py", ".sh", ".js", ".yaml", ".yml", ".md", ".sql")):
                    continue
                p = os.path.join(dp, fn)
                try:
                    code = open(p, encoding="utf-8", errors="replace").read()
                except OSError:
                    continue
                if not code.strip() or len(code) > 200_000:
                    continue
                r = pipeline.scan(code)
                rows.append({"file": os.path.relpath(p, d).replace("\\", "/"), "dir": os.path.basename(os.path.normpath(d)), "verdict": r["verdict"], "cats": r["categories"],
                             "risk": r["risk_score"], "lang": r["code_language"], "reason": r["reason"][:160]})
    c = Counter(r["verdict"] for r in rows)
    print(f"{len(rows)} files: {dict(c)}")
    for r in rows:
        print(f"{r['verdict']:5} {str(r['cats']):52} {r['file']}")
    if out_json:
        json.dump(rows, open(out_json, "w", encoding="utf-8"), indent=1)


if __name__ == "__main__":
    main()
