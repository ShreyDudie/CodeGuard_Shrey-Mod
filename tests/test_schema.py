"""Output-contract check over every fixture, every dev row and a set of malformed inputs.
    python tests/test_schema.py
Rules: exactly the six fields; verdict in {allow, block}; risk in [0, 1]; categories unique and from the nine; block => at least one
category, a reason and at least one line; allow => no categories and no lines; lines sorted, unique, 1-based and inside the text."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
sys.stdout.reconfigure(encoding="utf-8")

from codeguard import pipeline  # noqa: E402
import run_cases  # noqa: E402

CATS = {"secret_access", "data_exfiltration", "destructive_command", "persistence_or_privesc", "obfuscated_execution", "dependency_risk",
        "resource_exhaustion", "ssrf_network_exfil", "ai_targeted_instructions"}
FIELDS = {"verdict", "risk_score", "categories", "code_language", "reason", "vulnerable_lines"}
MALFORMED = ["", " ", "\n\n", "\x00\x01\x02", "{", "}}}}", "def (", "((((((((", "'''", "\"" * 7, "import", "# only a comment", "日本語のテキスト",
             "a" * 50000, "x = " + "(" * 400 + ")" * 400, "\r\n\r\n", "\t\t\t", "<?php echo 1;", "SELECT", "rm -rf", None, 123, ["list"], {"a": 1}]


def check(code, r):
    problems = []
    if set(r) != FIELDS:
        problems.append(f"fields {sorted(set(r) ^ FIELDS)}")
        return problems
    if r["verdict"] not in ("allow", "block"):
        problems.append("verdict")
    if not isinstance(r["risk_score"], (int, float)) or not 0.0 <= r["risk_score"] <= 1.0:
        problems.append("risk_score")
    cats = r["categories"]
    if not isinstance(cats, list) or len(set(cats)) != len(cats) or not set(cats) <= CATS:
        problems.append(f"categories {cats}")
    if not isinstance(r["code_language"], str) or r["code_language"] != r["code_language"].lower() or not r["code_language"]:
        problems.append("code_language")
    if not isinstance(r["reason"], str) or not r["reason"].strip():
        problems.append("reason empty")
    ln = r["vulnerable_lines"]
    n_lines = (len(code.split("\n")) if isinstance(code, str) else 1)
    if not isinstance(ln, list) or ln != sorted(set(ln)) or any((not isinstance(x, int)) or x < 1 for x in ln):
        problems.append(f"lines {ln}")
    elif ln and max(ln) > max(n_lines, 1):
        problems.append(f"line {max(ln)} beyond {n_lines} lines")
    if isinstance(code, str) and isinstance(ln, list):
        rows = code.split(chr(10))
        for x in ln:
            if isinstance(x, int) and 1 <= x <= len(rows):
                t = rows[x - 1].strip()
                if not t:
                    problems.append(f"line {x} is blank")
                elif t.startswith(("def ", "class ", "async def ")) and len(ln) > 1:
                    problems.append(f"line {x} is only a signature")
    if r["verdict"] == "block" and (not cats or not ln):
        problems.append("block without category/lines")
    if r["verdict"] == "allow" and (cats or ln):
        problems.append("allow with category/lines")
    return problems


def main():
    pipeline.warmup()
    rows = [(c[0], c[2]) for c in run_cases.load()]
    dev = os.path.join(ROOT, "codeguard_dev.jsonl")
    if os.path.exists(dev):
        rows += [(d["id"], d["code"]) for d in map(json.loads, open(dev, encoding="utf-8"))]
    rows += [(f"malformed_{i}", c) for i, c in enumerate(MALFORMED)]
    bad = 0
    for id_, code in rows:
        try:
            r = pipeline.scan(code)
        except Exception as e:
            print(f"CRASH {id_}: {type(e).__name__}: {e}")
            bad += 1
            continue
        p = check(code, r)
        if p:
            bad += 1
            print(f"BAD {id_}: {p}")
    print(f"schema: {len(rows)} outputs checked, {bad} problems")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
