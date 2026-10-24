"""The judge-side scoring: submit an answer key, get the metrics comparing it with the service's own predictions.   python tests/test_scoring.py"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from codeguard import pipeline, predlog, scoring  # noqa: E402

SNIPPETS = [
    ("s1", "def add(a, b):\n    return a + b\n", "allow", []),
    ("s2", "import os\nos.system('rm -rf /')\n", "block", ["destructive_command"]),
    ("s3", "import requests\nrequests.get('http://169.254.169.254/latest/meta-data/')\n", "block", ["ssrf_network_exfil"]),
    ("s4", "print('hello')\n", "allow", []),
]


def fresh_log(with_ids=True):
    predlog.clear()
    for ident, code, _v, _c in SNIPPETS:
        res = pipeline.scan(code)
        predlog.record(ident if with_ids else None, code, res, "api")


def check(out, n, acc=1.0):
    assert "error" not in out, out
    assert out["scored"] == n and out["unmatched"] == 0, out["match"]
    assert out["verdict"]["accuracy"] == acc, out["verdict"]
    assert out["categories"]["per_category"], out


def main():
    key = [{"id": i, "output": {"verdict": v, "categories": c, "code_language": "python", "risk_score": 0.9 if v == "block" else 0.0, "vulnerable_lines": [2] if v == "block" else []}}
           for i, _code, v, c in SNIPPETS]

    # 1. matched by id (the requests carried ids)
    fresh_log(True)
    out = scoring.score(json.dumps(key), "key.json")
    check(out, 4)
    assert out["match"]["by_id"] == 4 and out["verdict"]["precision"] == 1.0 and out["verdict"]["recall"] == 1.0
    assert out["categories"]["exact_set_match"] == 1.0 and out["language"]["accuracy"] == 1.0

    # 2. requests had no ids: matched by order
    fresh_log(False)
    out = scoring.score(json.dumps(key), "key.json")
    check(out, 4)
    assert out["match"]["by_order"] == 4

    # 3. the key carries the code: matched by code, in any order
    fresh_log(False)
    keyed = [{"id": "z%d" % n, "code": code, "expected_output": {"verdict": v, "categories": c}} for n, (i, code, v, c) in enumerate(SNIPPETS)][::-1]
    out = scoring.score(json.dumps(keyed), "key.json")
    check(out, 4)
    assert out["match"]["by_code"] == 4

    # 4. a wrong answer in the key is counted
    wrong = [dict(k) for k in key]
    wrong[0] = {"id": "s1", "output": {"verdict": "block", "categories": ["secret_access"]}}
    fresh_log(True)
    out = scoring.score(json.dumps(wrong), "key.json")
    assert out["verdict"]["fn"] == 1 and out["verdict"]["accuracy"] == 0.75, out["verdict"]          # the key says block, the system said allow
    assert any("false negative" in " ".join(it["flags"]) for it in out["items"])

    # 5. CSV key with 0/1 labels
    fresh_log(True)
    csv_key = "id,label,category\n" + "\n".join("%s,%d,%s" % (i, 1 if v == "block" else 0, "|".join(c) or "benign") for i, _code, v, c in SNIPPETS)
    out = scoring.score(csv_key, "key.csv")
    check(out, 4)

    # 6. JSON lines with a flat shape, wrapped lines inside strings (what a PDF text layer gives)
    fresh_log(True)
    flat = "\n".join(json.dumps({"id": i, "verdict": v, "categories": c}) for i, _code, v, c in SNIPPETS)
    wrapped = flat.replace('"verdict": "block", ', '"verdict":\n"block", ')
    out = scoring.score(wrapped, "key.pdf.txt")
    check(out, 4)

    # 7. the key has code that was never requested: scanned on the spot
    predlog.clear()
    out = scoring.score(json.dumps(keyed), "key.json")
    check(out, 4)
    assert out["match"]["scanned_now"] == 4

    # 8. nothing usable
    assert "error" in scoring.score("hello", "key.txt")
    predlog.clear()
    print("scoring ok: id, code, order, csv, labels, wrapped text, scan-on-the-spot, wrong answers")


if __name__ == "__main__":
    main()
