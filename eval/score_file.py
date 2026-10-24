"""Score a labelled JSONL (fields: code, label, category, language) with the production path (pipeline.scan) and list every mismatch.
    python eval/score_file.py tests/data/user_test50.jsonl
"""
import collections
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.stdout.reconfigure(encoding="utf-8")

from codeguard.pipeline import scan, warmup  # noqa: E402

CATS = ["secret_access", "data_exfiltration", "destructive_command", "persistence_or_privesc", "obfuscated_execution", "dependency_risk",
        "resource_exhaustion", "ssrf_network_exfil", "ai_targeted_instructions"]


def main(path):
    warmup()
    rows = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
    tp = fp = fn = tn = exact = lang_ok = 0
    ctp, cfp, cfn = collections.Counter(), collections.Counter(), collections.Counter()
    bad = []
    for r in rows:
        o = scan(r["code"])
        want = [] if r["label"] == 0 else [x.strip() for x in r["category"].split(",")]
        if r["label"] == 1 and o["verdict"] == "block":
            tp += 1
        elif r["label"] == 1:
            fn += 1
        elif o["verdict"] == "block":
            fp += 1
        else:
            tn += 1
        c_ok = sorted(o["categories"]) == sorted(want)
        exact += c_ok
        l_ok = o["code_language"] == r.get("language", o["code_language"])
        lang_ok += l_ok
        for c in CATS:
            if c in want and c in o["categories"]:
                ctp[c] += 1
            elif c in o["categories"]:
                cfp[c] += 1
            elif c in want:
                cfn[c] += 1
        if not (c_ok and l_ok and (o["verdict"] == "block") == (r["label"] == 1)):
            bad.append((r["id"], r["category"], r.get("language"), o["verdict"], o["categories"], o["code_language"], o["vulnerable_lines"]))
    n = len(rows)
    print(f"n={n} (positives {tp + fn}, benign {fp + tn})")
    print(f"VERDICT  accuracy {(tp + tn) / n:.3f}  precision {tp / max(tp + fp, 1):.3f}  recall {tp / max(tp + fn, 1):.3f}   TP {tp} FN {fn} FP {fp} TN {tn}")
    print(f"CATEGORY exact set match {exact}/{n} = {exact / n:.3f}   language {lang_ok}/{n}")
    for c in CATS:
        t, f, m = ctp[c], cfp[c], cfn[c]
        if t + f + m:
            print(f"  {c:26} tp={t} fp={f} fn={m}  precision={t / max(t + f, 1):.2f} recall={t / max(t + m, 1):.2f}")
    for b in bad:
        print("MISMATCH", b)


if __name__ == "__main__":
    main(sys.argv[1])
