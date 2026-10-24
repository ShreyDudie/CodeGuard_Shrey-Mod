"""Score full expected outputs (verdict, risk_score, categories, code_language, vulnerable_lines) with pipeline.scan.
    python eval/score_full.py tests/data/user_test50_v2.jsonl
Rows: {"id", "code", "expected_output": {...}}. Lines are scored by exact match and by overlap (Jaccard); risk by band agreement."""
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
    tp = fp = fn = tn = exact = lang = lines_exact = 0
    jac = []
    risk_in_band = 0
    ctp, cfp, cfn = collections.Counter(), collections.Counter(), collections.Counter()
    bad = []
    for r in rows:
        e = r["expected_output"]
        o = scan(r["code"])
        eb, ob = e["verdict"] == "block", o["verdict"] == "block"
        tp += eb and ob
        fn += eb and not ob
        fp += (not eb) and ob
        tn += (not eb) and (not ob)
        c_ok = sorted(o["categories"]) == sorted(e["categories"])
        exact += c_ok
        l_ok = o["code_language"] == e["code_language"]
        lang += l_ok
        a, b = set(o["vulnerable_lines"]), set(e["vulnerable_lines"])
        ln_ok = a == b
        lines_exact += ln_ok
        jac.append(1.0 if not a and not b else len(a & b) / len(a | b))
        risk_in_band += (abs(o["risk_score"] - e["risk_score"]) <= 0.15) or (eb == ob and ((e["risk_score"] >= 0.5) == (o["risk_score"] >= 0.5)))
        for c in CATS:
            if c in e["categories"] and c in o["categories"]:
                ctp[c] += 1
            elif c in o["categories"]:
                cfp[c] += 1
            elif c in e["categories"]:
                cfn[c] += 1
        if not (eb == ob and c_ok and l_ok and ln_ok):
            bad.append((r["id"], "expected", e["verdict"], e["categories"], e["vulnerable_lines"], e["code_language"], "| got", o["verdict"], o["categories"], o["vulnerable_lines"], o["code_language"], o["risk_score"]))
    n = len(rows)
    print(f"n={n} (expected block {tp + fn}, allow {fp + tn})")
    print(f"VERDICT   accuracy {(tp + tn) / n:.3f}  precision {tp / max(tp + fp, 1):.3f}  recall {tp / max(tp + fn, 1):.3f}   TP {tp} FN {fn} FP {fp} TN {tn}")
    print(f"CATEGORIES exact set {exact}/{n} = {exact / n:.3f}   | language {lang}/{n}")
    mt, mf, mn = sum(ctp.values()), sum(cfp.values()), sum(cfn.values())
    print(f"CATEGORY (micro over labels) precision {mt / max(mt + mf, 1):.3f}  recall {mt / max(mt + mn, 1):.3f}   tp {mt} fp {mf} fn {mn}")
    for c in CATS:
        t, f, m = ctp[c], cfp[c], cfn[c]
        if t + f + m:
            print(f"   {c:26} tp={t} fp={f} fn={m}  precision={t / max(t + f, 1):.2f} recall={t / max(t + m, 1):.2f}")
    print(f"LINES     exact {lines_exact}/{n} = {lines_exact / n:.3f}   mean overlap (Jaccard) {sum(jac) / n:.3f}")
    print(f"RISK      same side of 0.5 / within 0.15: {risk_in_band}/{n}  (risk is a heuristic ranking, not a calibrated probability)")
    for b in bad:
        print("MISMATCH", *b)


if __name__ == "__main__":
    main(sys.argv[1])
