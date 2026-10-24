"""Build one test set from the labelled data that was provided, score the system on it, and write reports/test_report.json for the UI's Results tab.

Two scorings of the same unique snippets:
  FIRST LOOK  the predictions that were saved BEFORE each file's expected outputs were read (reports/*_predictions.jsonl).  This is the honest figure: the engine had not
              seen those snippets.  A snippet that appears in several files counts once, at its first appearance.
  NOW         the current engine on the same snippets.  These snippets have since been used to fix the engine, so this is development data; it is shown to document the fixes.
A third block scores the engine on the unique snippets of expanded_dataset.jsonl (also development-informed).

The code itself is NOT written to the report (the files contain placeholder credentials that GitHub's secret scanning rejects); the report carries counts, metrics, ids and
a fingerprint of the test set.   python eval/make_test_report.py
"""
import collections
import hashlib
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.stdout.reconfigure(encoding="utf-8")

from codeguard import pipeline  # noqa: E402
from codeguard.fusion import CATEGORIES  # noqa: E402

D = os.path.join(ROOT, "tests", "data")
R = os.path.join(ROOT, "reports")
# chronological order of the blind runs: (name, code file, expected file, first-look predictions, note)
SOURCES = [("blind run 1", "blind_hidden25_code_only.json", "blind_hidden25_expected.json", "blind_hidden25_predictions.jsonl", "category labels: primary-category style at the time"),
           ("blind run 2", "blind2_code_only.json", "blind2_expected.json", "blind2_predictions.jsonl", "category labels: primary-category style at the time"),
           ("blind run 3", "blind3_code_only.json", "blind3_expected.json", "blind3_predictions.jsonl", ""),
           ("blind run 4", "blind4_code_only.json", "blind4_expected.json", "blind4_predictions.jsonl", ""),
           ("blind run 5", "blind5_code_only.json", "blind5_expected.json", "blind5_predictions.jsonl", ""),
           ("blind run 6", "blind6_code_only.json", "blind6_expected.json", "blind6_predictions.jsonl", "")]


def norm(code: str) -> str:
    return "\n".join(l.rstrip() for l in code.strip().split("\n"))


def load_pred(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        if line.strip():
            d = json.loads(line)
            out[d["id"]] = d.get("output", d)
    return out


def metrics(rows):
    """rows: [{'exp': {...}, 'got': {...}}]"""
    tp = fp = fn = tn = exact = lang = 0
    per = {c: [0, 0, 0] for c in CATEGORIES}
    ctp = cfp = cfn = 0
    risk_err = []
    for r in rows:
        e, g = r["exp"], r["got"]
        pos, blk = e["verdict"] == "block", g["verdict"] == "block"
        tp += pos and blk
        fn += pos and not blk
        fp += (not pos) and blk
        tn += (not pos) and not blk
        es, gs = set(e["categories"]), set(g["categories"])
        exact += es == gs
        lang += g["code_language"] == e["code_language"]
        for c in CATEGORIES:
            per[c][0] += c in es and c in gs
            per[c][1] += c not in es and c in gs
            per[c][2] += c in es and c not in gs
        ctp += len(es & gs)
        cfp += len(gs - es)
        cfn += len(es - gs)
        if pos and blk:
            risk_err.append(abs(g["risk_score"] - e["risk_score"]))
    n = len(rows)
    return {"n": n, "malicious": tp + fn, "benign": fp + tn, "tp": tp, "fp": fp, "fn": fn, "tn": tn, "verdict_accuracy": (tp + tn) / n, "precision": tp / max(tp + fp, 1),
            "recall": tp / max(tp + fn, 1), "false_positive_rate": fp / max(fp + tn, 1), "exact_category_sets": exact / n, "language_accuracy": lang / n,
            "category_precision": ctp / max(ctp + cfp, 1), "category_recall": ctp / max(ctp + cfn, 1), "risk_score_mean_abs_error": sum(risk_err) / max(len(risk_err), 1),
            "per_category": {c: {"tp": v[0], "fp": v[1], "fn": v[2]} for c, v in per.items()}}


def main():
    pipeline.warmup()
    seen: dict = {}
    per_source = collections.OrderedDict()
    dup = 0
    items = []
    for name, cf, ef, pf, note in SOURCES:
        code = {d["id"]: d["code"] for d in json.load(open(os.path.join(D, cf), encoding="utf-8"))}
        exp = {d["id"]: d["output"] for d in json.load(open(os.path.join(D, ef), encoding="utf-8"))}
        pred = load_pred(os.path.join(R, pf))
        kept = 0
        for i, c in code.items():
            key = hashlib.sha256(norm(c).encode()).hexdigest()
            if key in seen:
                dup += 1
                continue
            seen[key] = name
            kept += 1
            items.append({"source": name, "id": i, "code": c, "exp": exp[i], "first": pred[i], "key": key[:12]})
        per_source[name] = {"file_snippets": len(code), "new_unique": kept, "note": note}
    for it in items:
        it["now"] = pipeline.scan(it["code"])
    first = [{"exp": it["exp"], "got": it["first"]} for it in items]
    now = [{"exp": it["exp"], "got": it["now"]} for it in items]
    m_first, m_now = metrics(first), metrics(now)
    by_src = {}
    for name in per_source:
        sub = [{"exp": it["exp"], "got": it["first"]} for it in items if it["source"] == name]
        if sub:
            mm = metrics(sub)
            by_src[name] = {"n": mm["n"], "verdict_accuracy": round(mm["verdict_accuracy"], 4), "false_positives": mm["fp"], "missed_attacks": mm["fn"], "exact_category_sets": round(mm["exact_category_sets"], 4)}
    fp_first = [it["id"] for it in items if it["first"]["verdict"] == "block" and it["exp"]["verdict"] == "allow"]
    fn_first = [it["id"] for it in items if it["first"]["verdict"] == "allow" and it["exp"]["verdict"] == "block"]

    # expanded dataset: unique snippets, current engine (development-informed)
    ex_rows = [json.loads(l) for l in open(os.path.join(ROOT, "expanded_dataset.jsonl"), encoding="utf-8") if l.strip()]
    uniq = {}
    for r in ex_rows:
        uniq.setdefault(norm(r["code"]), r)
    ex = []
    for r in uniq.values():
        res = pipeline.scan(r["code"])
        gold = [] if r["category"] == "benign" else [c.strip() for c in r["category"].split(",")]
        ex.append({"exp": {"verdict": "block" if gold else "allow", "categories": gold, "code_language": r["language"], "risk_score": 1.0 if gold else 0.0}, "got": res})
    m_ex = metrics(ex)

    fp_key = hashlib.sha256("".join(sorted(it["key"] for it in items)).encode()).hexdigest()[:16]
    # the test set itself stays local (it holds placeholder credentials that GitHub's secret scanning rejects)
    with open(os.path.join(D, "test_set_v1.jsonl"), "w", encoding="utf-8") as f:
        for it in items:
            f.write(json.dumps({"id": it["id"], "source": it["source"], "code": it["code"], "expected": it["exp"], "first_look_prediction": {k: it["first"][k] for k in ("verdict", "risk_score", "categories", "code_language", "vulnerable_lines")}}, ensure_ascii=False) + "\n")
    rnd = lambda d: {k: (round(v, 6) if isinstance(v, float) else v) for k, v in d.items()}
    report = {"generated": time.strftime("%Y-%m-%d"), "fingerprint": fp_key, "sources": per_source, "duplicates_skipped": dup,
              "unique_snippets": len(items), "first_look": rnd(m_first), "now": rnd(m_now), "first_look_by_source": by_src,
              "first_look_false_positive_ids": fp_first, "first_look_missed_ids": fn_first,
              "expanded_dataset": {"rows": len(ex_rows), "unique_snippets": len(uniq), **rnd(m_ex)}}
    json.dump(report, open(os.path.join(R, "test_report.json"), "w", encoding="utf-8"), indent=1)
    f_, n_ = m_first, m_now
    print(f"test set: {len(items)} unique snippets ({f_['malicious']} malicious, {f_['benign']} benign) from {len(SOURCES)} blind runs; {dup} repeats skipped; fingerprint {fp_key}")
    print(f"FIRST LOOK: acc {f_['verdict_accuracy']:.3f}  P {f_['precision']:.3f}  R {f_['recall']:.3f}  FP {f_['fp']}/{f_['benign']}  FN {f_['fn']}/{f_['malicious']}  exact {f_['exact_category_sets']:.3f}  cat P/R {f_['category_precision']:.3f}/{f_['category_recall']:.3f}  lang {f_['language_accuracy']:.3f}")
    print(f"NOW       : acc {n_['verdict_accuracy']:.3f}  P {n_['precision']:.3f}  R {n_['recall']:.3f}  FP {n_['fp']}  FN {n_['fn']}  exact {n_['exact_category_sets']:.3f}  cat P/R {n_['category_precision']:.3f}/{n_['category_recall']:.3f}")
    print(f"expanded dataset ({len(uniq)} unique): acc {m_ex['verdict_accuracy']:.3f}  P {m_ex['precision']:.3f}  R {m_ex['recall']:.3f}  FP {m_ex['fp']}/{m_ex['benign']}  FN {m_ex['fn']}/{m_ex['malicious']}  exact {m_ex['exact_category_sets']:.3f}")
    for k, v in by_src.items():
        print("  ", k, v)


if __name__ == "__main__":
    main()
