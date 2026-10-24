"""Evaluate CodeGuard on a labelled jsonl file (fields: code, language, category, label, id).

usage: python eval/run_eval.py data/dev.jsonl [--no-models] [--verbose] [--report reports/dev_report.md]
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

from codeguard import CATEGORIES, pipeline  # noqa: E402


def load(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def gold_cats(r):
    c = r.get("category", "")
    if r.get("label", 0) == 0 or c == "benign":
        return set()
    return {x.strip() for x in c.split(",") if x.strip()}


def evaluate(rows, use_models=True, verbose=False):
    tp = fp = tn = fn = 0
    lat = []
    per = {c: [0, 0, 0] for c in CATEGORIES}   # tp, fp, fn
    wrong = []
    lang_ok = lang_n = 0
    exact = 0
    n_pos = 0
    for r in rows:
        t0 = time.perf_counter()
        out = pipeline.scan(r["code"], use_models=use_models)
        lat.append((time.perf_counter() - t0) * 1000)
        pred_block = out["verdict"] == "block"
        gold_block = r["label"] == 1
        gc = gold_cats(r)
        pc = set(out["categories"])
        if gold_block and pred_block:
            tp += 1
        elif gold_block and not pred_block:
            fn += 1
        elif not gold_block and pred_block:
            fp += 1
        else:
            tn += 1
        if gold_block:
            n_pos += 1
            if pc == gc:
                exact += 1
        for c in CATEGORIES:
            if c in gc and c in pc:
                per[c][0] += 1
            elif c in pc and c not in gc:
                per[c][1] += 1
            elif c in gc and c not in pc:
                per[c][2] += 1
        lang_n += 1
        if r.get("language") == out["code_language"]:
            lang_ok += 1
        if pred_block != gold_block or (gold_block and pc != gc):
            wrong.append((r["id"], r.get("category"), out["verdict"], sorted(pc), out["risk_score"], out["reason"][:160]))
    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    acc = (tp + tn) / max(1, len(rows))
    res = {
        "n": len(rows), "tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": prec, "recall": rec, "f1": f1, "accuracy": acc,
        "category_exact_match": exact / max(1, n_pos), "language_accuracy": lang_ok / max(1, lang_n),
        "latency_ms": {"p50": statistics.median(lat), "p95": sorted(lat)[int(0.95 * (len(lat) - 1))], "max": max(lat), "mean": statistics.mean(lat)},
        "per_category": {c: {"tp": v[0], "fp": v[1], "fn": v[2],
                             "precision": v[0] / (v[0] + v[1]) if v[0] + v[1] else None,
                             "recall": v[0] / (v[0] + v[2]) if v[0] + v[2] else None} for c, v in per.items()},
        "wrong": wrong,
    }
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--no-models", action="store_true")
    ap.add_argument("--report")
    args = ap.parse_args()
    rows = load(args.path)
    res = evaluate(rows, use_models=not args.no_models)
    print(f"n={res['n']}  acc={res['accuracy']:.3f}  precision={res['precision']:.3f}  recall={res['recall']:.3f}  f1={res['f1']:.3f}  "
          f"FP={res['fp']} FN={res['fn']}  cat-exact={res['category_exact_match']:.3f}  lang={res['language_accuracy']:.3f}")
    print("latency ms:", {k: round(v, 2) for k, v in res["latency_ms"].items()})
    for c, v in res["per_category"].items():
        if v["tp"] + v["fp"] + v["fn"]:
            print(f"  {c:<26} tp={v['tp']:<3} fp={v['fp']:<3} fn={v['fn']:<3}")
    for w in res["wrong"]:
        print("  WRONG", w)
    if args.report:
        os.makedirs(os.path.dirname(args.report) or ".", exist_ok=True)
        with open(args.report, "w", encoding="utf-8") as f:
            json.dump(res, f, indent=2)


if __name__ == "__main__":
    main()
