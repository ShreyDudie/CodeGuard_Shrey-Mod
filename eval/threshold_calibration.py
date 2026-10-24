"""Are the decision thresholds in the right place?  Data-driven check of BLOCK_T / CAT_MIN and of the 'hedged' signals that sit close to them.

For every labelled snippet (organiser dev rows, every blind file, the user's files, the semantic set; my own fixtures are listed separately) it takes the engine's
per-category scores and reports
  1. how well the top score separates malicious from benign (AUC) and the verdict metrics for a sweep of BLOCK_T,
  2. a leave-one-set-out choice of BLOCK_T / per-category CAT_MIN: tune on all other sets, score on the held-out set,
  3. the correct decisions that are fragile (top score within 0.12 of the threshold) and the rules behind them.
    python eval/threshold_calibration.py
"""
import collections
import os
import sys

import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "eval"))
sys.stdout.reconfigure(encoding="utf-8")

import benchmark                       # noqa: E402
from codeguard import fusion, pipeline  # noqa: E402

CATS = fusion.CATEGORIES


def collect():
    suites = benchmark.load_suites()
    pipeline.warmup()
    rows = []
    for name, items in suites.items():
        for r in items:
            a = pipeline.analyze(r["code"])
            cs = {c: float(a.fused["cat_scores"].get(c, 0.0)) for c in CATS}
            rules = {c: [(f.rule, round(f.weight, 2)) for f in a.fused["groups"].get(c, [])[:3]] for c in CATS}
            rows.append({"set": name, "id": r["id"], "label": int(r["label"]), "gold": set(r["cats"]), "cs": cs, "top": max(cs.values()) if cs else 0.0, "rules": rules})
    return rows


def auc(pos, neg):
    if not pos or not neg:
        return float("nan")
    p, n = np.array(pos), np.array(neg)
    return float(np.mean([(x > n).mean() + 0.5 * (x == n).mean() for x in p]))


def verdict_metrics(rows, t):
    tp = sum(1 for r in rows if r["label"] and r["top"] >= t)
    fn = sum(1 for r in rows if r["label"] and r["top"] < t)
    fp = sum(1 for r in rows if not r["label"] and r["top"] >= t)
    tn = sum(1 for r in rows if not r["label"] and r["top"] < t)
    n = max(len(rows), 1)
    return {"acc": (tp + tn) / n, "prec": tp / max(tp + fp, 1), "rec": tp / max(tp + fn, 1), "fp": fp, "fn": fn}


def cat_f1(rows, t_block, cat_min):
    tp = fp = fn = 0
    for r in rows:
        blocked = r["top"] >= t_block
        pred = {c for c in CATS if r["cs"][c] >= cat_min.get(c, 0.5)} if blocked else set()
        if blocked and not pred and r["cs"]:
            pred = {max(r["cs"], key=r["cs"].get)}
        tp += len(pred & r["gold"])
        fp += len(pred - r["gold"])
        fn += len(r["gold"] - pred)
    return 2 * tp / max(2 * tp + fp + fn, 1)


def main():
    rows = collect()
    sets = sorted({r["set"] for r in rows if r["set"] != "fixtures"})
    ev = [r for r in rows if r["set"] != "fixtures"]
    print(f"{len(ev)} labelled snippets from {len(sets)} sets (+ {sum(1 for r in rows if r['set'] == 'fixtures')} own fixtures)")
    pos = [r["top"] for r in ev if r["label"]]
    neg = [r["top"] for r in ev if not r["label"]]
    print(f"\n1. separation: AUC of the top category score = {auc(pos, neg):.4f}   (malicious n={len(pos)}, benign n={len(neg)})")
    print(f"   malicious top score: min {min(pos):.2f}  p10 {np.percentile(pos, 10):.2f}  median {np.median(pos):.2f}")
    print(f"   benign    top score: p90 {np.percentile(neg, 90):.2f}  max {max(neg):.2f}")
    print("   BLOCK_T  accuracy  precision  recall   FP  FN")
    for t in (0.30, 0.40, 0.45, 0.50, 0.55, 0.60, 0.70, 0.80):
        m = verdict_metrics(ev, t)
        print(f"   {t:5.2f}    {m['acc']:.3f}     {m['prec']:.3f}     {m['rec']:.3f}   {m['fp']:3d} {m['fn']:3d}" + ("   <- current" if abs(t - fusion.BLOCK_T) < 1e-9 else ""))

    print("\n2. leave-one-set-out: choose BLOCK_T on the other sets, score on the held-out set (verdict accuracy / category F1)")
    grid = [0.35, 0.40, 0.45, 0.50, 0.55, 0.60, 0.65, 0.70]
    for held in sets:
        train = [r for r in ev if r["set"] != held]
        test = [r for r in ev if r["set"] == held]
        if not test:
            continue
        best = max(grid, key=lambda t: (verdict_metrics(train, t)["acc"], -abs(t - 0.5)))
        cur = verdict_metrics(test, fusion.BLOCK_T)["acc"]
        new = verdict_metrics(test, best)["acc"]
        print(f"   {held:10s} n={len(test):3d}  chosen T={best:.2f}  held-out accuracy {new:.3f}  (current 0.50: {cur:.3f})")

    print("\n3. per-category CAT_MIN sweep on all sets (category-level F1, BLOCK_T fixed at the current value)")
    base = cat_f1(ev, fusion.BLOCK_T, {})
    print(f"   all categories at 0.50: F1 {base:.4f}")
    for c in CATS:
        out = []
        for t in (0.40, 0.45, 0.50, 0.55, 0.60, 0.70):
            out.append((t, cat_f1(ev, fusion.BLOCK_T, {c: t})))
        best = max(out, key=lambda x: (x[1], -abs(x[0] - 0.5)))
        print(f"   {c:26s} best {best[0]:.2f} -> F1 {best[1]:.4f}   ({', '.join(f'{t:.2f}:{f:.3f}' for t, f in out)})")

    print("\n4. fragile signals: correct decisions whose top score is within 0.12 of BLOCK_T")
    frag = collections.Counter()
    near = 0
    for r in ev:
        if abs(r["top"] - fusion.BLOCK_T) <= 0.12 and (r["top"] >= fusion.BLOCK_T) == bool(r["label"]):
            near += 1
            c = max(r["cs"], key=r["cs"].get)
            for rule, w in r["rules"][c][:1]:
                frag[(rule, w)] += 1
    print(f"   {near} of {len(ev)} correct decisions are within 0.12 of the threshold")
    for (rule, w), n in frag.most_common(12):
        print(f"   {n:3d}  {rule}  weight {w}")
    wrong = [r for r in ev if (r["top"] >= fusion.BLOCK_T) != bool(r["label"])]
    print(f"\n   wrong decisions at the current threshold: {len(wrong)}")
    for r in wrong[:10]:
        print("   ", r["set"], r["id"], "label", r["label"], "top %.2f" % r["top"])


if __name__ == "__main__":
    main()
