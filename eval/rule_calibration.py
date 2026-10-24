"""Per-rule precision against rule weight.  A weight is a claim ("when this fires, this much evidence of harm"); this measures how well each claim holds.

Evidence: every labelled snippet (organiser dev rows, blind files, user files; own fixtures excluded) and ~650 real benign files (standard library + installed packages, read only).
For each rule: fires on malicious snippets of its category (TP), on labelled benign snippets (FP), on real benign files (FP-real).
    python eval/rule_calibration.py
"""
import collections
import glob
import os
import random
import sys
import sysconfig

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "eval"))
sys.stdout.reconfigure(encoding="utf-8")

import benchmark                 # noqa: E402
from codeguard import engine, fusion, pipeline  # noqa: E402


def real_files(n_std=350, n_site=300):
    std = sysconfig.get_paths()["stdlib"]
    a = [f for f in glob.glob(std + "/*.py") + glob.glob(std + "/*/*.py") if "test" not in f.lower() and os.path.getsize(f) < 100000]
    root = sysconfig.get_paths()["purelib"]
    b = [f for f in glob.glob(root + "/*/*.py") + glob.glob(root + "/*/*/*.py") if "test" not in f.lower() and os.path.getsize(f) < 100000]
    random.Random(5).shuffle(a)
    random.Random(6).shuffle(b)
    return a[:n_std] + b[:n_site]


def main():
    suites = benchmark.load_suites()
    pipeline.warmup()
    weights = {r.id: r.weight for r in engine.get_rules()}
    tp = collections.Counter()
    fp = collections.Counter()
    fpr = collections.Counter()
    alone_tp = collections.Counter()
    for name, items in suites.items():
        if name == "fixtures":
            continue
        for it in items:
            a = pipeline.analyze(it["code"])
            gold = set(it["cats"])
            seen = set()
            for f in a.findings:
                if f.rule in seen or f.weight < 0.3:
                    continue
                seen.add(f.rule)
                if it["label"] and f.category in gold:
                    tp[f.rule] += 1
                elif not it["label"]:
                    fp[f.rule] += 1
    files = real_files()
    for path in files:
        a = pipeline.analyze(open(path, encoding="utf-8", errors="replace").read())
        for rule in {f.rule for f in a.findings if f.weight >= 0.3}:
            fpr[rule] += 1
    print(f"{len(files)} real benign files; {sum(tp.values())} rule hits on labelled malicious snippets\n")
    print(f"{'rule':44s} {'weight':>6s} {'TP':>4s} {'FP':>3s} {'FPreal':>6s}  precision   note")
    rows = []
    for rule in sorted(set(tp) | set(fp) | set(fpr)):
        w = weights.get(rule)
        w = float(w) if isinstance(w, (int, float)) else float("nan")
        prec = (tp[rule] + 1) / (tp[rule] + fp[rule] + fpr[rule] * 1.0 + 2)          # Laplace-smoothed; real benign files count as benign evidence
        note = ""
        if w == w and w >= 0.5 and prec < 0.6 and (fp[rule] + fpr[rule]) >= 3:
            note = "weight above measured precision"
        elif w == w and 0.35 <= w < 0.62 and tp[rule] >= 4 and fp[rule] + fpr[rule] == 0:
            note = "hedged but precise"
        rows.append((rule, w, tp[rule], fp[rule], fpr[rule], prec, note))
    for r in sorted(rows, key=lambda x: (-(x[3] + x[4]), -x[2])):
        if r[3] + r[4] > 0 or r[6]:
            print(f"{r[0]:44s} {r[1]:6.2f} {r[2]:4d} {r[3]:3d} {r[4]:6d}  {r[5]:.2f}       {r[6]}")
    print("\nrules that only ever fire on malicious data and are hedged (candidates to make decisive):")
    for r in sorted(rows, key=lambda x: -x[2]):
        if r[6] == "hedged but precise":
            print(f"  {r[0]:44s} weight {r[1]:.2f}  TP {r[2]}")


if __name__ == "__main__":
    main()
