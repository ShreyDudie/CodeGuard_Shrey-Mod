"""Evaluate the exported ONNX classifier on data it never trained on, and compare with the engine and the union.

    python eval/onnx_eval.py

Test sets: held-out expanded-dataset families, the organiser's dev rows, the 32-case semantic benchmark, real benign functions.
Also measures inference latency (model alone and union).
"""
import json
import os
import sys
import time

import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
sys.path.insert(0, os.path.join(ROOT, "eval"))
sys.stdout.reconfigure(encoding="utf-8")

import expanded_split as es  # noqa: E402
from codeguard import pipeline  # noqa: E402
from codeguard.union import scan_union, _get_clf  # noqa: E402

CATS = es.CATS


def jsonl(path):
    return [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]


def to_y(cat_list):
    y = np.zeros(len(CATS), dtype=bool)
    for c in cat_list:
        if c in CATS:
            y[CATS.index(c)] = True
    return y


def sets():
    import train_and_export as te
    _tr, _va, (te_c, te_y) = te.build_data()
    out = {"expanded held-out families": (te_c, te_y.astype(bool))}
    dev = jsonl(os.path.join(ROOT, "codeguard_dev.jsonl"))
    dev = [d for d in dev if d["language"] == "python"]
    out["dev (python rows)"] = ([d["code"] for d in dev],
                                np.array([to_y([x.strip() for x in d["category"].split(",")] if d["label"] else []) for d in dev]))
    sem = jsonl(os.path.join(ROOT, "tests", "data", "sem32.jsonl"))
    sem = [d for d in sem if d["language"] == "python"]
    out["sem32 (python rows)"] = ([d["code"] for d in sem], np.array([to_y([d["category"]] if d["label"] else []) for d in sem]))
    from stdlib_fp import corpus
    held = {os.path.abspath(f) for f in corpus()}
    fn = es.stdlib_functions(held, limit=300, seed=4242)
    out["real benign functions"] = (fn, np.zeros((len(fn), len(CATS)), dtype=bool))
    return out


def main():
    clf = _get_clf()
    if clf is None:
        print("ONNX model not found - run train_and_export.py first")
        return 1
    pipeline.warmup()
    for name, (codes, Y) in sets().items():
        eng = es.engine_pred(codes)
        mod = np.array([[p >= clf.threshold for p in clf.predict(c, with_lines=False)["probabilities"].values()] for c in codes])
        uni = np.array([[c in scan_union(code)["categories"] for c in CATS] for code in codes])
        print(f"\n== {name} (n={len(codes)})")
        for label, pred in (("engine", eng), ("onnx model", mod), ("union", uni)):
            print(f"  {label:11} {es.prf(Y, pred)}")
    # latency
    sample = [c for c, _ in zip(*sets()["dev (python rows)"][:1], range(1))] if False else sets()["dev (python rows)"][0]
    t = []
    for c in sample * 3:
        a = time.perf_counter()
        clf.predict(c, with_lines=False)
        t.append((time.perf_counter() - a) * 1000)
    t.sort()
    u = []
    for c in sample * 2:
        a = time.perf_counter()
        scan_union(c)
        u.append((time.perf_counter() - a) * 1000)
    u.sort()
    print(f"\nlatency ms  model alone: p50 {t[len(t) // 2]:.1f} p95 {t[int(len(t) * .95)]:.1f}   union: p50 {u[len(u) // 2]:.1f} p95 {u[int(len(u) * .95)]:.1f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
