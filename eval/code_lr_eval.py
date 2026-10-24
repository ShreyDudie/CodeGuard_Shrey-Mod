"""Does a trained code classifier add anything to the rule engine?  Train on expanded_dataset.jsonl (+ lots of real benign code), test ONLY on
independent labelled sets (the organiser's dev rows and every blind file), and report engine / model / union at several thresholds.

    python eval/code_lr_eval.py            # prints the comparison
    python eval/code_lr_eval.py --export   # also writes models/code_lr.npz (only do this if the union helps)
"""
import ast
import glob
import json
import os
import random
import re
import sys
import sysconfig

import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "eval"))
sys.path.insert(0, os.path.join(ROOT, "tests"))
sys.stdout.reconfigure(encoding="utf-8")

import expanded_split as E          # noqa: E402
import benchmark                    # noqa: E402
from codeguard import pipeline      # noqa: E402

CATS = E.CATS


def site_functions(limit: int = 6000, seed: int = 21) -> list:
    """Benign functions from installed third-party packages (read only)."""
    root = sysconfig.get_paths()["purelib"]
    files = sorted(f for f in glob.glob(root + "/*/*.py") + glob.glob(root + "/*/*/*.py") if "test" not in f.lower() and os.path.getsize(f) < 150000)
    rnd = random.Random(seed)
    rnd.shuffle(files)
    out = []
    for f in files:
        try:
            src = open(f, encoding="utf-8", errors="replace").read()
            tree = ast.parse(src)
        except (SyntaxError, ValueError, OSError, RecursionError):
            continue
        lines = src.split("\n")
        funcs = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and 4 <= (n.end_lineno - n.lineno + 1) <= 40]
        rnd.shuffle(funcs)
        for n in funcs[:2]:
            seg = "\n".join(lines[n.lineno - 1:n.end_lineno])
            out.append(re.sub(r"^" + " " * n.col_offset, "", seg, flags=re.M))
        if len(out) >= limit:
            break
    return out


def main() -> None:
    rows, fams = E.load_expanded()
    codes, Y = [], []
    for (cat, f), rs in fams.items():
        for r in rs[:4]:
            codes.append(r["code"])
            y = np.zeros(len(CATS), dtype=int)
            if r["category"] != "benign":
                y[CATS.index(r["category"])] = 1
            Y.append(y)
    n_attack = len(codes)
    from stdlib_fp import corpus
    held = {os.path.abspath(f) for f in corpus()}
    benign = E.stdlib_functions(held, limit=4000) + site_functions()
    print(f"training rows: {n_attack} from expanded_dataset.jsonl (all families), {len(benign)} real benign functions")
    Xc = codes + benign
    XY = np.vstack([np.array(Y), np.zeros((len(benign), len(CATS)), dtype=int)])
    models = E.fit_models(Xc, XY)

    suites = benchmark.load_suites()
    items = []
    for name, rs in suites.items():
        if name == "fixtures":
            continue                                    # my own cases were written while building the engine
        for r in rs:
            items.append((name, r))
    test_codes = [r["code"] for _, r in items]
    pipeline.warmup()
    P = E.predict(models, test_codes)
    eng = np.zeros((len(items), len(CATS)), dtype=bool)
    gold = np.zeros((len(items), len(CATS)), dtype=bool)
    for i, (_, r) in enumerate(items):
        res = pipeline.scan(r["code"])
        for c in res["categories"]:
            eng[i, CATS.index(c)] = True
        for c in r["cats"]:
            if c in CATS:
                gold[i, CATS.index(c)] = True
    print(f"independent labelled snippets: {len(items)} ({int(gold.any(axis=1).sum())} malicious, {int((~gold.any(axis=1)).sum())} benign)")
    print("engine alone:", E.prf(gold, eng))
    for thr in (0.5, 0.7, 0.85, 0.95):
        m = P >= thr
        print(f"threshold {thr}: model alone {E.prf(gold, m)}")
        print(f"             union        {E.prf(gold, eng | m)}")

    # the cases the engine got wrong when they were fresh (predictions saved before the expected outputs were seen)
    fresh_missed = []
    for pred_file, exp_file, code_file, prefix in (("reports/blind5_predictions.jsonl", "tests/data/blind5_expected.json", "tests/data/blind5_code_only.json", ""),
                                                   ("reports/blind6_predictions.jsonl", "tests/data/blind6_expected.json", "tests/data/blind6_code_only.json", "")):
        pred = {json.loads(l)["id"]: json.loads(l)["output"] for l in open(os.path.join(ROOT, pred_file), encoding="utf-8")}
        exp = {d["id"]: d["output"] for d in json.load(open(os.path.join(ROOT, exp_file), encoding="utf-8"))}
        code = {d["id"]: d["code"] for d in json.load(open(os.path.join(ROOT, code_file), encoding="utf-8"))}
        for k, e in exp.items():
            if e["verdict"] == "block" and pred[k]["verdict"] == "allow":
                fresh_missed.append((k, code[k], e["categories"]))
    Pm = E.predict(models, [c for _, c, _ in fresh_missed])
    print(f"fresh engine misses (blocks that were allowed when first seen): {len(fresh_missed)}")
    for (k, _, cats), row in zip(fresh_missed, Pm):
        best = int(row.argmax())
        print(f"  {k}: expected {cats}; model's top category {CATS[best]} p={row[best]:.2f}  (caught at 0.7: {bool(row.max() >= 0.7)})")
    if "--export" in sys.argv:
        coefs = np.stack([(m.coef_.ravel() if m is not None else np.zeros(E.N_FEATURES)) for m in models]).astype(np.float32)
        icpt = np.array([(m.intercept_[0] if m is not None else -9.0) for m in models], dtype=np.float32)
        np.savez_compressed(os.path.join(ROOT, "models", "code_lr.npz"), coef=coefs, intercept=icpt)
        print("exported models/code_lr.npz")


if __name__ == "__main__":
    main()
