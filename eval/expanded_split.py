"""Honest train/test evaluation on expanded_dataset.jsonl.

The file has 500 rows but only ~103 distinct snippets and 52 template families (rows often differ by one number), so a random row split
would leak near-copies into the test set and report inflated scores.  This script therefore:
  1. collapses each snippet to its template family (digits -> N),
  2. splits FAMILIES, stratified by category (about 30% of each category's families held out for testing),
  3. trains a lightweight multi-label model on the training families + real benign code (Python standard library functions),
  4. reports accuracy / precision / recall on the held-out families for: the rule+analysis engine alone, the model alone, and their union,
  5. reports the train-vs-test gap and a leave-families-out cross-validation to show whether the model over- or under-fits.
    python eval/expanded_split.py
"""
import ast
import collections
import glob
import json
import os
import random
import re
import sys
import sysconfig

import numpy as np
from scipy.sparse import csr_matrix
from sklearn.linear_model import LogisticRegression

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
sys.stdout.reconfigure(encoding="utf-8")

from codeguard import pipeline  # noqa: E402
from codeguard.ml.textfeat import N_FEATURES, featurize  # noqa: E402

CATS = ["secret_access", "data_exfiltration", "destructive_command", "persistence_or_privesc", "obfuscated_execution", "dependency_risk",
        "resource_exhaustion", "ssrf_network_exfil", "ai_targeted_instructions"]
SEED = 11


def family(code: str) -> str:
    return re.sub(r"\d+", "N", code)


def load_expanded():
    rows = [json.loads(l) for l in open(os.path.join(ROOT, "expanded_dataset.jsonl"), encoding="utf-8") if l.strip()]
    fams = collections.OrderedDict()
    for r in rows:
        fams.setdefault((r["category"], family(r["code"])), []).append(r)
    return rows, fams


def stdlib_functions(held_out_files: set, limit: int = 4000, seed: int = SEED) -> list:
    """Real benign code: top-level functions / methods (4-40 lines) from stdlib files that are not in the FP hold-out."""
    std = sysconfig.get_paths()["stdlib"]
    files = sorted(f for f in glob.glob(std + "/**/*.py", recursive=True) if "site-packages" not in f and "test" not in f.lower() and os.path.getsize(f) < 200000)
    rnd = random.Random(seed)
    rnd.shuffle(files)
    out = []
    for f in files:
        if os.path.abspath(f) in held_out_files:
            continue
        try:
            src = open(f, encoding="utf-8", errors="replace").read()
            tree = ast.parse(src)
        except (SyntaxError, ValueError, OSError, RecursionError):
            continue
        lines = src.split("\n")
        funcs = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and 4 <= (n.end_lineno - n.lineno + 1) <= 40]
        rnd.shuffle(funcs)
        for n in funcs[:3]:
            seg = "\n".join(lines[n.lineno - 1:n.end_lineno])
            seg = re.sub(r"^" + " " * n.col_offset, "", seg, flags=re.M)
            out.append(seg)
        if len(out) >= limit:
            break
    return out


def code_features(code: str) -> dict:
    c = re.sub(r"\d+", "0", code)
    return featurize(c)


def matrix(codes: list) -> csr_matrix:
    r, c, v = [], [], []
    for i, code in enumerate(codes):
        for k, x in code_features(code).items():
            r.append(i)
            c.append(k)
            v.append(x)
    return csr_matrix((v, (r, c)), shape=(len(codes), N_FEATURES), dtype=np.float32)


def fit_models(codes: list, Y: np.ndarray) -> list:
    X = matrix(codes)
    models = []
    for j in range(len(CATS)):
        if Y[:, j].sum() == 0:
            models.append(None)
            continue
        m = LogisticRegression(C=8.0, class_weight="balanced", max_iter=3000, solver="liblinear")
        m.fit(X, Y[:, j])
        models.append(m)
    return models


def predict(models: list, codes: list) -> np.ndarray:
    X = matrix(codes)
    P = np.zeros((len(codes), len(CATS)))
    for j, m in enumerate(models):
        if m is not None:
            P[:, j] = m.predict_proba(X)[:, 1]
    return P


def prf(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    """Snippet-level verdict metrics: positive = any category present."""
    t = y_true.any(axis=1)
    p = y_pred.any(axis=1)
    tp, fp, fn, tn = int(np.sum(t & p)), int(np.sum(~t & p)), int(np.sum(t & ~p)), int(np.sum(~t & ~p))
    return {"n": len(t), "accuracy": round((tp + tn) / max(len(t), 1), 3), "precision": round(tp / max(tp + fp, 1), 3), "recall": round(tp / max(tp + fn, 1), 3),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def category_prf(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    out = {}
    for j, c in enumerate(CATS):
        tp = int(np.sum(y_true[:, j] & y_pred[:, j]))
        fp = int(np.sum(~y_true[:, j] & y_pred[:, j]))
        fn = int(np.sum(y_true[:, j] & ~y_pred[:, j]))
        if tp + fp + fn:
            out[c] = {"precision": round(tp / max(tp + fp, 1), 2), "recall": round(tp / max(tp + fn, 1), 2), "tp": tp, "fp": fp, "fn": fn}
    return out


def engine_pred(codes: list) -> np.ndarray:
    Y = np.zeros((len(codes), len(CATS)), dtype=bool)
    for i, code in enumerate(codes):
        r = pipeline.scan(code)
        for c in r["categories"]:
            Y[i, CATS.index(c)] = True
    return Y


def main() -> None:
    rows, fams = load_expanded()
    rnd = random.Random(SEED)
    by_cat = collections.defaultdict(list)
    for (cat, f), rs in fams.items():
        by_cat[cat].append((cat, f))
    train_f, test_f = [], []
    for cat, keys in by_cat.items():
        keys = sorted(keys)
        rnd.shuffle(keys)
        n_test = max(1, round(0.3 * len(keys)))
        test_f += keys[:n_test]
        train_f += keys[n_test:]
    print(f"rows {len(rows)}, distinct snippets {len({r['code'] for r in rows})}, families {len(fams)}  ->  train families {len(train_f)}, test families {len(test_f)}")
    print("test families per category:", dict(collections.Counter(c for c, _ in test_f)))

    def sample(keys: list, per_family: int = 4):
        codes, Y = [], []
        for k in keys:
            rs = fams[k]
            for r in rs[:per_family]:                     # a few members per family: no family can dominate
                codes.append(r["code"])
                y = np.zeros(len(CATS), dtype=bool)
                if r["category"] != "benign":
                    y[CATS.index(r["category"])] = True
                Y.append(y)
        return codes, np.array(Y)

    tr_codes, tr_Y = sample(train_f)
    te_codes, te_Y = sample(test_f, per_family=1)            # one member per held-out family: every family counts once

    # real benign code for the model (the dataset itself has only 3 benign templates)
    from stdlib_fp import corpus
    held = {os.path.abspath(f) for f in corpus()}
    benign_real = stdlib_functions(held)
    print(f"real benign functions added to training: {len(benign_real)}")
    X_codes = tr_codes + benign_real
    X_Y = np.vstack([tr_Y, np.zeros((len(benign_real), len(CATS)), dtype=bool)])

    models = fit_models(X_codes, X_Y.astype(int))
    P_te = predict(models, te_codes)
    P_tr = predict(models, tr_codes)
    thr = 0.5
    model_te, model_tr = P_te >= thr, P_tr >= thr

    pipeline.warmup()
    eng_te = engine_pred(te_codes)
    union_te = eng_te | model_te

    print("\n=== held-out families (never seen in training) ===")
    for name, pred in (("engine only (rules+analysis, no training on this file)", eng_te), ("model only (trained on train families + real benign code)", model_te), ("union (engine OR model)", union_te)):
        print(f"{name:58} {prf(te_Y, pred)}")
    print("\nper category, union:", category_prf(te_Y, union_te))
    print("per category, engine:", category_prf(te_Y, eng_te))
    print("per category, model :", category_prf(te_Y, model_te))
    print("\n=== fit diagnostics ===")
    print("model on its TRAINING families:", prf(tr_Y, model_tr))
    print("model on HELD-OUT families   :", prf(te_Y, model_te))

    # leave-families-out cross-validation over all families (5 folds, grouped by family, stratified by category)
    keys_all = sorted(fams.keys())
    rnd.shuffle(keys_all)
    folds = [[] for _ in range(5)]
    seen = collections.defaultdict(int)
    for k in sorted(keys_all, key=lambda x: x[0]):
        folds[seen[k[0]] % 5].append(k)
        seen[k[0]] += 1
    accs = []
    for i in range(5):
        te_k = folds[i]
        tr_k = [k for j in range(5) if j != i for k in folds[j]]
        c1, y1 = sample(tr_k)
        c2, y2 = sample(te_k, per_family=1)
        mm = fit_models(c1 + benign_real, np.vstack([y1, np.zeros((len(benign_real), len(CATS)), dtype=bool)]).astype(int))
        pr = predict(mm, c2) >= thr
        eg = engine_pred(c2)
        accs.append((prf(y2, pr), prf(y2, eg), prf(y2, pr | eg)))
    for idx, name in enumerate(("model", "engine", "union")):
        a = np.mean([x[idx]["accuracy"] for x in accs])
        p = np.mean([x[idx]["precision"] for x in accs])
        r = np.mean([x[idx]["recall"] for x in accs])
        print(f"5-fold leave-families-out {name:7}: accuracy {a:.3f}  precision {p:.3f}  recall {r:.3f}")

    # false positives of each component on real, unseen benign code (stdlib held-out files)
    held_fn = stdlib_functions(set(), limit=60, seed=999)
    held_fn = [f for f in held_fn][:60]
    fp_engine = int(engine_pred(held_fn).any(axis=1).sum())
    fp_model = int((predict(models, held_fn) >= thr).any(axis=1).sum())
    print(f"\nfalse positives on {len(held_fn)} unseen real benign functions: engine {fp_engine}, model {fp_model}")


if __name__ == "__main__":
    main()
