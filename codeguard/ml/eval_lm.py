"""Evaluate the naturalness LM as an obfuscation detector.

negatives: real string literals (>=24 chars) from HELD-OUT standard-library files.
positives: other held-out literals pushed through common encoders (base64, hex, zlib+base64, rot13, reversed, urlsafe).
Nothing malicious is authored: the positives are benign text, merely encoded.
    python -m codeguard.ml.eval_lm
"""
from __future__ import annotations

import ast
import base64
import codecs
import json
import os
import random
import math
import sys
import zlib
from collections import Counter

import numpy as np

from .lm import NGramLM
from .train import MODELS, heldout


def shannon(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def auc(pos, neg) -> float:
    pos, neg = np.asarray(pos), np.asarray(neg)
    allv = np.concatenate([pos, neg])
    ranks = allv.argsort().argsort() + 1.0
    return float((ranks[:len(pos)].sum() - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg)))


def literals(files, cap=6000):
    out = []
    for f in files:
        try:
            tree = ast.parse(open(f, encoding="utf-8", errors="replace").read())
        except Exception:
            continue
        for n in ast.walk(tree):
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and 24 <= len(n.value) <= 600 and "\n" not in n.value:
                out.append(n.value)
    random.Random(3).shuffle(out)
    return out[:cap]


def encoders(s: str):
    b = s.encode("utf-8", "replace")
    yield "base64", base64.b64encode(b).decode()
    yield "hex", b.hex()
    yield "zlib64", base64.b64encode(zlib.compress(b)).decode()
    yield "rot13", codecs.encode(s, "rot13")
    yield "reversed", s[::-1]
    yield "urlsafe", base64.urlsafe_b64encode(b).decode().rstrip("=")


def main() -> None:
    lm = NGramLM.load(os.path.join(MODELS, "lm_py.npz"))
    files = sorted(heldout())
    lits = literals(files)
    half = len(lits) // 2
    neg_src, pos_src = lits[:half], lits[half:]
    neg = neg_src
    pos_by = {}
    for s in pos_src:
        for name, enc in encoders(s):
            if len(enc) >= 24:
                pos_by.setdefault(name, []).append(enc)
    res = {"negatives": len(neg), "model_kb": round(os.path.getsize(os.path.join(MODELS, "lm_py.npz")) / 1024, 1), "encoders": {}}
    neg_lm = [lm.bits_per_char(s) for s in neg]
    neg_en = [shannon(s) for s in neg]
    pos_lm_all, pos_en_all = [], []
    for name, items in pos_by.items():
        p_lm = [lm.bits_per_char(s) for s in items]
        p_en = [shannon(s) for s in items]
        pos_lm_all += p_lm
        pos_en_all += p_en
        res["encoders"][name] = {"n": len(items), "auc_lm": round(auc(p_lm, neg_lm), 4), "auc_entropy": round(auc(p_en, neg_en), 4)}
    res["overall"] = {"auc_lm": round(auc(pos_lm_all, neg_lm), 4), "auc_entropy": round(auc(pos_en_all, neg_en), 4)}
    thr = float(np.percentile(neg_lm, 99))
    res["threshold_bpc_p99_of_benign"] = round(thr, 3)
    res["recall_at_p99_threshold"] = round(float(np.mean(np.array(pos_lm_all) > thr)), 4)
    from .infer import payload_shape, BPC_THRESHOLD
    blob_pos = [(name, e) for name, items in pos_by.items() for e in items if name in ("base64", "hex", "zlib64", "urlsafe") and payload_shape(e)]
    blob_hit = [lm.bits_per_char(e) >= BPC_THRESHOLD for _n, e in blob_pos]
    benign_blobshaped = [s for s in neg if payload_shape(s)]
    res["deployed_detector"] = {"threshold_bpc": BPC_THRESHOLD, "blob_recall": round(float(np.mean(blob_hit)), 4), "n_blobs": len(blob_pos),
                                "benign_literals": len(neg), "benign_blob_shaped": len(benign_blobshaped),
                                "benign_false_alarms": int(sum(lm.bits_per_char(s) >= BPC_THRESHOLD for s in benign_blobshaped))}
    res["benign_literal_median_bpc"] = round(float(np.median(neg_lm)), 3)
    print(json.dumps(res, indent=2))
    with open(os.path.join(os.path.dirname(MODELS), "reports", "lm_eval.json"), "w") as f:
        json.dump(res, f, indent=2)


if __name__ == "__main__":
    main()
