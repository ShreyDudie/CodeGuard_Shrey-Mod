"""Choose, per category, the probability above which the ONNX model may ADD a category on its own.

Calibrated on real benign functions the model never trained on (standard-library code, a seed different from training), so that the model alone
does not block ordinary code: threshold = max(0.9, highest benign probability + 0.02).  Written into models/codeguard_model.json.
"""
import json
import os
import sys

import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
sys.path.insert(0, os.path.join(ROOT, "eval"))
sys.stdout.reconfigure(encoding="utf-8")

import expanded_split as es  # noqa: E402
from onnx_engine import ONNXCodeGuardClassifier, CATS  # noqa: E402
from stdlib_fp import corpus  # noqa: E402

clf = ONNXCodeGuardClassifier()
held = {os.path.abspath(f) for f in corpus()}
fns = es.stdlib_functions(held, limit=600, seed=777)
P = np.array([[clf.predict(c, with_lines=False)["probabilities"][k] for k in CATS] for c in fns])
th = {k: round(float(max(0.9, P[:, j].max() + 0.02)), 3) for j, k in enumerate(CATS)}
path = os.path.join(ROOT, "models", "codeguard_model.json")
meta = json.load(open(path, encoding="utf-8"))
meta["add_thresholds"] = th
meta["calibration"] = {"benign_functions": len(fns), "max_benign_probability": {k: round(float(P[:, j].max()), 3) for j, k in enumerate(CATS)}}
json.dump(meta, open(path, "w", encoding="utf-8"), indent=1)
print(len(fns), "benign functions; thresholds:", th)
