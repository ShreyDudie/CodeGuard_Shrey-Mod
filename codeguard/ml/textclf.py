"""Inference for the instruction-text classifier (numpy only, ~0.2 ms per text)."""
from __future__ import annotations

import os
import threading

import numpy as np

from .textfeat import featurize

_HERE = os.path.dirname(os.path.abspath(__file__))
_PATH = os.path.join(os.path.dirname(os.path.dirname(_HERE)), "models", "text_lr.npz")
_m = None
_lock = threading.Lock()
THRESHOLD = 0.9          # chosen so held-out real comments stay clean (see models/text_lr.json)


def _load():
    global _m
    if _m is None:
        with _lock:
            if _m is None:
                if not os.path.exists(_PATH):
                    _m = False
                else:
                    z = np.load(_PATH)
                    _m = (z["coef"], float(z["intercept"]))
    return _m


def probability(text: str) -> float:
    """P(text is an instruction aimed at an AI reader / manipulating a model). 0.0 if the model file is missing."""
    m = _load()
    if not m or not text or len(text) < 12:
        return 0.0
    coef, b = m
    f = featurize(text)
    z = b + sum(coef[k] * v for k, v in f.items())
    return float(1.0 / (1.0 + np.exp(-z)))
