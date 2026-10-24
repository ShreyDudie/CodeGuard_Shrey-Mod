"""Shared featuriser for the instruction-text classifier: hashed word 1-2-grams + character 3-5-grams, sub-linear tf, L2 norm.

Training (scikit-learn, offline) and inference (numpy only) both call this module, so the features are identical.
"""
from __future__ import annotations

import re
import zlib

import numpy as np

N_FEATURES = 1 << 17
_WORD = re.compile(r"[a-z0-9_']+")
_LEET = str.maketrans("013457@$", "oleastas")


def normalize(text: str) -> str:
    t = text.lower()
    t = re.sub(r"[​-‏⁠﻿]", "", t)                 # zero-width characters
    t = t.translate(_LEET) if re.search(r"[a-z][0-9@$][a-z]", t) else t
    return re.sub(r"\s+", " ", t).strip()


def _h(s: str) -> int:
    return zlib.crc32(s.encode("utf-8")) & (N_FEATURES - 1)


def featurize(text: str) -> dict:
    """-> {feature_index: weight} (sub-linear tf, L2-normalised)."""
    t = normalize(text)[:2000]
    counts: dict = {}
    words = _WORD.findall(t)
    for i, w in enumerate(words):
        counts[_h("w:" + w)] = counts.get(_h("w:" + w), 0) + 1
        if i + 1 < len(words):
            k = _h("b:" + w + " " + words[i + 1])
            counts[k] = counts.get(k, 0) + 1
    padded = " " + t + " "
    for n in (3, 4, 5):
        for i in range(len(padded) - n + 1):
            g = padded[i:i + n]
            if g.strip() == "":
                continue
            k = _h("c:" + g)
            counts[k] = counts.get(k, 0) + 1
    out = {k: 1.0 + np.log(v) for k, v in counts.items()}
    norm = float(np.sqrt(sum(v * v for v in out.values()))) or 1.0
    return {k: v / norm for k, v in out.items()}
