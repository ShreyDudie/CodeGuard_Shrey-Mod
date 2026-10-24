"""Byte-level hashed n-gram language model with stupid back-off, trained from scratch with numpy.

It learns what *ordinary* source text looks like.  Text that is very surprising to it (encoded payloads, packed blobs,
scrambled identifiers) gets a high bits-per-character score - an unsupervised obfuscation signal that needs no attack data.
"""
from __future__ import annotations

import numpy as np

ORDER = 5
BUCKETS = 1 << 22
_MULT = np.uint64(0x9E3779B97F4A7C15)
BACKOFF = 0.4


def _grams(arr: np.ndarray, n: int) -> np.ndarray:
    """hash of every length-n window (uint64); entry i covers arr[i:i+n]"""
    m = len(arr) - n + 1
    if m <= 0:
        return np.zeros(0, dtype=np.uint64)
    h = np.full(m, np.uint64(n), dtype=np.uint64)
    for k in range(n):
        h = (h * _MULT) ^ arr[k:k + m].astype(np.uint64)
        h ^= h >> np.uint64(29)
    return (h % np.uint64(BUCKETS)).astype(np.int64)


class NGramLM:
    def __init__(self, counts: np.ndarray | None = None, total: int = 0):
        self.counts = counts if counts is not None else np.zeros(BUCKETS, dtype=np.uint32)
        self.total = total

    # -- training ------------------------------------------------------------------------------
    def update(self, data: bytes) -> None:
        arr = np.frombuffer(data, dtype=np.uint8)
        if len(arr) < ORDER:
            return
        for n in range(1, ORDER + 1):
            idx = _grams(arr, n)
            self.counts += np.bincount(idx, minlength=BUCKETS).astype(np.uint32)
        self.total += len(arr)

    # -- scoring ---------------------------------------------------------------------------------
    def nll(self, data: bytes) -> np.ndarray:
        """negative log2 probability of every byte (len(data) values)"""
        arr = np.frombuffer(data, dtype=np.uint8)
        L = len(arr)
        if L == 0:
            return np.zeros(0)
        padded = np.concatenate([np.full(ORDER - 1, 10, dtype=np.uint8), arr])     # newline padding
        g = {n: _grams(padded, n) for n in range(1, ORDER + 1)}                    # g[n][i] covers padded[i:i+n]; byte j is padded[j+ORDER-1]
        c = {n: self.counts[g[n]].astype(np.float64) for n in g}
        prob = (c[1][ORDER - 1:ORDER - 1 + L] + 1.0) / (self.total + 256.0)          # unigram fallback
        scale = np.ones(L)
        out = np.zeros(L)
        resolved = np.zeros(L, dtype=bool)
        for n in range(ORDER, 1, -1):
            # window for byte j of order n starts at j + ORDER - n
            start = ORDER - n
            num = c[n][start:start + L]
            den = c[n - 1][start:start + L]
            ok = (~resolved) & (num > 0) & (den > 0)
            out[ok] = scale[ok] * num[ok] / den[ok]
            resolved |= ok
            scale = np.where(resolved, scale, scale * BACKOFF)
        out[~resolved] = scale[~resolved] * prob[~resolved]
        return -np.log2(np.clip(out, 1e-9, 1.0))

    def bits_per_char(self, text: str) -> float:
        b = text.encode("utf-8", "replace")
        if len(b) == 0:
            return 0.0
        return float(self.nll(b).mean())

    # -- persistence -----------------------------------------------------------------------------
    def save(self, path: str) -> None:
        nz = np.nonzero(self.counts)[0]
        np.savez_compressed(path, idx=nz.astype(np.uint32), val=self.counts[nz], total=np.array([self.total], dtype=np.int64))

    @classmethod
    def load(cls, path: str) -> "NGramLM":
        d = np.load(path)
        counts = np.zeros(BUCKETS, dtype=np.uint32)
        counts[d["idx"].astype(np.int64)] = d["val"]
        return cls(counts, int(d["total"][0]))
