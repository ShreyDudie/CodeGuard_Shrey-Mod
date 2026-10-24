"""Train the naturalness language model on benign Python source (the local standard library, PSF licence).

The 400 files used by tests/stdlib_fp.py are held out so the false-positive measurement stays honest.
    python -m codeguard.ml.train
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import sys
import sysconfig

import numpy as np

from .lm import NGramLM

HERE = os.path.dirname(os.path.abspath(__file__))
MODELS = os.path.join(os.path.dirname(os.path.dirname(HERE)), "models")


def stdlib_files() -> list:
    std = sysconfig.get_paths()["stdlib"]
    files = glob.glob(std + "/**/*.py", recursive=True)
    return sorted(f for f in files if "site-packages" not in f and "test" not in f.lower() and "idlelib" not in f and os.path.getsize(f) < 400000)


def heldout() -> set:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(HERE)), "tests"))
    from stdlib_fp import corpus
    return {os.path.abspath(f) for f in corpus()}


def main() -> None:
    os.makedirs(MODELS, exist_ok=True)
    held = heldout()
    files = [f for f in stdlib_files() if os.path.abspath(f) not in held]
    lm = NGramLM()
    h = hashlib.sha256()
    nbytes = 0
    for f in files:
        data = open(f, "rb").read()
        h.update(data[:4096])
        lm.update(data)
        nbytes += len(data)
    path = os.path.join(MODELS, "lm_py.npz")
    lm.save(path)
    manifest = {"lm_py.npz": {"kind": "byte 5-gram LM, stupid back-off", "train_files": len(files), "train_bytes": nbytes, "heldout_files": len(held),
                              "data_fingerprint": h.hexdigest()[:16], "size_kb": round(os.path.getsize(path) / 1024, 1), "source": "Python standard library (PSF)"}}
    with open(os.path.join(MODELS, "MANIFEST.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
