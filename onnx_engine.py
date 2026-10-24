"""ONNX inference for the fine-tuned MiniLM multi-label code classifier (CPU only).

    clf = ONNXCodeGuardClassifier()
    clf.predict(code)  ->  {"categories": [...], "probabilities": {...}, "risk_score": float, "vulnerable_lines": [...]}

Line attribution scores each short code line on its own in ONE batched session run (dynamic batch axis),
so it costs one extra forward pass, not one per line.
"""
import json
import os
import re

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
MODELS = os.path.join(HERE, "models")
CATS = [
    "secret_access", "data_exfiltration", "destructive_command", "persistence_or_privesc",
    "obfuscated_execution", "dependency_risk", "resource_exhaustion", "ssrf_network_exfil",
    "ai_targeted_instructions",
]


def _load_meta():
    path = os.path.join(MODELS, "codeguard_model.json")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return {}


class ONNXCodeGuardClassifier:
    def __init__(self, model_path=None, threshold=None, max_len=None):
        import onnxruntime as ort
        from tokenizers import Tokenizer

        meta = _load_meta()
        int8 = os.path.join(MODELS, "codeguard_model.int8.onnx")
        full = os.path.join(MODELS, "codeguard_model.onnx")
        if model_path is None:
            model_path = full if os.path.exists(full) else int8      # int8 is faster (7 ms) but measurably less accurate
        self.model_path = model_path
        self.threshold = threshold if threshold is not None else meta.get("threshold", 0.5)
        self.max_len = max_len or meta.get("max_len", 192)
        tok_file = os.path.join(MODELS, "codeguard_tok", "tokenizer.json")
        self.tok = Tokenizer.from_file(tok_file)
        self.tok.enable_truncation(max_length=self.max_len)
        self.tok.enable_padding()
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = 4
        opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        self.sess = ort.InferenceSession(model_path, sess_options=opts, providers=["CPUExecutionProvider"])

    def _run(self, texts):
        texts = [re.sub(r"\d+", "0", t) for t in texts]
        enc = self.tok.encode_batch(texts)
        ids = np.array([e.ids for e in enc], dtype=np.int64)
        mask = np.array([e.attention_mask for e in enc], dtype=np.int64)
        logits = self.sess.run(None, {"input_ids": ids, "attention_mask": mask})[0]
        return 1.0 / (1.0 + np.exp(-logits))

    def predict(self, code, with_lines=True):
        probs = self._run([code])[0]
        found = [CATS[j] for j in range(len(CATS)) if probs[j] >= self.threshold]
        out = {
            "categories": found,
            "probabilities": {CATS[j]: round(float(probs[j]), 4) for j in range(len(CATS))},
            "risk_score": round(float(probs.max()), 4),
            "vulnerable_lines": [],
        }
        if found and with_lines:
            out["vulnerable_lines"] = self._lines(code, found)
        return out

    def _lines(self, code, found, limit=48):
        rows = code.split("\n")
        idx = [i for i, r in enumerate(rows) if len(r.strip()) >= 6][:limit]
        if not idx:
            return []
        scores = self._run([rows[i] for i in idx])
        cols = [CATS.index(c) for c in found]
        hits = []
        for k, i in enumerate(idx):
            if max(scores[k][c] for c in cols) >= self.threshold:
                hits.append(i + 1)
        return hits
