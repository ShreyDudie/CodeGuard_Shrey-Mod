"""Fine-tune all-MiniLM-L6-v2 (Apache-2.0) as a 9-way multi-label code classifier (BCEWithLogitsLoss, CPU) and export it to ONNX.

Training data is REAL: the expanded dataset's training families, our hand-written cases (positives and benign look-alikes) and real benign
functions from the Python standard library.  Held out and never trained on: the expanded dataset's test families, the organiser's dev rows
and the 32-case semantic benchmark.  Early stopping uses validation families carved out of the training families.

    python train_and_export.py [--epochs 6] [--max-len 192] [--out models]

Outputs: models/codeguard_model.onnx (+ int8 version), models/codeguard_tok/tokenizer.json, models/codeguard_model.json (metrics, thresholds).
"""
import argparse
import collections
import json
import os
import random
import re
import sys
import time

import numpy as np
import torch
import torch.nn as nn

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
sys.path.insert(0, os.path.join(ROOT, "eval"))
sys.stdout.reconfigure(encoding="utf-8")

from transformers import AutoModel, AutoTokenizer  # noqa: E402

import expanded_split as es  # noqa: E402

CATS = es.CATS
BASE = "sentence-transformers/all-MiniLM-L6-v2"


class CodeGuardNet(nn.Module):
    def __init__(self, base: str = BASE, n: int = 9):
        super().__init__()
        self.enc = AutoModel.from_pretrained(base)
        self.drop = nn.Dropout(0.1)
        self.head = nn.Linear(self.enc.config.hidden_size, n)

    def forward(self, input_ids, attention_mask):
        h = self.enc(input_ids=input_ids, attention_mask=attention_mask).last_hidden_state
        m = attention_mask.unsqueeze(-1).to(h.dtype)
        pooled = (h * m).sum(1) / m.sum(1).clamp(min=1.0)
        return self.head(self.drop(pooled))                      # logits; sigmoid is applied at inference


def build_data():
    rows, fams = es.load_expanded()
    rnd = random.Random(es.SEED)
    by_cat = collections.defaultdict(list)
    for key in fams:
        by_cat[key[0]].append(key)
    train_f, test_f = [], []
    for cat, keys in by_cat.items():
        keys = sorted(keys)
        rnd.shuffle(keys)
        n_test = max(1, round(0.3 * len(keys)))
        test_f += keys[:n_test]
        train_f += keys[n_test:]
    # validation families for early stopping
    rnd.shuffle(train_f)
    val_f = train_f[: max(4, len(train_f) // 6)]
    train_f = train_f[len(val_f):]

    def take(keys, per_family):
        codes, Y = [], []
        for k in keys:
            for r in fams[k][:per_family]:
                codes.append(r["code"])
                y = np.zeros(len(CATS), dtype=np.float32)
                if r["category"] != "benign":
                    y[CATS.index(r["category"])] = 1
                Y.append(y)
        return codes, np.array(Y, dtype=np.float32)

    tr_c, tr_y = take(train_f, 4)
    va_c, va_y = take(val_f, 1)
    te_c, te_y = take(test_f, 1)

    # hand-written cases: positives and benign twins (family = case id, so everything here is training data)
    import run_cases
    for c in run_cases.load():
        cats = c[1]
        y = np.zeros(len(CATS), dtype=np.float32)
        if cats not in ("benign", "", None):
            for x in str(cats).split(","):
                y[CATS.index(x.strip())] = 1
        if (c[3] if len(c) > 3 else "python") == "python":
            tr_c.append(c[2])
            tr_y = np.vstack([tr_y, y])
    from stdlib_fp import corpus
    held = {os.path.abspath(f) for f in corpus()}
    benign = es.stdlib_functions(held, limit=1500)
    tr_c += benign
    tr_y = np.vstack([tr_y, np.zeros((len(benign), len(CATS)), dtype=np.float32)])
    return (tr_c, tr_y), (va_c, va_y), (te_c, te_y)


def encode(tok, codes, max_len):
    e = tok(codes, padding=True, truncation=True, max_length=max_len, return_tensors="pt")
    return e["input_ids"], e["attention_mask"]


def evaluate(model, tok, codes, Y, max_len, bs=32, thr=0.5):
    model.eval()
    P = []
    with torch.no_grad():
        for i in range(0, len(codes), bs):
            ids, am = encode(tok, [re.sub(r"\d+", "0", c) for c in codes[i:i + bs]], max_len)
            P.append(torch.sigmoid(model(ids, am)).numpy())
    P = np.vstack(P)
    return P, es.prf(Y.astype(bool), P >= thr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--epochs", type=int, default=6)
    ap.add_argument("--max-len", type=int, default=192)
    ap.add_argument("--bs", type=int, default=16)
    ap.add_argument("--lr", type=float, default=4e-5)
    ap.add_argument("--out", default=os.path.join(ROOT, "models"))
    a = ap.parse_args()
    torch.manual_seed(es.SEED)
    torch.set_num_threads(os.cpu_count() or 4)
    (tr_c, tr_y), (va_c, va_y), (te_c, te_y) = build_data()
    print(f"train {len(tr_c)} (positives {int(tr_y.any(axis=1).sum())}), val {len(va_c)}, test families {len(te_c)}")
    tok = AutoTokenizer.from_pretrained(BASE)
    model = CodeGuardNet()
    pos_w = torch.tensor(np.clip((len(tr_y) - tr_y.sum(0)) / np.maximum(tr_y.sum(0), 1), 1, 30), dtype=torch.float32)
    loss_fn = nn.BCEWithLogitsLoss(pos_weight=pos_w)
    opt = torch.optim.AdamW(model.parameters(), lr=a.lr, weight_decay=0.01)
    steps = a.epochs * ((len(tr_c) + a.bs - 1) // a.bs)
    sched = torch.optim.lr_scheduler.LambdaLR(opt, lambda s: min(1.0, (s + 1) / 30) * max(0.05, 1 - s / steps))
    best, best_state, bad = -1.0, None, 0
    rnd = random.Random(1)
    idx = list(range(len(tr_c)))
    hist = []
    for ep in range(a.epochs):
        model.train()
        rnd.shuffle(idx)
        t0, tot = time.time(), 0.0
        for i in range(0, len(idx), a.bs):
            b = idx[i:i + a.bs]
            ids, am = encode(tok, [re.sub(r"\d+", "0", tr_c[j]) for j in b], a.max_len)
            loss = loss_fn(model(ids, am), torch.tensor(tr_y[b]))
            opt.zero_grad()
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            sched.step()
            tot += float(loss) * len(b)
            if (i // a.bs) % 10 == 0:
                print(f"  step {i // a.bs}/{(len(idx) + a.bs - 1) // a.bs} loss {float(loss):.3f} ({time.time() - t0:.0f}s)", flush=True)
        _, mv = evaluate(model, tok, va_c, va_y, a.max_len)
        _, mt = evaluate(model, tok, tr_c[:400], tr_y[:400], a.max_len)
        score = mv["accuracy"] + mv["recall"]
        hist.append({"epoch": ep + 1, "loss": round(tot / len(idx), 4), "val": mv, "train_sample": mt})
        print(f"epoch {ep + 1}: loss {tot / len(idx):.4f}  val acc {mv['accuracy']} recall {mv['recall']} precision {mv['precision']}  | train-sample acc {mt['accuracy']}  ({time.time() - t0:.0f}s)")
        if score > best:
            best, bad = score, 0
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
        else:
            bad += 1
            if bad >= 2:
                print("early stop")
                break
    model.load_state_dict(best_state)

    # held-out evaluation
    P_te, m_te = evaluate(model, tok, te_c, te_y, a.max_len)
    print("held-out families:", m_te)

    # ONNX export (dynamic batch and sequence axes), CPU-only
    os.makedirs(a.out, exist_ok=True)
    model.eval()
    path = os.path.join(a.out, "codeguard_model.onnx")
    dummy = tok(["import os\nprint(1)", "x"], padding=True, return_tensors="pt")
    with torch.no_grad():
        torch.onnx.export(model, (dummy["input_ids"], dummy["attention_mask"]), path, input_names=["input_ids", "attention_mask"], output_names=["logits"],
                          dynamic_axes={"input_ids": {0: "batch", 1: "seq"}, "attention_mask": {0: "batch", 1: "seq"}, "logits": {0: "batch"}}, opset_version=17, dynamo=False)
    tokdir = os.path.join(a.out, "codeguard_tok")
    tok.save_pretrained(tokdir)
    try:
        from onnxruntime.quantization import quantize_dynamic, QuantType
        quantize_dynamic(path, os.path.join(a.out, "codeguard_model.int8.onnx"), weight_type=QuantType.QInt8)
    except Exception as e:
        print("int8 quantisation skipped:", e)

    # parity check torch vs onnxruntime
    import onnxruntime as ort
    sess = ort.InferenceSession(path, providers=["CPUExecutionProvider"])
    enc = tok(te_c[:8], padding=True, truncation=True, max_length=a.max_len, return_tensors="np")
    lo = sess.run(None, {"input_ids": enc["input_ids"].astype(np.int64), "attention_mask": enc["attention_mask"].astype(np.int64)})[0]
    with torch.no_grad():
        lt = model(torch.tensor(enc["input_ids"]), torch.tensor(enc["attention_mask"])).numpy()
    print("onnx vs torch max abs logit difference:", float(np.abs(lo - lt).max()))

    meta = {"base_model": BASE, "base_licence": "Apache-2.0", "max_len": a.max_len, "categories": CATS, "threshold": 0.5, "history": hist,
            "heldout_expanded_families": m_te, "train_size": len(tr_c)}
    json.dump(meta, open(os.path.join(a.out, "codeguard_model.json"), "w"), indent=1)
    print("saved", path)


if __name__ == "__main__":
    main()
