"""Score the service's own predictions against an answer key that a judge submits.

parse_key()  reads the answer key: JSON (list, object per line, objects back to back, or {id: output}), CSV, or the text layer of a PDF.  Each entry needs the expected
             verdict (or a 0/1 label) and may carry categories, code_language, risk_score, vulnerable_lines; it is identified by an id, by its code, or by its position.
match()      pairs every key entry with the prediction the service made (from the request log), by id, by code, or by order; an entry that carries code but was never
             requested is scanned on the spot.
metrics()    accuracy, precision, recall, F1, false positives, confusion matrix, per-category precision / recall / F1, exact category sets, language accuracy,
             risk-score error and vulnerable-line overlap.
"""
from __future__ import annotations

import csv
import io
import json
import re
from typing import Optional

from . import predlog
from .fusion import CATEGORIES

_BLOCK_WORDS = {"1", "true", "block", "blocked", "malicious", "unsafe", "bad", "vulnerable", "reject", "deny", "yes"}
_ALLOW_WORDS = {"0", "false", "allow", "allowed", "benign", "safe", "good", "clean", "accept", "no"}
_CONTAINERS = ("expected_output", "expected", "output", "answer", "ground_truth", "truth", "gold", "label_output")
_LIST_KEYS = ("items", "data", "results", "answers", "samples", "expected", "key", "rows", "records", "outputs")


# ---------------------------------------------------------------------------------------------------------------- reading the key
def _json_objects(text: str) -> list:
    """Every top-level {...} in the text, tolerant of line wrapping inside strings (PDF text layers) and of several objects back to back."""
    out, depth, start, in_str, esc = [], 0, None, False, False
    for i, ch in enumerate(text):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth:
            depth -= 1
            if depth == 0 and start is not None:
                chunk = text[start:i + 1]
                try:
                    out.append(json.loads(chunk, strict=False))
                except ValueError:
                    try:
                        out.append(json.loads(re.sub(r",\s*([}\]])", r"\1", chunk), strict=False))
                    except ValueError:
                        pass
                start = None
    return out


def _as_rows(obj) -> list:
    if isinstance(obj, list):
        rows = []
        for x in obj:
            rows.extend(_as_rows(x) if isinstance(x, list) else [x])
        return rows
    if isinstance(obj, dict):
        for k in _LIST_KEYS:
            if isinstance(obj.get(k), list):
                return _as_rows(obj[k])
        vals = list(obj.values())
        if vals and all(isinstance(v, dict) for v in vals) and not any(k in obj for k in ("verdict", "label", "categories", "expected_output")):
            return [{"id": k, **v} if "id" not in v else v for k, v in obj.items()]          # {id: {verdict..}, id2: {...}}
        return [obj]
    return []


def _cats(v) -> list:
    if v is None:
        return []
    if isinstance(v, str):
        parts = [p.strip() for p in re.split(r"[,;|/]+", v)]
    elif isinstance(v, (list, tuple)):
        parts = [str(p).strip() for p in v]
    else:
        parts = [str(v)]
    return [p for p in parts if p and p.lower() not in ("benign", "none", "null", "n/a", "safe", "[]", "nan")]


def _lines(v) -> Optional[list]:
    if v is None or v == "":
        return None
    if isinstance(v, (int, float)):
        return [int(v)]
    if isinstance(v, str):
        return sorted({int(x) for x in re.findall(r"\d+", v)})
    try:
        return sorted({int(x) for x in v})
    except (TypeError, ValueError):
        return None


def _verdict(v) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip().lower()
    if s in _BLOCK_WORDS:
        return "block"
    if s in _ALLOW_WORDS:
        return "allow"
    return None


def normalise_row(d: dict) -> Optional[dict]:
    if not isinstance(d, dict):
        return None
    exp = d
    for k in _CONTAINERS:
        if isinstance(d.get(k), dict):
            exp = {**d, **d[k]}
            break
    verdict = _verdict(exp.get("verdict", exp.get("decision")))
    if verdict is None:
        for k in ("label", "is_malicious", "malicious", "unsafe", "is_unsafe", "block"):
            if k in exp:
                verdict = _verdict(exp[k])
                if verdict:
                    break
    cats = _cats(exp.get("categories", exp.get("category", exp.get("labels"))))
    if verdict is None:
        raw_cat = str(exp.get("category", "")).strip().lower()
        if cats:
            verdict = "block"
        elif raw_cat in ("benign", "safe", "none"):
            verdict = "allow"
    if verdict is None:
        return None
    if verdict == "allow":
        cats = []
    risk = exp.get("risk_score", exp.get("risk"))
    try:
        risk = float(risk) if risk not in (None, "") else None
    except (TypeError, ValueError):
        risk = None
    code = d.get("code") if isinstance(d.get("code"), str) else (exp.get("code") if isinstance(exp.get("code"), str) else None)
    ident = d.get("id", exp.get("id", d.get("sample_id", d.get("name"))))
    lang = exp.get("code_language", exp.get("language"))
    return {"id": None if ident is None else str(ident), "code": code, "verdict": verdict, "categories": cats, "code_language": (str(lang).strip().lower() if lang else None),
            "risk_score": risk, "vulnerable_lines": _lines(exp.get("vulnerable_lines", exp.get("lines")))}


def parse_key(raw, filename: str = "") -> tuple:
    """-> (rows, notes).  raw is bytes or str."""
    notes: list = []
    if isinstance(raw, bytes):
        if raw[:5] == b"%PDF-" or filename.lower().endswith(".pdf"):
            from .snippets import _pdf_text
            text = _pdf_text(raw)
            notes.append("read the text layer of a PDF")
        else:
            text = raw.decode("utf-8-sig", "replace")
    else:
        text = raw
    text = text.lstrip("﻿")
    head = text.lstrip()[:1]
    rows: list = []
    if head not in ("{", "[") or filename.lower().endswith(".csv"):
        try:
            sample = text[:4000]
            dialect = csv.Sniffer().sniff(sample.split("\n", 1)[0] + "\n") if "," in sample.split("\n", 1)[0] or ";" in sample.split("\n", 1)[0] else None
            if dialect is not None:
                csv.field_size_limit(10 ** 9)
                rows = list(csv.DictReader(io.StringIO(text), dialect=dialect))
                if rows and not any(k and k.strip().lower() in ("verdict", "label", "categories", "category", "expected", "decision") for k in rows[0]):
                    rows = []
        except (csv.Error, ValueError):
            rows = []
        if rows:
            notes.append("read as CSV")
    if not rows:
        try:
            rows = _as_rows(json.loads(text, strict=False))
        except ValueError:
            rows = _as_rows(_json_objects(text))
            if rows:
                notes.append("read as separate JSON objects")
    out = [r for r in (normalise_row(x) for x in rows) if r]
    skipped = len(rows) - len(out)
    if skipped:
        notes.append(f"{skipped} entr{'y' if skipped == 1 else 'ies'} had no verdict or label and {'was' if skipped == 1 else 'were'} skipped")
    return out, notes


# ---------------------------------------------------------------------------------------------------------------- matching
def match(rows: list, log: list, mode: str = "auto", scan_missing: bool = True) -> tuple:
    """-> (pairs, info).  pairs[i] = (key_row, prediction_dict_or_None, matched_by, log_entry_or_None)."""
    from . import pipeline
    mode = mode if mode in ("auto", "id", "code", "order") else "auto"
    used: set = set()
    by_id: dict = {}
    by_hash: dict = {}
    for e in log:
        if e["id"] is not None:
            by_id.setdefault(e["id"], []).append(e)
        by_hash.setdefault(e["hash"], []).append(e)

    def take(lst):
        for e in lst or []:
            if e["seq"] not in used:
                used.add(e["seq"])
                return e
        return None

    pairs: list = [None] * len(rows)
    info = {"mode": mode, "by_id": 0, "by_code": 0, "by_order": 0, "scanned_now": 0, "unmatched": 0}
    if mode != "order":
        for i, r in enumerate(rows):
            e = None
            how = None
            if mode in ("auto", "id") and r["id"] is not None:
                e = take(by_id.get(r["id"]))
                how = "id"
            if e is None and mode in ("auto", "code") and r["code"]:
                e = take(by_hash.get(predlog.code_hash(r["code"])))
                how = "code"
            if e is not None:
                pairs[i] = (r, e["response"], how, e)
                info["by_" + how] += 1
    # order: used when asked, or when the key has no usable identifier at all, or when no key id appears in the log
    key_has_code = any(r["code"] for r in rows)
    order_ok = mode == "order" or (mode == "auto" and not key_has_code and info["by_id"] == 0)
    if order_ok:
        api_calls = [e for e in log if e["source"] == "api"]          # UI scans and the sample button are not part of the judge's run
        remaining = [e for e in api_calls if e["seq"] not in used] if mode != "order" else api_calls
        j = 0
        for i, r in enumerate(rows):
            if pairs[i] is None and j < len(remaining):
                pairs[i] = (r, remaining[j]["response"], "order", remaining[j])
                used.add(remaining[j]["seq"])
                j += 1
                info["by_order"] += 1
    if scan_missing:
        for i, r in enumerate(rows):
            if pairs[i] is None and r["code"]:
                res = pipeline.scan(r["code"])
                pairs[i] = (r, {k: res.get(k) for k in ("verdict", "risk_score", "categories", "code_language", "reason", "vulnerable_lines")}, "scanned now", None)
                info["scanned_now"] += 1
    for i, r in enumerate(rows):
        if pairs[i] is None:
            pairs[i] = (r, None, None, None)
            info["unmatched"] += 1
    info["log_entries_unused"] = len([e for e in log if e["seq"] not in used])
    return pairs, info


# ---------------------------------------------------------------------------------------------------------------- metrics
def _prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f


def metrics(pairs: list) -> dict:
    scored = [(r, g, how, e) for r, g, how, e in pairs if g is not None]
    tp = fp = fn = tn = exact = lang_n = lang_ok = line_n = line_exact = risk_n = band = 0
    jac, risk_err = [], []
    cat_names = list(CATEGORIES)
    for r, g, _h, _e in scored:
        for c in list(r["categories"]) + list(g.get("categories") or []):
            if c not in cat_names:
                cat_names.append(c)
    per = {c: [0, 0, 0] for c in cat_names}
    items = []
    for idx, (r, g, how, e) in enumerate(pairs):
        if g is None:
            items.append({"n": idx + 1, "id": r["id"], "matched_by": None, "expected": {k: r[k] for k in ("verdict", "categories", "code_language", "risk_score", "vulnerable_lines")}, "got": None,
                          "verdict_ok": None, "categories_ok": None, "language_ok": None, "flags": ["no prediction found"], "code": (r["code"] or "")[:160]})
            continue
        pos, blk = r["verdict"] == "block", g["verdict"] == "block"
        tp += pos and blk
        fn += pos and not blk
        fp += (not pos) and blk
        tn += (not pos) and not blk
        es, gs = set(r["categories"]), set(g.get("categories") or [])
        cats_ok = es == gs
        exact += cats_ok
        for c in cat_names:
            per[c][0] += c in es and c in gs
            per[c][1] += c not in es and c in gs
            per[c][2] += c in es and c not in gs
        lang_ok_row = None
        if r["code_language"]:
            lang_n += 1
            lang_ok_row = (g.get("code_language") or "").lower() == r["code_language"]
            lang_ok += lang_ok_row
        jac_row = None
        if r["vulnerable_lines"] is not None:
            line_n += 1
            a, b = set(g.get("vulnerable_lines") or []), set(r["vulnerable_lines"])
            line_exact += a == b
            jac_row = 1.0 if not a and not b else len(a & b) / len(a | b)
            jac.append(jac_row)
        err = None
        if r["risk_score"] is not None and g.get("risk_score") is not None:
            risk_n += 1
            err = abs(float(g["risk_score"]) - r["risk_score"])
            risk_err.append(err)
            band += (r["risk_score"] >= 0.5) == (float(g["risk_score"]) >= 0.5)
        flags = []
        if pos != blk:
            flags.append("false negative (missed attack)" if pos else "false positive")
        elif not cats_ok:
            flags.append("categories differ")
        if lang_ok_row is False:
            flags.append("language differs")
        items.append({"n": idx + 1, "id": r["id"], "matched_by": how, "expected": {k: r[k] for k in ("verdict", "categories", "code_language", "risk_score", "vulnerable_lines")},
                      "got": {k: g.get(k) for k in ("verdict", "categories", "code_language", "risk_score", "vulnerable_lines")}, "reason": g.get("reason"),
                      "verdict_ok": pos == blk, "categories_ok": cats_ok, "language_ok": lang_ok_row, "lines_overlap": None if jac_row is None else round(jac_row, 3),
                      "risk_abs_error": None if err is None else round(err, 3), "flags": flags, "code": ((e or {}).get("code") or r["code"] or "")[:160]})
    n = len(scored)
    p, rc, f1 = _prf(tp, fp, fn)
    ctp, cfp, cfn = sum(v[0] for v in per.values()), sum(v[1] for v in per.values()), sum(v[2] for v in per.values())
    cp, cr, cf = _prf(ctp, cfp, cfn)
    per_out = {}
    for c, (a, b, d) in per.items():
        pp, rr, ff = _prf(a, b, d)
        if a + b + d:
            per_out[c] = {"tp": a, "fp": b, "fn": d, "support": a + d, "precision": round(pp, 4), "recall": round(rr, 4), "f1": round(ff, 4)}
    macro = [v for v in per_out.values() if v["support"] or v["fp"]]
    return {"keyed": len(pairs), "scored": n, "unmatched": len(pairs) - n,
            "verdict": {"accuracy": round((tp + tn) / n, 4) if n else None, "precision": round(p, 4), "recall": round(rc, 4), "f1": round(f1, 4),
                        "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else None, "false_negative_rate": round(fn / (fn + tp), 4) if fn + tp else None,
                        "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn), "expected_block": int(tp + fn), "expected_allow": int(fp + tn)},
            "categories": {"exact_set_match": round(exact / n, 4) if n else None, "micro_precision": round(cp, 4), "micro_recall": round(cr, 4), "micro_f1": round(cf, 4),
                           "macro_f1": round(sum(v["f1"] for v in macro) / len(macro), 4) if macro else None, "per_category": per_out},
            "language": {"scored": lang_n, "accuracy": round(lang_ok / lang_n, 4) if lang_n else None},
            "vulnerable_lines": {"scored": line_n, "exact_match": round(line_exact / line_n, 4) if line_n else None, "mean_overlap": round(sum(jac) / len(jac), 4) if jac else None},
            "risk_score": {"scored": risk_n, "mean_abs_error": round(sum(risk_err) / len(risk_err), 4) if risk_err else None, "same_side_of_0_5": round(band / risk_n, 4) if risk_n else None},
            "items": items}


def score(raw, filename: str = "", mode: str = "auto", scan_missing: bool = True, log: Optional[list] = None) -> dict:
    rows, notes = parse_key(raw, filename)
    if not rows:
        return {"error": "no answers found in the key: each entry needs a verdict (allow / block) or a 0/1 label, plus an id or the code", "notes": notes}
    log = predlog.snapshot() if log is None else log
    pairs, info = match(rows, log, mode, scan_missing)
    out = metrics(pairs)
    out["match"] = info
    out["notes"] = notes
    out["log_entries"] = len(log)
    return out


def score_predictions(raw, filename: str, predictions: list) -> dict:
    """Score a list of predictions (the results of scanning a file of snippets, in file order) against an answer key.  Key and predictions are paired by id when both
    carry ids that agree, otherwise by position (the key is one object per snippet, in the same order as the snippets)."""
    rows, notes = parse_key(raw, filename)
    if not rows:
        return {"error": "no answers found in the key: each entry needs a verdict (allow / block) or a 0/1 label", "notes": notes}
    preds = [p for p in (predictions or []) if isinstance(p, dict)]
    info = {"mode": "order", "by_id": 0, "by_code": 0, "by_order": 0, "scanned_now": 0, "unmatched": 0, "log_entries_unused": 0}
    ids = {}
    for j, p in enumerate(preds):
        if p.get("id") is not None:
            ids.setdefault(str(p["id"]), []).append(j)
    id_hits = sum(1 for r in rows if r["id"] is not None and r["id"] in ids)
    use_ids = id_hits >= max(1, len(rows) // 2)
    pairs: list = []
    taken: set = set()
    for i, r in enumerate(rows):
        j = None
        how = None
        if use_ids and r["id"] is not None:
            for cand in ids.get(r["id"], []):
                if cand not in taken:
                    j, how = cand, "id"
                    break
        elif not use_ids and i < len(preds):
            j, how = i, "order"
        if j is None:
            pairs.append((r, None, None, None))
            info["unmatched"] += 1
        else:
            taken.add(j)
            g = preds[j]
            pairs.append((r, {k: g.get(k) for k in ("verdict", "risk_score", "categories", "code_language", "reason", "vulnerable_lines")}, how, {"code": g.get("code", "")}))
            info["by_" + how] += 1
    info["mode"] = "id" if use_ids else "order"
    if len(rows) != len(preds):
        notes.append(f"the key has {len(rows)} entries but the file has {len(preds)} snippets" + ("; extra snippets were not scored" if len(preds) > len(rows) else "; entries without a snippet were not scored"))
    out = metrics(pairs)
    out["match"] = info
    out["notes"] = notes
    out["log_entries"] = len(preds)
    return out
