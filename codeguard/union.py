"""Union of the deterministic engine and the trained ONNX classifier.

    from codeguard.union import scan_union
    result = scan_union(code)        # the same six-field dict as pipeline.scan

Rules of the union:
  * the deterministic result is always computed first and is never weakened by the model;
  * the model may ADD a category only when its probability reaches that category's own threshold
    (calibrated on real benign code so the model alone does not block ordinary functions);
  * lines come from the engine; model lines are added only for categories the model added;
  * if the model files or onnxruntime are missing, the engine result is returned unchanged.
"""
import json
import os
import threading

from . import pipeline

_HERE = os.path.dirname(os.path.abspath(__file__))
_MODELS = os.path.join(os.path.dirname(_HERE), "models")
_clf = None
_clf_failed = False
_meta = {}
_lock = threading.Lock()


def _get_clf():
    global _clf, _clf_failed, _meta
    if _clf is not None or _clf_failed:
        return _clf
    with _lock:
        if _clf is None and not _clf_failed:
            try:
                import sys
                sys.path.insert(0, os.path.dirname(_HERE))
                from onnx_engine import ONNXCodeGuardClassifier
                _clf = ONNXCodeGuardClassifier()
                path = os.path.join(_MODELS, "codeguard_model.json")
                if os.path.exists(path):
                    _meta = json.load(open(path, encoding="utf-8"))
            except Exception:
                _clf_failed = True
    return _clf


def _cat_threshold(cat):
    """Per-category minimum probability for the model to add a category on its own."""
    return float(_meta.get("add_thresholds", {}).get(cat, _meta.get("add_threshold", 0.9)))


def scan_union(code, verbose=False):
    base = pipeline.scan(code, verbose=verbose)
    clf = _get_clf()
    if clf is None or not isinstance(code, str) or not code.strip():
        return base
    try:
        ml = clf.predict(code, with_lines=False)
    except Exception:
        return base
    added = [c for c, p in ml["probabilities"].items() if p >= _cat_threshold(c) and c not in base["categories"]]
    if not added:
        return base
    out = dict(base)
    out["categories"] = [c for c in pipeline.fusion.CATEGORIES if c in set(base["categories"]) | set(added)]
    out["verdict"] = "block"
    out["risk_score"] = round(max(base["risk_score"], 0.5 + 0.49 * max(ml["probabilities"][c] for c in added) - 0.0), 4)
    lines = list(base["vulnerable_lines"])
    try:
        lines += clf._lines(code, added)
    except Exception:
        pass
    n_lines = max(1, len(code.split("\n")))
    out["vulnerable_lines"] = sorted({x for x in lines if 1 <= x <= n_lines}) or [1]
    note = " A trained model also flagged: " + ", ".join(added) + "."
    out["reason"] = (base["reason"] if base["verdict"] == "block" else "") + note if base["verdict"] == "block" else (
        "A trained code model flagged this snippet as " + ", ".join(added) + " (no explicit rule matched, so this is a statistical finding)."
    )
    return out
