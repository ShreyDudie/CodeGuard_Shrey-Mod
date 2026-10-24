"""Fusion: turn rule findings into per-category scores, a verdict and a risk score."""
from __future__ import annotations

from collections import defaultdict

CATEGORIES = ["secret_access", "data_exfiltration", "destructive_command", "persistence_or_privesc", "obfuscated_execution", "dependency_risk",
              "resource_exhaustion", "ssrf_network_exfil", "ai_targeted_instructions"]

BLOCK_T = 0.50          # category score at/above which the snippet is blocked
CAT_MIN = 0.50          # minimum category score to be reported
CAT_MIN_BY_CATEGORY: dict = {}   # optional per-category override, e.g. {"ai_targeted_instructions": 0.4}; empty = every category uses CAT_MIN


def fuse(findings: list, model_cat: dict | None = None) -> dict:
    """-> {"cat_scores": {...}, "top": float, "groups": {cat: [Finding...]}}"""
    best: dict = {}
    for f in findings:
        key = (f.category, f.rule)
        cur = best.get(key)
        if cur is None or f.weight > cur.weight:
            lines = set(f.lines) | (set(cur.lines) if cur else set())
            nf = f if cur is None or f.weight > cur.weight else cur
            nf.lines = sorted(lines)
            best[key] = nf
        else:
            cur.lines = sorted(set(cur.lines) | set(f.lines))
    groups: dict = defaultdict(list)
    for (cat, _r), f in best.items():
        groups[cat].append(f)
    cat_scores: dict = {}
    for cat, fs in groups.items():
        p = 1.0
        for f in sorted(fs, key=lambda x: -x.weight):
            p *= (1.0 - min(max(f.weight, 0.0), 0.995))
        cat_scores[cat] = 1.0 - p
    if model_cat:
        for cat, ms in model_cat.items():
            cat_scores[cat] = max(cat_scores.get(cat, 0.0), ms)
    top = max(cat_scores.values()) if cat_scores else 0.0
    for cat in groups:
        groups[cat].sort(key=lambda x: -x.weight)
    return {"cat_scores": cat_scores, "top": top, "groups": dict(groups)}


def decide(fused: dict) -> tuple:
    """-> (verdict, risk_score, categories)"""
    cs = fused["cat_scores"]
    top = fused["top"]
    verdict = "block" if top >= BLOCK_T else "allow"
    cats = [c for c in CATEGORIES if cs.get(c, 0.0) >= CAT_MIN_BY_CATEGORY.get(c, CAT_MIN)] if verdict == "block" else []
    if verdict == "block" and not cats and cs:
        cats = [max(cs, key=cs.get)]
    if verdict == "block":
        extra = 1.0
        for c, s in cs.items():
            if s < top:
                extra *= (1.0 - 0.25 * s)
        risk = min(0.995, 1.0 - (1.0 - top) * extra)
        risk = max(risk, 0.5)
    else:
        risk = min(0.49, top * 0.85)
    return verdict, round(risk, 4), cats
