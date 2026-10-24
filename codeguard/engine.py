"""Rule engine: declarative behaviour signatures (rules/*.yaml) matched over events.

Rules are data.  A rule is a small condition tree over event fields (capability, labels, flags, host/path
classes, multiplicity ...) plus explanation templates.  Rules reload automatically when files change.
"""
from __future__ import annotations

import glob
import os
import time
import re
import threading
from dataclasses import dataclass, field
from typing import Optional

import yaml

from . import knowledge as K
from .events import EMPTY, HOLE, Event, Finding

RULES_DIR = K.RULES_DIR
_lock = threading.Lock()
_cache: dict = {"rules": None, "mtimes": None}


@dataclass
class Rule:
    id: str
    category: str
    weight: object
    when: dict = field(default_factory=dict)
    unless: Optional[dict] = None
    all: Optional[list] = None
    tags: list = field(default_factory=list)
    does: str = ""
    why: str = ""
    would: str = ""
    hard: bool = False
    note: str = ""


_rx_cache: dict = {}


def _rx(p: str):
    r = _rx_cache.get(p)
    if r is None:
        r = re.compile(p, re.I | re.S)
        _rx_cache[p] = r
    return r


def _as_set(v) -> set:
    if v is None:
        return set()
    if isinstance(v, (list, tuple, set)):
        return set(v)
    return {v}


def cond_match(c: dict, ev: Event) -> bool:
    if not c:
        return True
    for k, v in c.items():
        if k == "cap":
            if ev.cap not in _as_set(v):
                return False
        elif k == "name_re":
            if not _rx(v).search(ev.name or ""):
                return False
        elif k == "target_re":
            if not _rx(v).search(ev.target or ""):
                return False
        elif k == "src_re":
            if not _rx(v).search(" | ".join(str(x) for x in (ev.extra.get("src") or ()))):
                return False
        elif k == "content_re":
            if not _rx(v).search(str(ev.extra.get("content") or "")):
                return False
        elif k == "content_empty":
            ce = not str(ev.extra.get("content") or "").strip() or HOLE in str(ev.extra.get("content") or "")
            if bool(v) != ce:
                return False
        elif k == "pathc_any":
            if not (ev.pathc & _as_set(v)):
                return False
        elif k == "pathc_all":
            if not _as_set(v) <= ev.pathc:
                return False
        elif k == "pathc_none":
            if ev.pathc & _as_set(v):
                return False
        elif k == "hostc_any":
            if ev.hostc not in _as_set(v):
                return False
        elif k == "hostc_none":
            if ev.hostc in _as_set(v):
                return False
        elif k == "tl_any":
            if not (ev.tlabels & _as_set(v)):
                return False
        elif k == "tl_none":
            if ev.tlabels & _as_set(v):
                return False
        elif k == "pl_any":
            if not (ev.plabels & _as_set(v)):
                return False
        elif k == "pl_all":
            if not _as_set(v) <= ev.plabels:
                return False
        elif k == "pl_none":
            if ev.plabels & _as_set(v):
                return False
        elif k == "labels_any":
            if not ((ev.tlabels | ev.plabels) & _as_set(v)):
                return False
        elif k == "flags_all":
            if not _as_set(v) <= ev.flags:
                return False
        elif k == "flags_any":
            if not (ev.flags & _as_set(v)):
                return False
        elif k == "flags_none":
            if ev.flags & _as_set(v):
                return False
        elif k == "mult_gte":
            if ev.mult < v:
                return False
        elif k == "mult_lt":
            if ev.mult >= v:
                return False
        elif k == "score_gte":
            if float(ev.extra.get("score", 0)) < v:
                return False
        elif k == "extra_eq":
            for ek, evv in v.items():
                if ev.extra.get(ek) != evv:
                    return False
        elif k == "extra_in":
            for ek, evv in v.items():
                if ev.extra.get(ek) not in _as_set(evv):
                    return False
        elif k == "extra_ne":
            for ek, evv in v.items():
                if ev.extra.get(ek) == evv:
                    return False
        elif k == "any":
            if not any(cond_match(sub, ev) for sub in v):
                return False
        elif k == "not":
            if cond_match(v, ev):
                return False
        else:
            raise ValueError(f"unknown condition key {k!r}")
    return True


def _load_files() -> tuple:
    rules: list = []
    mt = {}
    for fn in sorted(glob.glob(os.path.join(RULES_DIR, "*.rules.yaml"))):
        mt[fn] = os.path.getmtime(fn)
        with open(fn, encoding="utf-8") as f:
            data = yaml.safe_load(f) or []
        for d in data:
            r = Rule(id=d["id"], category=d["category"], weight=d.get("weight", 0.5), when=d.get("when") or {}, unless=d.get("unless"),
                     all=d.get("all"), tags=d.get("tags") or [], does=d.get("does", ""), why=d.get("why", ""), would=d.get("would", ""),
                     hard=bool(d.get("hard", False)), note=d.get("note", ""))
            rules.append(r)
    return rules, mt


def get_rules() -> list:
    with _lock:
        now = time.monotonic()
        if _cache["rules"] is not None and now - _cache.get("checked", 0.0) < 1.0:       # hot reload: look at the files at most once a second
            return _cache["rules"]
        _cache["checked"] = now
        cur = {fn: os.path.getmtime(fn) for fn in glob.glob(os.path.join(RULES_DIR, "*.rules.yaml"))}
        if _cache["rules"] is None or cur != _cache["mtimes"]:
            rules, mt = _load_files()
            _cache["rules"], _cache["mtimes"] = rules, mt
        return _cache["rules"]


def reload_rules() -> int:
    with _lock:
        _cache["rules"] = None
    return len(get_rules())


def _weight(r: Rule, ev: Event) -> float:
    w = r.weight
    if isinstance(w, (int, float)):
        return float(w)
    if w == "score":
        return float(ev.extra.get("score", 0.0))
    if w == "conf":
        return float(ev.extra.get("conf", 0.0))
    if isinstance(w, str) and w.startswith("score*"):
        return float(ev.extra.get("score", 0.0)) * float(w.split("*", 1)[1])
    return 0.5


def run_rules(events: list, rules: Optional[list] = None) -> list:
    rules = rules if rules is not None else get_rules()
    out: list = []
    for r in rules:
        if r.all:
            matched = []
            ok = True
            for sub in r.all:
                m = next((e for e in events if cond_match(sub, e)), None)
                if m is None:
                    ok = False
                    break
                matched.append(m)
            if ok and not (r.unless and any(cond_match(r.unless, e) for e in matched)):
                lines = sorted({ln for e in matched for ln in e.all_lines()})
                out.append(Finding(r.category, _weight(r, matched[0]), r.id, r.tags, lines, r.does, r.why, r.would, matched[0], r.hard))
            continue
        for e in events:
            if cond_match(r.when, e):
                if r.unless and cond_match(r.unless, e):
                    continue
                out.append(Finding(r.category, _weight(r, e), r.id, r.tags, sorted(e.all_lines()), r.does, r.why, r.would, e, r.hard))
    return out
