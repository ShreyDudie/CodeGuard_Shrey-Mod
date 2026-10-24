"""Inference glue: turns the naturalness LM into extra evidence (findings) for the fusion step.

The model never blocks on its own: an unnatural long literal only counts when the code also has a way to execute it
(eval/exec/compile, dynamic import, deserialisation).  A weaker signal is recorded for shell/process execution.
"""
from __future__ import annotations

import os
import re
import threading

from ..events import Event, Finding

_HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(_HERE)), "models", "lm_py.npz")
BPC_THRESHOLD = 6.2          # ~p99 of benign literals on held-out standard-library files (see reports/lm_eval.json)
MIN_LEN = 28
_lm = None
_lock = threading.Lock()
_STR = re.compile(r"""(?P<t>\"\"\"|\'\'\')(?P<tb>.{%d,3000}?)(?P=t)|\"(?P<d>(?:[^\"\\\n]|\\.){%d,3000})\"|\'(?P<s>(?:[^\'\\\n]|\\.){%d,3000})\'""" % (MIN_LEN, MIN_LEN, MIN_LEN), re.S)
_HASHLIKE = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{56}$|^[0-9a-fA-F]{64}$|^[0-9a-fA-F]{96}$|^[0-9a-fA-F]{128}$|^[0-9a-fA-F-]{36}$")


def get_lm():
    global _lm
    if _lm is None:
        with _lock:
            if _lm is None:
                if not os.path.exists(MODEL_PATH):
                    return None
                from .lm import NGramLM
                _lm = NGramLM.load(MODEL_PATH)
    return _lm


_BLOBSHAPE = re.compile(r"[A-Za-z0-9+/=_\-]{28,}")
_ESCSHAPE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}|(?:\\u[0-9a-fA-F]{4}){8,}|(?:\\[0-7]{3}){8,}")


def payload_shape(s: str) -> bool:
    """Could this literal be a packed/encoded blob?  (base64/hex/urlsafe alphabet without spaces, or dense escape sequences)"""
    if _ESCSHAPE.search(s):
        return True
    if re.fullmatch(r"[A-Za-z_\-]+", s):          # identifiers / slugs: a random base64 blob of this length almost always contains a digit or +/
        return False
    return bool(_BLOBSHAPE.fullmatch(s))


def _benign_format(s: str) -> bool:
    if _HASHLIKE.match(s):
        return True
    if "://" in s or s.startswith(("/", "./", "../", "~")) and " " not in s and s.count("/") >= 1 and len(set(s)) < 30:
        return True
    if re.match(r"^-----BEGIN [A-Z ]+-----", s):
        return True
    return False


def anomalous_literals(code: str, limit: int = 60, char_budget: int = 40000) -> list:
    """-> [(line, bits_per_char, preview)] for long literals that look nothing like ordinary code/text"""
    lm = get_lm()
    if lm is None:
        return []
    out = []
    spent = 0
    for i, m in enumerate(_STR.finditer(code)):
        if i >= limit or spent > char_budget:
            break
        body = m.group("tb") or m.group("d") or m.group("s") or ""
        if not body or _benign_format(body):
            continue
        if not payload_shape(body):                    # prose, regexes, tables, names: not a packed blob
            continue
        spent += len(body)
        bpc = lm.bits_per_char(body)
        if bpc >= BPC_THRESHOLD:
            out.append((code.count("\n", 0, m.start()) + 1, round(bpc, 2), body[:24] + ("…" if len(body) > 24 else "")))
    return out


def predict(code: str, lang: str, ctx, findings: list) -> tuple:
    info: dict = {"lm": "naturalness-5gram"}
    caps = {e.cap for e in ctx.events}
    strong = caps & {"EVAL", "PIPE_EXEC"}
    medium = caps & {"LOAD_MODULE", "DESERIALIZE"}
    weak = caps & {"EXEC_SHELL", "EXEC_PROC"}
    if not (strong or medium or weak) and not re.search(r"\b(eval|exec|compile|Function|system|popen|spawn|__import__)\b", code):
        return None, info          # nothing could execute a payload: skip scoring entirely (also keeps latency low)
    lits = anomalous_literals(code)
    info["anomalous_literals"] = len(lits)
    if not lits:
        return None, info
    info["max_bpc"] = max(b for _l, b, _p in lits)
    w = 0.72 if strong else 0.60 if medium else 0.50 if re.search(r"\b(eval|exec|compile|Function)\s*\(", code) else 0.38 if weak else 0.35
    line = lits[0][0]
    ev = Event(cap="TEXT", line=line, name="unnatural-literal", target=lits[0][2], flags={"ml_unnatural"}, extra={"bpc": info["max_bpc"]}, lines={l for l, _b, _p in lits[:4]})
    findings.append(Finding("obfuscated_execution", w, "ml.unnatural_literal_with_executor", ["T1027"], sorted({l for l, _b, _p in lits[:4]}),
                            does="contains a long string that looks nothing like normal code or text (a packed or encoded payload) next to code that can execute things",
                            why="packed payloads are how malware hides what it will run",
                            would="the hidden payload could be unpacked and run", event=ev))
    info["added"] = w
    return None, info
