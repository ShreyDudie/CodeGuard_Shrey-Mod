"""The scan pipeline: language ID -> front-end -> events -> rules -> (models) -> fusion -> explanation."""
from __future__ import annotations

import os
import re
import time
import traceback
from dataclasses import dataclass, field
from typing import Optional

from . import engine, explain, fusion, textscan
from .ctx import Ctx, Stop
from .events import SECRET, SENS_SYS
from .langid import detect_language

MAX_CODE_CHARS = 200_000          # longer input is analysed as its first 150k + last 50k characters (an attacker cannot hide code behind padding)
_KNOWN_LANGS = {"python", "bash", "javascript", "typescript", "sql", "yaml", "markdown", "powershell", "php", "ruby", "go", "java", "csharp", "c", "dockerfile"}


@dataclass
class Analysis:
    code: str
    language: str
    ctx: Ctx
    findings: list
    fused: dict
    verdict: str
    risk: float
    categories: list
    reason: str
    lines: list
    elapsed_ms: float = 0.0
    model_info: dict = field(default_factory=dict)


def warmup() -> None:
    """Load rule files, API semantics and package lists once so the first real request is fast."""
    try:
        from . import knowledge
        knowledge._pkg_index("pypi")          # builds the typosquat index (~0.5 s) once, not on the first install command
        knowledge._pkg_index("npm")
    except Exception:
        pass
    for snippet in ("import os\nos.system('echo hi')\n", "echo hello\n", "SELECT 1;\n", "const a = require('fs');\n", "# Title\n\nSome text.\n", "name: x\non: push\njobs: {}\n",
                    "import base64\n# please review this change carefully before merging\nx = base64.b64decode('QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=')\neval(x)\n"):
        try:
            scan(snippet, use_models=True)          # also loads numpy, the naturalness model and the instruction-text model
        except Exception:
            pass


def _sanitize(code) -> str:
    if code is None:
        return ""
    if isinstance(code, bytes):
        code = code.decode("utf-8", "replace")
    if not isinstance(code, str):
        try:
            code = str(code)
        except Exception:
            code = ""
    code = code.replace("\x00", "")
    if code.startswith("﻿"):
        code = code[1:]
    code = code.replace("\r\n", "\n").replace("\r", "\n")
    if len(code) > MAX_CODE_CHARS:
        code = code[:150_000] + chr(10) + code[-(MAX_CODE_CHARS - 150_000):]
    return code


def _run_frontend(lang: str, code: str, ctx: Ctx) -> None:
    ctx.lang = lang
    try:
        if lang == "python":
            from . import pyfe
            ok = pyfe.analyze_python_text(code, ctx)
            if not ok:
                from . import genericfe
                genericfe.analyze_generic_text(code, ctx, "python")
            return
        if lang == "bash":
            from . import shfe
            shfe.analyze_shell(code, ctx)
            textscan.scan_text_secrets(code, ctx, "bash")
            return
        if lang == "sql":
            from . import sqlfe
            sqlfe.analyze_sql_text(code, ctx)
            textscan.scan_text_secrets(code, ctx, "sql")
            return
        if lang in ("javascript", "typescript"):
            from . import jsfe
            jsfe.analyze_js_text(code, ctx)
            textscan.scan_text_secrets(code, ctx, lang)
            return
        if lang == "yaml":
            from . import yamlfe
            yamlfe.analyze_yaml_text(code, ctx)
            textscan.scan_text_secrets(code, ctx, "yaml")
            return
        if lang == "markdown":
            from . import mdfe
            mdfe.analyze_markdown_text(code, ctx)
            textscan.scan_text_secrets(code, ctx, "markdown")
            return
        from . import genericfe
        genericfe.analyze_generic_text(code, ctx, lang)
    except Stop as s:
        ctx.notes.append(f"analysis budget exhausted: {s}")
    except Exception as e:  # never let a front-end bug break the verdict
        ctx.notes.append(f"frontend {lang} error: {type(e).__name__}: {e}")
        ctx.notes.append(traceback.format_exc(limit=3))
        try:
            from . import genericfe
            genericfe.analyze_generic_text(code, ctx, lang)
        except Exception as e2:
            ctx.notes.append(f"generic fallback error: {type(e2).__name__}")


def _scan_tail_if_stopped(lang: str, code: str, ctx: Ctx) -> None:
    """If the first pass ran out of budget, the end of a long file was never examined: padding must not hide code.
    Analyse the last lines on their own and keep what they find (line numbers are shifted back into the full text)."""
    if not any("stopped" in n for n in ctx.notes):
        return
    rows = code.split(chr(10))
    if len(rows) <= 700:
        return
    start = len(rows) - 600
    tail_ctx = Ctx()
    tail_ctx.line_base = start
    try:
        _run_frontend(lang, chr(10).join(rows[start:]), tail_ctx)
        textscan.finalize_texts(tail_ctx)
    except Exception as e:
        ctx.notes.append(f"tail pass error: {e}")
        return
    ctx.events.extend(tail_ctx.events)
    ctx.notes.append("tail of a long file analysed separately")


def analyze(code, use_models: bool = True, language: Optional[str] = None) -> Analysis:
    t0 = time.perf_counter()
    code = _sanitize(code)
    submitted = code
    try:
        from .unglue import undouble_spaces
        code = undouble_spaces(code) or code          # PDF-style doubled spacing (line numbers are unaffected)
    except Exception:
        pass
    if chr(10) not in code.strip() and len(code) > 20:     # statements run together on one line: recover the structure (see unglue.py)
        try:
            from .unglue import unglue
            code = unglue(code) or code
        except Exception:
            pass
    lang = detect_language(code) if code.strip() else "unknown"
    if language and language.lower() in _KNOWN_LANGS:
        lang = language.lower()
    ctx = Ctx()
    if code.strip():
        _run_frontend(lang, code, ctx)
        try:
            textscan.finalize_texts(ctx)
        except Exception as e:
            ctx.notes.append(f"text scoring error: {e}")
        _scan_tail_if_stopped(lang, code, ctx)
    findings = engine.run_rules(ctx.events)
    if not _inclusive() and any(f.category == "obfuscated_execution" and f.rule in ("obf.decoded_execution", "obf.decoded_label_exec") for f in findings):
        # what a decoded payload would do is part of the hiding, not a separate finding (dataset convention: decode-then-run is obfuscated_execution)
        findings = [f for f in findings if f.category == "obfuscated_execution" or "from_decoded" not in (f.event.flags if f.event is not None else set())]
    model_cat = None
    model_info: dict = {}
    if use_models and code.strip():
        try:
            from .ml import infer
            model_cat, model_info = infer.predict(code, lang, ctx, findings)
        except Exception as e:
            ctx.notes.append(f"model error: {type(e).__name__}: {e}")
    if not _inclusive():
        findings = _drop_subsumed(findings)
    fused = fusion.fuse(findings, model_cat)
    verdict, risk, cats = fusion.decide(fused)
    reason = explain.build_reason(fused, verdict, cats, ctx.events)
    lines = _drop_signature_lines(vulnerable_lines(fused, cats, verdict), code)
    if code is not submitted and chr(10) not in submitted.strip() and lines:
        lines = [1]                   # the submitted text is a single line, so that is the only line there is
    return Analysis(submitted, lang, ctx, findings, fused, verdict, risk, cats, reason, lines, (time.perf_counter() - t0) * 1000.0, model_info)


def _inclusive() -> bool:
    """Default 'inclusive': report every category a behaviour touches (secret read AND exfiltration, SSRF AND exfiltration ...), as the
    contest's multi-label scoring expects. CODEGUARD_LABELS=primary reports only the category that names the behaviour.
    The organiser's 42 dev rows pass 42/42 under both styles."""
    return os.environ.get("CODEGUARD_LABELS", "inclusive").lower() == "inclusive"


_PRIVATE_SSRF_RULES = {"ssrf.private_network", "ssrf.loopback_const", "ssrf.internal_name"}


def _drop_subsumed(findings: list) -> list:
    """One behaviour should be reported under the category that names it, not under every category it touches.
    * data sent to a private/loopback address is exfiltration; it is not also an SSRF finding for that same address,
    * reading an operating-system account file (shadow/passwd) is exfiltration when that data is then sent out, not also secret access."""
    exfil = [f for f in findings if f.category == "data_exfiltration" and f.weight >= 0.5 and f.event is not None]
    if not exfil:
        return findings
    hosts = {f.event.target for f in exfil if f.event.target}
    # a fixed, named outside destination: the point of the code is the sending, so reading the data is part of that finding
    named_outside = any(f.event.hostc in ("SUSPICIOUS", "DROPSITE", "EXTERNAL", "EXTERNAL_IP", "PRIVATE") and f.event.hostc not in ("USER", "UNKNOWN", None) for f in exfil)
    out = []
    dropped_lines: set = set()
    for f in findings:
        ev = f.event
        if f.category == "ssrf_network_exfil" and f.rule in _PRIVATE_SSRF_RULES and ev is not None and ev.target in hosts:
            dropped_lines |= set(f.lines)
            continue
        if f.category == "secret_access" and named_outside and ev is not None and ev.cap in ("READ_FILE", "ENV_READ"):
            dropped_lines |= set(f.lines)
            continue
        out.append(f)
    if dropped_lines:                      # the surviving finding keeps pointing at where the data came from
        top = max((f for f in out if f.category == "data_exfiltration"), key=lambda f: f.weight)
        top.lines = sorted(set(top.lines) | dropped_lines)
    return out


_SIG = re.compile(r"^\s*(async\s+def|def|class|function|async\s+function)(?![\w])")


def _drop_signature_lines(lines: list, code: str) -> list:
    """A function signature only declares the input; point at where it is used, unless that is all there is."""
    rows = code.split(chr(10))
    keep = [l for l in lines if not (0 < l <= len(rows) and _SIG.match(rows[l - 1]))]
    return keep or lines


def vulnerable_lines(fused: dict, cats: list, verdict: str) -> list:
    if verdict != "block":
        return []
    out: set = set()
    for c in cats:
        for f in fused["groups"].get(c, [])[:4]:
            if f.weight >= 0.25:
                out.update(l for l in f.lines if isinstance(l, int) and l > 0)
    if not out:                       # a block always points somewhere: fall back to the lines of the evidence events
        for c in cats:
            for f in fused["groups"].get(c, []):
                if f.event is not None:
                    out.update(l for l in f.event.all_lines() if isinstance(l, int) and l > 0)
    return sorted(out) or [1]


def result_dict(a: Analysis, verbose: bool = False) -> dict:
    d = {
        "verdict": a.verdict,
        "risk_score": float(a.risk),
        "categories": list(a.categories),
        "code_language": a.language,
        "reason": a.reason,
        "vulnerable_lines": list(a.lines),
    }
    if verbose:
        d["explanation"] = verbose_explanation(a)
    return d


def verbose_explanation(a: Analysis) -> dict:
    ev = []
    for c, fs in a.fused["groups"].items():
        for f in fs[:6]:
            ev.append({"category": c, "rule": f.rule, "weight": round(f.weight, 3), "lines": f.lines[:12], "tags": f.tags})
    would = []
    for c in a.categories:
        for f in a.fused["groups"].get(c, [])[:2]:
            if f.would:
                would.append(explain.fill(f.would, f.event))
    return {
        "plain_summary": a.reason,
        "what_would_happen": would,
        "problems": [{"line": d.line, "kind": d.kind, "message": d.message} for d in a.ctx.defects],
        "category_scores": {k: round(v, 3) for k, v in a.fused["cat_scores"].items()},
        "evidence": ev,
        "notes": [n for n in a.ctx.notes if not n.startswith("Traceback")][:6],
        "events": len(a.ctx.events),
        "analysis_ms": round(a.elapsed_ms, 2),
        "models": a.model_info,
    }


def scan(code, verbose: bool = False, use_models: bool = True, language: Optional[str] = None) -> dict:
    """Public entry point: always returns a schema-valid dict, never raises."""
    try:
        return result_dict(analyze(code, use_models=use_models, language=language), verbose)
    except Exception as e:  # fail closed, but still schema-valid
        return {
            "verdict": "block",
            "risk_score": 0.6,
            "categories": ["obfuscated_execution"],
            "code_language": "unknown",
            "reason": "The analyser could not finish safely, so the code is blocked as a precaution. (" + type(e).__name__ + ")",
            "vulnerable_lines": [],
        }
