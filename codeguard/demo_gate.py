"""The interception proof as data, for the web UI.

Exactly the same experiment as demo/intercept_check.py, but it returns what happened step by step so the page can draw it:
  safe snippet   -> guard says allow -> it runs      -> ALLOWED.marker appears in a temporary directory
  unsafe snippet -> guard says block -> it NEVER runs -> BLOCKED_SHOULD_NOT_EXIST.marker stays absent
  @guarded function -> body is never entered (a counter stays at 0)

Safety: the only code that can ever run is demo/safe_snippet.py (a fixed file in this repository that writes one marker file).
The unsafe snippet is only scanned, never executed, and no request data is ever executed.  Set CODEGUARD_DEMO=0 to disable the endpoint.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import threading
import time

from .intercept import GuardBlocked, guarded, guarded_exec

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO = os.path.join(ROOT, "demo")
_lock = threading.Lock()
ALLOWED, BLOCKED = "ALLOWED.marker", "BLOCKED_SHOULD_NOT_EXIST.marker"


def enabled() -> bool:
    return os.environ.get("CODEGUARD_DEMO", "1") != "0"


def _preview(text: str, n: int = 14) -> str:
    rows = [r for r in text.split(chr(10))]
    return chr(10).join(rows[:n]) + (chr(10) + "..." if len(rows) > n else "")


def _brief(res: dict, ms: float) -> dict:
    return {"verdict": res["verdict"], "risk_score": res["risk_score"], "categories": res["categories"], "code_language": res["code_language"],
            "vulnerable_lines": res["vulnerable_lines"], "reason": res["reason"], "latency_ms": round(ms, 2)}


def run_interception_demo() -> dict:
    safe_text = open(os.path.join(DEMO, "safe_snippet.py"), encoding="utf-8").read()
    unsafe_text = open(os.path.join(DEMO, "unsafe_snippet.py"), encoding="utf-8").read()
    with _lock:
        md = tempfile.mkdtemp(prefix="codeguard_ui_markers_")
        try:
            before = sorted(os.listdir(md))
            steps = []

            # 1. safe snippet: scanned, allowed, executed (this is the only thing that is ever run)
            t0 = time.perf_counter()
            res = guarded_exec(safe_text, {"MARKER_DIR": md, "__name__": "__guarded__"})
            ms = (time.perf_counter() - t0) * 1000
            steps.append({"id": "safe", "title": "Safe snippet", "code": _preview(safe_text), "scan": _brief(res, ms), "gate": "allowed", "executed": True,
                          "marker": {"name": ALLOWED, "exists": os.path.exists(os.path.join(md, ALLOWED)), "expected": "appears"}})

            # 2. unsafe snippet: scanned and blocked; it is never executed
            t0 = time.perf_counter()
            blocked_result, raised = None, False
            try:
                guarded_exec(unsafe_text, {"MARKER_DIR": md, "__name__": "__guarded__"})
            except GuardBlocked as gb:
                raised, blocked_result = True, gb.result
            ms = (time.perf_counter() - t0) * 1000
            steps.append({"id": "unsafe", "title": "Unsafe snippet", "code": _preview(unsafe_text), "scan": _brief(blocked_result, ms) if blocked_result else None,
                          "gate": "blocked" if raised else "ALLOWED (unexpected)", "executed": not raised, "guard_blocked_raised": raised,
                          "would_have": [s.strip().rstrip(".") for s in (blocked_result or {}).get("reason", "").split(". ") if s.strip()][:4],
                          "marker": {"name": BLOCKED, "exists": os.path.exists(os.path.join(md, BLOCKED)), "expected": "stays absent"}})

            # 3. a decorated function: its body must never be entered for the blocked argument
            entered = {"n": 0}

            @guarded
            def run_agent_step(code: str, marker_dir: str):
                entered["n"] += 1                                  # only increments if the body runs
                exec(compile(code, "<agent-step>", "exec"), {"MARKER_DIR": marker_dir})   # noqa: S102  (never reached for blocked code)

            t0 = time.perf_counter()
            d_raised = False
            try:
                run_agent_step(unsafe_text, md)
            except GuardBlocked:
                d_raised = True
            ms = (time.perf_counter() - t0) * 1000
            steps.append({"id": "decorated", "title": "@guarded run_agent_step(code)", "gate": "blocked" if d_raised else "ALLOWED (unexpected)", "executed": not d_raised,
                          "guard_blocked_raised": d_raised, "body_entered": entered["n"], "latency_ms": round(ms, 2),
                          "marker": {"name": BLOCKED, "exists": os.path.exists(os.path.join(md, BLOCKED)), "expected": "stays absent"}})

            after = sorted(os.listdir(md))
            ok = (steps[0]["executed"] and steps[0]["marker"]["exists"] and steps[1]["gate"] == "blocked" and not steps[1]["executed"] and not steps[1]["marker"]["exists"]
                  and steps[2]["body_entered"] == 0 and not steps[2]["marker"]["exists"])
            return {"pass": bool(ok), "marker_dir_before": before, "marker_dir_after": after, "steps": steps,
                    "summary": "INTERCEPTION PROOF: PASS - blocked code never executed" if ok else "INTERCEPTION PROOF: FAIL"}
        finally:
            shutil.rmtree(md, ignore_errors=True)
