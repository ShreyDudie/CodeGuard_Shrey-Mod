"""Interception proof: CodeGuard gates real calls and a blocked snippet provably never executes.

    python demo/intercept_check.py                      # uses demo/safe_snippet.py + demo/unsafe_snippet.py
    python demo/intercept_check.py --safe A --unsafe B  # organizer-provided safe/unsafe pair (.py or .sh)

What is proven (observable side effects, not just a verdict):
  1. SAFE snippet   -> verdict allow -> executed       -> ALLOWED.marker EXISTS
  2. UNSAFE snippet -> verdict block -> GuardBlocked   -> BLOCKED_SHOULD_NOT_EXIST.marker is ABSENT
  3. A decorated function (@guarded) refuses a blocked argument and never enters its body.
Exit code 0 only if every check passes.  Nothing outside the safe/unsafe pair is ever executed, and the unsafe
snippet is never executed at all.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

from codeguard.intercept import GuardBlocked, guarded, guarded_exec, require_allow  # noqa: E402

OK, BAD = "[PASS]", "[FAIL]"


def hr(title: str) -> None:
    print("\n" + "=" * 78 + f"\n{title}\n" + "=" * 78)


def show(res: dict, ms: float) -> None:
    print(json.dumps({k: res[k] for k in ("verdict", "risk_score", "categories", "code_language", "vulnerable_lines")}, ensure_ascii=False))
    print("reason :", res["reason"])
    print(f"latency: {ms:.1f} ms")


def run_file(path: str, marker_dir: str, text: str):
    """Scan + execute a snippet file through the guard.  Returns (result, executed_flag)."""
    ext = os.path.splitext(path)[1].lower()
    if ext in (".sh", ".bash"):
        res = require_allow(text, "bash")                     # raises GuardBlocked on block
        subprocess.run(["bash", "-c", text], env={**os.environ, "MARKER_DIR": marker_dir}, check=False)   # only reached on allow
        return res, True
    res = guarded_exec(text, {"MARKER_DIR": marker_dir, "__name__": "__guarded__"})
    return res, True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--safe", default=os.path.join(HERE, "safe_snippet.py"))
    ap.add_argument("--unsafe", default=os.path.join(HERE, "unsafe_snippet.py"))
    ap.add_argument("--marker-dir")
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()

    marker_dir = args.marker_dir or tempfile.mkdtemp(prefix="codeguard_markers_")
    os.makedirs(marker_dir, exist_ok=True)
    allowed_marker = os.path.join(marker_dir, "ALLOWED.marker")
    blocked_marker = os.path.join(marker_dir, "BLOCKED_SHOULD_NOT_EXIST.marker")
    for m in (allowed_marker, blocked_marker):
        if os.path.exists(m):
            os.remove(m)
    ok_all = True

    hr("STEP 0  marker directory (must be empty before the run)")
    print("dir     :", marker_dir)
    print("contents:", os.listdir(marker_dir))

    # ---------------------------------------------------------------- SAFE
    hr("STEP 1  SAFE snippet through the guard  (expected: allow -> runs -> marker appears)")
    safe_text = open(args.safe, encoding="utf-8").read()
    t0 = time.perf_counter()
    try:
        res, executed = run_file(args.safe, marker_dir, safe_text)
        ms = (time.perf_counter() - t0) * 1000
        show(res, ms)
    except GuardBlocked as gb:
        executed = False
        print("unexpected block:", gb.result.get("reason"))
    exists = os.path.exists(allowed_marker)
    print(f"{OK if executed and exists else BAD} ALLOWED.marker exists: {exists}")
    ok_all &= bool(executed and exists)

    # ---------------------------------------------------------------- UNSAFE
    hr("STEP 2  UNSAFE snippet through the guard  (expected: block -> NEVER runs -> no marker)")
    unsafe_text = open(args.unsafe, encoding="utf-8").read()
    blocked = False
    t0 = time.perf_counter()
    try:
        run_file(args.unsafe, marker_dir, unsafe_text)
        ms = (time.perf_counter() - t0) * 1000
        print("!! the unsafe snippet was executed")
    except GuardBlocked as gb:
        ms = (time.perf_counter() - t0) * 1000
        blocked = True
        show(gb.result, ms)
        print("what would have happened (nothing was run):")
        for line in gb.result.get("reason", "").split(". "):
            if line.strip():
                print("   -", line.strip().rstrip("."))
    absent = not os.path.exists(blocked_marker)
    print(f"{OK if blocked and absent else BAD} GuardBlocked raised: {blocked}   BLOCKED_SHOULD_NOT_EXIST.marker absent: {absent}")
    ok_all &= bool(blocked and absent)

    # ---------------------------------------------------------------- decorator
    hr("STEP 3  a real decorated function is gated  (@guarded run_agent_step(code))")
    entered = {"n": 0}

    @guarded
    def run_agent_step(code: str, md: str):
        entered["n"] += 1                                   # observable side effect: only increments if the body runs
        exec(compile(code, "<agent-step>", "exec"), {"MARKER_DIR": md})   # noqa: S102

    decorated_ok = True
    try:
        run_agent_step(unsafe_text, marker_dir)
        decorated_ok = False
    except GuardBlocked as gb:
        print("blocked :", gb.result["verdict"], gb.result["categories"])
    decorated_ok &= entered["n"] == 0 and not os.path.exists(blocked_marker)
    print(f"{OK if decorated_ok else BAD} function body never entered (counter={entered['n']}), unsafe marker absent")
    ok_all &= decorated_ok

    hr("RESULT")
    print("marker dir now contains:", sorted(os.listdir(marker_dir)))
    print("INTERCEPTION PROOF:", "PASS - blocked code never executed" if ok_all else "FAIL")
    if not args.keep and not args.marker_dir:
        shutil.rmtree(marker_dir, ignore_errors=True)
    return 0 if ok_all else 1


if __name__ == "__main__":
    raise SystemExit(main())
