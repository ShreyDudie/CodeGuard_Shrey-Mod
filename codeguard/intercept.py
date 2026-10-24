"""Real interception: wrappers that scan code/commands *before* executing them and refuse to run blocked ones.

Everything here is synchronous and fail-closed: if the scan raises, times out or returns a non-"allow" verdict,
the wrapped call is never made.  The exact bytes that were scanned are the bytes that get executed (TOCTOU-safe).
"""
from __future__ import annotations

import functools
import hashlib
import inspect
import shlex
import subprocess
import time
from contextlib import contextmanager
from typing import Any, Callable, Optional

from . import pipeline


pipeline.warmup()


class GuardBlocked(Exception):
    """Raised instead of executing code that CodeGuard blocked."""

    def __init__(self, result: dict, code_hash: str = ""):
        self.result = result
        self.code_hash = code_hash
        super().__init__(f"CodeGuard blocked execution: {result.get('reason', '')}")


def check(code: Any, language: Optional[str] = None) -> dict:
    """Scan `code`; any internal failure is reported as a block (fail-closed)."""
    try:
        res = pipeline.scan(code, language=language) if language else pipeline.scan(code)
    except Exception as e:  # pragma: no cover - pipeline.scan already never raises
        res = {"verdict": "block", "risk_score": 1.0, "categories": [], "code_language": "unknown",
               "reason": f"scan failed ({type(e).__name__}); blocked as a precaution", "vulnerable_lines": []}
    return res


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()


def require_allow(code: str, language: Optional[str] = None) -> dict:
    res = check(code, language)
    if res.get("verdict") != "allow":
        raise GuardBlocked(res, _sha(code))
    return res


@contextmanager
def guard(code: str, language: Optional[str] = None):
    """with guard(code): <execute code here>  - the body is skipped (exception) when blocked."""
    res = require_allow(code, language)
    yield res


def guarded_exec(code: str, globals_: Optional[dict] = None, locals_: Optional[dict] = None, language: Optional[str] = "python") -> dict:
    """Scan then exec a Python source string.  The compiled object is built from the exact string that was scanned."""
    h = _sha(code)
    res = require_allow(code, language)
    if _sha(code) != h:       # defensive: str is immutable, but keep the invariant explicit
        raise GuardBlocked({"verdict": "block", "reason": "code changed after scan"}, h)
    compiled = compile(code, "<guarded>", "exec")
    exec(compiled, globals_ if globals_ is not None else {"__name__": "__guarded__"}, locals_)   # noqa: S102 - executed only after an 'allow'
    return res


def guarded_run(command: Any, **kwargs) -> subprocess.CompletedProcess:
    """Scan then run a shell command string or argv list with subprocess."""
    text = command if isinstance(command, str) else " ".join(shlex.quote(str(c)) for c in command)
    require_allow(text, "bash")
    return subprocess.run(command, **kwargs)   # noqa: S603 - only reached after an 'allow'


def guarded_file(path: str, runner: Optional[Callable[[str], Any]] = None) -> dict:
    """Read a script once, scan those bytes, then execute those same bytes (python only)."""
    with open(path, "rb") as f:
        raw = f.read()
    code = raw.decode("utf-8", "replace")
    res = require_allow(code)
    if runner is not None:
        runner(code)
    else:
        exec(compile(code, path, "exec"), {"__name__": "__main__"})   # noqa: S102
    return res


def guarded(fn: Optional[Callable] = None, *, arg: Any = 0, language: Optional[str] = None, on_block: str = "raise"):
    """Decorator: scan the code/command passed to `fn` (positional index or keyword name) before calling it.

        @guarded
        def run_agent_step(code: str): exec(code)

        @guarded(arg="cmd", language="bash", on_block="return")
        def run_cmd(cmd): ...
    """
    def deco(func: Callable):
        sig = inspect.signature(func)

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if isinstance(arg, int):
                code = args[arg] if len(args) > arg else None
                if code is None and kwargs:
                    names = list(sig.parameters)
                    if arg < len(names):
                        code = kwargs.get(names[arg])
            else:
                code = kwargs.get(arg)
                if code is None and arg in sig.parameters:
                    try:
                        code = sig.bind_partial(*args, **kwargs).arguments.get(arg)
                    except TypeError:
                        code = None
            if code is None:
                raise GuardBlocked({"verdict": "block", "reason": "no code argument found to scan; blocked as a precaution", "categories": [],
                                    "risk_score": 1.0, "code_language": "unknown", "vulnerable_lines": []})
            t0 = time.perf_counter()
            res = check(code if isinstance(code, str) else str(code), language)
            wrapper.last_result = res
            wrapper.last_latency_ms = (time.perf_counter() - t0) * 1000.0
            if res.get("verdict") != "allow":
                if on_block == "return":
                    return res
                raise GuardBlocked(res, _sha(code if isinstance(code, str) else str(code)))
            return func(*args, **kwargs)
        wrapper.last_result = None
        wrapper.last_latency_ms = 0.0
        return wrapper
    return deco(fn) if callable(fn) else deco
