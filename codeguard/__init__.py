"""CodeGuard: a real-time pre-execution safety layer for LLM-generated code."""
from .pipeline import analyze, scan  # noqa: F401
from .fusion import CATEGORIES  # noqa: F401

__version__ = "1.0.0"


def scan_many(snippets, verbose: bool = False) -> list:
    """Batch helper: list of code strings (or {"code": ...} dicts) -> list of results, same order."""
    out = []
    for s in snippets:
        code = s.get("code") if isinstance(s, dict) else s
        out.append(scan(code, verbose=verbose))
    return out
