"""Robustness: odd but harmless inputs must always yield a schema-valid result quickly."""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from codeguard import pipeline  # noqa: E402
from codeguard.fusion import CATEGORIES  # noqa: E402

KEYS = {"verdict", "risk_score", "categories", "code_language", "reason", "vulnerable_lines"}


def check(res):
    assert KEYS <= set(res), res
    assert res["verdict"] in ("allow", "block")
    assert 0.0 <= res["risk_score"] <= 1.0
    assert isinstance(res["categories"], list) and all(c in CATEGORIES for c in res["categories"])
    assert isinstance(res["code_language"], str) and res["code_language"]
    assert isinstance(res["reason"], str)
    assert all(isinstance(x, int) for x in res["vulnerable_lines"])
    if res["verdict"] == "block":
        assert res["categories"], res
    else:
        assert res["categories"] == []


INPUTS = [
    "", " ", "\n\n", None, 123, b"\x00\x01\x02binary", "\x00" * 50, "a" * 300_000, "(" * 5000, "{" * 5000, "[" * 3000,
    "def f(:\n  pass", "if True:\nprint(1)", "SELECT", "'unterminated", '"""unterminated', "echo \"unterminated", "$(", "`", "<!--",
    "​‌‍" * 20, "\r\n".join(["x = 1"] * 2000), "print('é漢字🙂')", "# only a comment", "x = " + "1+" * 3000 + "1",
    "for i in range(10**12):\n    pass\n", "while True:\n    pass\n"[:-1], "a = [" + ",".join(["1"] * 20000) + "]",
    "const x = " + "(" * 800 + "1" + ")" * 800, "if (a) " * 500, "name: x\nvalue: [1, 2\n", "```\nunclosed fence\n", "﻿print(1)",
]


def test_inputs():
    for inp in INPUTS:
        t0 = time.perf_counter()
        res = pipeline.scan(inp)
        dt = time.perf_counter() - t0
        check(res)
        assert dt < 3.0, (str(inp)[:40], dt)


def test_batch_shape():
    import codeguard
    out = codeguard.scan_many(["print(1)", {"code": "echo hi"}, ""])
    assert len(out) == 3
    for r in out:
        check(r)


if __name__ == "__main__":
    test_inputs()
    test_batch_shape()
    print("robustness ok")
