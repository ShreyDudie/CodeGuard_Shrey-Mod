"""The UI's interception proof (codeguard/demo_gate.py) must report exactly what demo/intercept_check.py proves.   python tests/test_demo_gate.py"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from codeguard.demo_gate import run_interception_demo  # noqa: E402


def main():
    r = run_interception_demo()
    safe, unsafe, deco = r["steps"]
    assert r["pass"], r
    assert safe["gate"] == "allowed" and safe["executed"] and safe["marker"]["exists"], safe
    assert unsafe["gate"] == "blocked" and not unsafe["executed"] and not unsafe["marker"]["exists"], unsafe
    assert deco["gate"] == "blocked" and deco["body_entered"] == 0 and not deco["marker"]["exists"], deco
    assert r["marker_dir_before"] == [] and r["marker_dir_after"] == ["ALLOWED.marker"], r
    print("demo gate ok:", r["summary"])


if __name__ == "__main__":
    main()
