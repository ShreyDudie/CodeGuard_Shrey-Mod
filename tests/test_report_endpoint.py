"""GET /report (the UI's Results tab) must serve the dev-sample metrics, the efficiency note and live figures.   python tests/test_report_endpoint.py"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from codeguard import api  # noqa: E402


def main():
    d = api.report()
    if hasattr(d, "body"):
        d = json.loads(d.body)
    for k in ("dev", "efficiency", "optimisation", "generalisation", "live"):
        assert k in d, k
    m = d["dev"]["with_models"]
    assert 0 <= m["prec"] <= 1 and 0 <= m["rec"] <= 1 and m["fp"] >= 0
    assert d["efficiency"]["model_mb"] and d["efficiency"]["latency_ms_with_models"]["median"] > 0
    assert d["live"]["rules"] > 100 and d["live"]["model_mb"]
    print("report endpoint ok: precision %.2f recall %.2f, %d false positives, models %s MB" % (m["prec"], m["rec"], m["fp"], list(d["live"]["model_mb"].values())))


if __name__ == "__main__":
    main()
