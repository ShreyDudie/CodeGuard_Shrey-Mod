"""HTTP service: POST /scan, POST /batch, GET /health, GET /metrics, GET / (minimal UI).

The response of /scan is exactly the fixed schema:
  {"verdict": "allow|block", "risk_score": 0-1, "categories": [...], "code_language": "...", "reason": "...", "vulnerable_lines": [...]}
Requests are parsed tolerantly (JSON object, JSON string, raw text) and the endpoint never returns a non-schema body.
"""
from __future__ import annotations

import json
import os
import threading
import time
from collections import deque
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

from . import __version__, engine, pipeline

app = FastAPI(title="CodeGuard", version=__version__, docs_url="/docs", redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

_stats_lock = threading.Lock()
_lat: deque = deque(maxlen=2000)
_counts = {"scan": 0, "batch_items": 0, "block": 0, "allow": 0, "errors": 0}
_started = time.time()
_UI = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ui", "index.html")

_SAMPLES = ["import os\nos.system('echo hi')\n", "echo hello\n", "SELECT 1;\n", "const a = 1;\nconsole.log(a)\n", "# Title\n\nSome text.\n"]


@app.on_event("startup")
def _warm() -> None:
    try:
        pipeline.warmup()           # rules, models, package index: the first real request must not pay for any of them
    except Exception:
        pass
    for s in _SAMPLES:
        try:
            pipeline.scan(s)
        except Exception:
            pass


def _extract_code(body: Any) -> str:
    if isinstance(body, dict):
        for k in ("code", "snippet", "source", "text", "content", "input"):
            if k in body:
                v = body[k]
                return v if isinstance(v, str) else ("" if v is None else json.dumps(v))
        return ""
    if isinstance(body, str):
        return body
    if body is None:
        return ""
    return str(body)


async def _read_body(request: Request) -> Any:
    raw = await request.body()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        try:
            return raw.decode("utf-8", "replace")
        except Exception:
            return ""


def _scan_one(code: str, verbose: bool) -> dict:
    t0 = time.perf_counter()
    try:
        res = pipeline.scan(code, verbose=verbose)
    except Exception:
        with _stats_lock:
            _counts["errors"] += 1
        res = {"verdict": "block", "risk_score": 0.6, "categories": ["obfuscated_execution"], "code_language": "unknown",
               "reason": "The analyser failed, so the code is blocked as a precaution.", "vulnerable_lines": []}
    dt = (time.perf_counter() - t0) * 1000.0
    with _stats_lock:
        _lat.append(dt)
        _counts["scan"] += 1
        _counts[res.get("verdict", "block")] = _counts.get(res.get("verdict", "block"), 0) + 1
    return res


@app.post("/scan")
async def scan_endpoint(request: Request, verbose: int = 0):
    body = await _read_body(request)
    code = _extract_code(body)
    if isinstance(body, dict) and "verbose" in body:
        verbose = int(bool(body.get("verbose")))
    res = _scan_one(code, bool(verbose))
    return JSONResponse(res)


@app.post("/batch")
async def batch_endpoint(request: Request, verbose: int = 0):
    body = await _read_body(request)
    items: list = []
    if isinstance(body, str) and body.lstrip()[:1] in ("{", "["):
        from .snippets import extract_snippets
        body = [{"code": c} for _i, c in extract_snippets(body)]
    if isinstance(body, list):
        items = body
    elif isinstance(body, dict):
        for k in ("items", "snippets", "samples", "codes", "data", "batch", "inputs"):
            if isinstance(body.get(k), list):
                items = body[k]
                break
        else:
            items = [body]
    out = []
    for it in items:
        code = _extract_code(it)
        res = _scan_one(code, bool(verbose))
        if isinstance(it, dict) and it.get("id") is not None:
            res = {"id": it["id"], **res}
        out.append(res)
    with _stats_lock:
        _counts["batch_items"] += len(out)
    return JSONResponse(out)


@app.post("/batch_file")
async def batch_file_endpoint(request: Request, filename: str = ""):
    """UI helper: raw text of an uploaded file of snippets -> results (+ the code, for display).  Not part of the judged schema."""
    from .snippets import extract_from_bytes
    items = extract_from_bytes(await request.body(), filename)[:2000]
    results = []
    for i, (ident, code) in enumerate(items, start=1):
        res = _scan_one(code, True)
        results.append({"index": i, "id": ident, "code": code[:40000], **res})
    blocked = sum(1 for r in results if r["verdict"] == "block")
    return JSONResponse({"count": len(results), "blocked": blocked, "allowed": len(results) - blocked, "results": results})


@app.get("/health")
def health():
    return {"status": "ok", "version": __version__, "rules": len(engine.get_rules()), "uptime_s": round(time.time() - _started, 1)}


@app.get("/metrics")
def metrics():
    with _stats_lock:
        lat = sorted(_lat)
        pct = lambda p: round(lat[min(len(lat) - 1, int(p * (len(lat) - 1)))], 2) if lat else 0.0
        return {"counts": dict(_counts), "latency_ms": {"p50": pct(0.5), "p95": pct(0.95), "p99": pct(0.99), "n": len(lat)}}


@app.get("/report")
def report():
    """Evaluation results and the efficiency note for the UI: the dev-sample metrics (generated by eval/make_dev_results.py) plus live figures from this running service."""
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports", "ui_metrics.json")
    if not os.path.exists(path):
        return JSONResponse({"error": "reports/ui_metrics.json is missing: run python eval/make_dev_results.py"}, status_code=404)
    data = json.load(open(path, encoding="utf-8"))
    tpath = os.path.join(os.path.dirname(path), "test_report.json")
    if os.path.exists(tpath):
        data["test"] = json.load(open(tpath, encoding="utf-8"))          # held-out test set results, written by eval/make_test_report.py
    models_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
    live_sizes = {}
    for label, fn in (("Byte 5-gram naturalness model", "lm_py.npz"), ("Instruction-text classifier", "text_lr.npz")):
        fp = os.path.join(models_dir, fn)
        if os.path.exists(fp):
            live_sizes[label] = round(os.path.getsize(fp) / 1e6, 2)
    lat = sorted(_lat)
    pct = lambda p: round(lat[min(len(lat) - 1, int(p * (len(lat) - 1)))], 2) if lat else None
    data["live"] = {"rules": len(engine.get_rules()), "model_mb": live_sizes, "uptime_s": round(time.time() - _started, 1), "requests": dict(_counts),
                    "service_latency_ms": {"median": pct(0.5), "p95": pct(0.95), "p99": pct(0.99), "n": len(lat)}}
    return data


@app.post("/demo/intercept")
def demo_intercept():
    """The interception proof as data for the UI.  Runs only the fixed harmless demo pair (see codeguard/demo_gate.py); never executes request data."""
    from . import demo_gate
    if not demo_gate.enabled():
        return JSONResponse({"error": "the interception demo is disabled (CODEGUARD_DEMO=0)"}, status_code=404)
    return demo_gate.run_interception_demo()


@app.post("/admin/reload")
def reload_rules():
    return {"rules": engine.reload_rules()}


@app.get("/", response_class=HTMLResponse)
def ui():
    if os.path.exists(_UI):
        return FileResponse(_UI)
    return HTMLResponse("<h1>CodeGuard</h1><p>POST /scan {\"code\": \"...\"}</p>")
