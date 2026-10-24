"""CLI:  python -m codeguard scan <file|->   |   serve [--port 8000]   |   eval <jsonl>"""
from __future__ import annotations

import argparse
import json
import os
import sys


def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    ap = argparse.ArgumentParser(prog="codeguard")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sc = sub.add_parser("scan", help="scan a file (or - for stdin)")
    sc.add_argument("path")
    sc.add_argument("--explain", action="store_true", help="include the detailed explanation")
    bt = sub.add_parser("batch", help="scan a file of snippets (.jsonl/.json/.csv, a code file, or a folder) and write results")
    bt.add_argument("path", help="input file or folder")
    bt.add_argument("-o", "--output", help="output file (default: <input>_results.jsonl)")
    bt.add_argument("--array", action="store_true", help="write one JSON array instead of JSON Lines")
    bt.add_argument("--keep-id", action="store_true", help="copy the input id (if any) into each result")
    bt.add_argument("--explain", action="store_true", help="add the detailed explanation to each result")
    sv = sub.add_parser("serve", help="run the HTTP service")
    sv.add_argument("--host", default=os.environ.get("HOST", "0.0.0.0"))
    sv.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    sv.add_argument("--workers", type=int, default=int(os.environ.get("WORKERS", "1")))
    ev = sub.add_parser("eval", help="evaluate on a labelled jsonl file")
    ev.add_argument("path")
    ev.add_argument("--no-models", action="store_true")
    args = ap.parse_args(argv)
    if args.cmd == "scan":
        from . import scan
        code = sys.stdin.read() if args.path == "-" else open(args.path, encoding="utf-8", errors="replace").read()
        res = scan(code, verbose=args.explain)
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0 if res["verdict"] == "allow" else 2
    if args.cmd == "batch":
        from .batchfile import run
        return run(args.path, args.output, args.array, args.keep_id, args.explain)
    if args.cmd == "serve":
        import socket
        import uvicorn
        shown = "localhost" if args.host in ("0.0.0.0", "::") else args.host
        probe = socket.socket()
        try:
            probe.bind((args.host, args.port))
        except OSError as e:
            print(f"Port {args.port} is not available ({e}). Try:  python -m codeguard serve --port {args.port + 1}", flush=True)
            return 1
        finally:
            probe.close()
        print("CodeGuard is starting (loading rules and model, a few seconds) ...", flush=True)
        print(f"  UI      : http://{shown}:{args.port}", flush=True)
        print(f"  API     : POST http://{shown}:{args.port}/scan   {{\"code\": \"...\"}}", flush=True)
        print("  Stop    : press Ctrl+C.  This window stays busy while the server runs - that is normal.", flush=True)
        uvicorn.run("codeguard.api:app", host=args.host, port=args.port, workers=args.workers, log_level="info")
        return 0
    if args.cmd == "eval":
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from eval import run_eval
        sys.argv = ["run_eval", args.path] + (["--no-models"] if args.no_models else [])
        run_eval.main()
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
