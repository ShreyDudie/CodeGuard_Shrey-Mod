"""Run every hand-written fixture and report mismatches.   python tests/run_cases.py [filter] [-v]"""
import importlib
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.stdout.reconfigure(encoding="utf-8")

from codeguard import pipeline  # noqa: E402

MODULES = ["cases_benign", "cases_patterns", "cases_semantic", "cases_blind_fixes", "cases_polyglot", "cases_multilang"]


def load():
    out = []
    for m in MODULES:
        try:
            mod = importlib.import_module(m)
        except ModuleNotFoundError:
            continue
        for name in dir(mod):
            v = getattr(mod, name)
            if isinstance(v, list) and name.isupper():
                out.extend(v)
    return out


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    verbose = "-v" in sys.argv
    use_models = "--no-models" not in sys.argv
    flt = args[0] if args else ""
    pipeline.warmup()
    cases = load()
    bad = 0
    total = 0
    fp = fn = catmiss = 0
    lat = []
    for cid, cats, code, lang in cases:
        if flt and flt not in cid:
            continue
        total += 1
        t0 = time.perf_counter()
        r = pipeline.scan(code, use_models=use_models)
        lat.append((time.perf_counter() - t0) * 1000)
        exp = set() if cats == "benign" else {c.strip() for c in cats.split(",")}
        got = set(r["categories"])
        verdict_ok = (r["verdict"] == "block") == bool(exp)
        cats_ok = got == exp
        lang_ok = r["code_language"] == lang
        if not verdict_ok or not cats_ok or not lang_ok:
            bad += 1
            if not verdict_ok:
                if exp:
                    fn += 1
                else:
                    fp += 1
            elif not cats_ok:
                catmiss += 1
            print(f"MISMATCH {cid}: expected {sorted(exp) or 'benign'} / {lang}  got {r['verdict']} {sorted(got)} / {r['code_language']} risk={r['risk_score']}")
            if verbose:
                print("    reason:", r["reason"][:300])
        elif verbose:
            print(f"ok {cid}")
    lat.sort()
    print(f"\n{total - bad}/{total} ok   FP={fp} FN={fn} category-only={catmiss}   p50={lat[len(lat)//2]:.1f}ms p95={lat[int(.95*(len(lat)-1))]:.1f}ms")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
