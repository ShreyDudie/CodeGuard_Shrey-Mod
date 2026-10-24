"""Frozen-baseline benchmark: run every labelled suite, report precision/recall per suite and category, save the outputs,
and later compare a changed system against the saved baseline.

    python eval/benchmark.py                    # run + print metrics
    python eval/benchmark.py --save reports/baseline_v1     # freeze: outputs.jsonl, metrics.json, MANIFEST.json
    python eval/benchmark.py --compare reports/baseline_v1  # list every case whose verdict/categories/language/lines changed
    python eval/benchmark.py --rules            # which rules fire on how many distinct cases (generalisation check)

Suites: dev (the 42 provided rows), sem32 (the 32-case semantic benchmark; labels are our reading of the dataset's conventions,
not organiser labels), fixtures (our own positive cases + benign look-alikes).
"""
import argparse
import glob
import hashlib
import json
import os
import sys
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
sys.stdout.reconfigure(encoding="utf-8")

from codeguard import pipeline  # noqa: E402

CATS = ["secret_access", "data_exfiltration", "destructive_command", "persistence_or_privesc", "obfuscated_execution", "dependency_risk",
        "resource_exhaustion", "ssrf_network_exfil", "ai_targeted_instructions"]


def load_suites() -> dict:
    suites = {}
    dev = []
    dev_path = os.path.join(ROOT, "codeguard_dev.jsonl")           # the organiser's sample; kept out of git (see README "Test data")
    for line in (open(dev_path, encoding="utf-8") if os.path.exists(dev_path) else []):
        d = json.loads(line)
        cats = sorted(c.strip() for c in d["category"].split(",")) if d["label"] == 1 else []
        dev.append({"id": d["id"], "code": d["code"], "label": d["label"], "cats": cats, "language": d["language"]})
    suites["dev"] = dev
    sem = []
    p = os.path.join(ROOT, "tests", "data", "sem32.jsonl")
    if os.path.exists(p):
        for line in open(p, encoding="utf-8"):
            d = json.loads(line)
            sem.append({"id": d["id"], "code": d["code"], "label": d["label"], "cats": [d["category"]] if d["label"] else [], "language": d["language"]})
    suites["sem32"] = sem
    u50 = []
    p50 = os.path.join(ROOT, "tests", "data", "user_test50.jsonl")
    if os.path.exists(p50):
        for line in open(p50, encoding="utf-8"):
            if line.strip():
                d = json.loads(line)
                u50.append({"id": d["id"], "code": d["code"], "label": d["label"], "cats": [d["category"]] if d["label"] else [], "language": d["language"]})
    suites["user50"] = u50
    v2 = []
    p2 = os.path.join(ROOT, "tests", "data", "user_test50_v2.jsonl")
    if os.path.exists(p2):
        for line in open(p2, encoding="utf-8"):
            if line.strip():
                d = json.loads(line)
                e = d["expected_output"]
                v2.append({"id": d["id"], "code": d["code"], "label": 1 if e["verdict"] == "block" else 0, "cats": sorted(e["categories"]), "language": e["code_language"]})
    suites["user50_v2"] = v2
    for name, cf, ef in (("blind1", "blind_hidden25_code_only.json", "blind_hidden25_expected.json"), ("blind2", "blind2_code_only.json", "blind2_expected.json"), ("blind3", "blind3_code_only.json", "blind3_expected.json"), ("blind4", "blind4_code_only.json", "blind4_expected.json"), ("blind5", "blind5_code_only.json", "blind5_expected.json"), ("blind6", "blind6_code_only.json", "blind6_expected.json")):
        pc, pe = os.path.join(ROOT, "tests", "data", cf), os.path.join(ROOT, "tests", "data", ef)
        rows_b = []
        if os.path.exists(pc) and os.path.exists(pe):
            exp = {d["id"]: d["output"] for d in json.load(open(pe, encoding="utf-8"))}
            for d in json.load(open(pc, encoding="utf-8")):
                e = exp[d["id"]]
                rows_b.append({"id": d["id"], "code": d["code"], "label": 1 if e["verdict"] == "block" else 0, "cats": sorted(e["categories"]), "language": e["code_language"]})
        suites[name] = rows_b
    import run_cases
    fx = []
    for c in run_cases.load():
        id_, cats, code = c[0], c[1], c[2]
        lang = c[3] if len(c) > 3 else "python"
        want = [] if cats in ("benign", "", None) else sorted(x.strip() for x in str(cats).split(","))
        fx.append({"id": id_, "code": code, "label": 1 if want else 0, "cats": want, "language": lang})
    suites["fixtures"] = fx
    return suites


def run(suites: dict, use_models: bool = True) -> list:
    pipeline.warmup()
    out = []
    for name, rows in suites.items():
        for row in rows:
            a = pipeline.analyze(row["code"], use_models=use_models)
            r = pipeline.result_dict(a)
            rules = sorted({f.rule for f in a.findings if f.category in r["categories"]})
            out.append({"suite": name, "id": row["id"], "label": row["label"], "want_cats": row["cats"], "want_language": row["language"],
                        "verdict": r["verdict"], "risk_score": r["risk_score"], "categories": r["categories"], "code_language": r["code_language"],
                        "vulnerable_lines": r["vulnerable_lines"], "rules": rules})
    return out


def metrics(results: list) -> dict:
    m = {}
    for suite in sorted({r["suite"] for r in results}):
        rs = [r for r in results if r["suite"] == suite]
        tp = sum(1 for r in rs if r["label"] == 1 and r["verdict"] == "block")
        fp = sum(1 for r in rs if r["label"] == 0 and r["verdict"] == "block")
        fn = sum(1 for r in rs if r["label"] == 1 and r["verdict"] == "allow")
        tn = sum(1 for r in rs if r["label"] == 0 and r["verdict"] == "allow")
        per = {}
        for c in CATS:
            ctp = sum(1 for r in rs if c in r["want_cats"] and c in r["categories"])
            cfp = sum(1 for r in rs if c not in r["want_cats"] and c in r["categories"])
            cfn = sum(1 for r in rs if c in r["want_cats"] and c not in r["categories"])
            if ctp + cfp + cfn:
                per[c] = {"tp": ctp, "fp": cfp, "fn": cfn, "precision": round(ctp / (ctp + cfp), 3) if ctp + cfp else None, "recall": round(ctp / (ctp + cfn), 3) if ctp + cfn else None}
        m[suite] = {
            "n": len(rs), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(tp / (tp + fp), 3) if tp + fp else None, "recall": round(tp / (tp + fn), 3) if tp + fn else None,
            "false_positive_rate": round(fp / (fp + tn), 3) if fp + tn else None,
            "category_exact": round(sum(1 for r in rs if sorted(r["categories"]) == r["want_cats"]) / len(rs), 3),
            "language_acc": round(sum(1 for r in rs if r["code_language"] == r["want_language"]) / len(rs), 3),
            "per_category": per,
        }
    return m


def manifest() -> dict:
    h = hashlib.sha256()
    files = sorted(glob.glob(os.path.join(ROOT, "rules", "*")) + glob.glob(os.path.join(ROOT, "codeguard", "*.py")) + glob.glob(os.path.join(ROOT, "codeguard", "ml", "*.py")))
    for f in files:
        h.update(os.path.basename(f).encode())
        h.update(open(f, "rb").read())
    return {"source_hash": h.hexdigest()[:16], "files": len(files)}


def print_metrics(m: dict) -> None:
    for suite, d in m.items():
        print(f"[{suite}] n={d['n']}  precision={d['precision']}  recall={d['recall']}  FP={d['fp']} FN={d['fn']}  FPR={d['false_positive_rate']}  "
              f"category-exact={d['category_exact']}  language={d['language_acc']}")
        for c, v in d["per_category"].items():
            print(f"    {c:26} tp={v['tp']:<3} fp={v['fp']:<3} fn={v['fn']:<3} precision={v['precision']} recall={v['recall']}")


def compare(base_dir: str, results: list) -> int:
    old = {(r["suite"], r["id"]): r for r in map(json.loads, open(os.path.join(base_dir, "outputs.jsonl"), encoding="utf-8"))}
    changed = 0
    new_ids = 0
    for r in results:
        o = old.get((r["suite"], r["id"]))
        if o is None:
            new_ids += 1
            continue
        diffs = [k for k in ("verdict", "categories", "code_language", "vulnerable_lines") if o[k] != r[k]]
        if diffs:
            changed += 1
            print(f"CHANGED {r['suite']}/{r['id']}: " + "; ".join(f"{k} {o[k]} -> {r[k]}" for k in diffs))
    print(f"compare: {len(results)} cases, {changed} changed vs baseline, {new_ids} new (not in baseline)")
    return changed


def rule_report(results: list) -> None:
    by_rule = defaultdict(set)
    for r in results:
        for ru in r["rules"]:
            by_rule[ru].add((r["suite"], r["id"]))
    rows = sorted(by_rule.items(), key=lambda kv: len(kv[1]))
    single = [k for k, v in rows if len(v) == 1]
    print(f"{len(rows)} rules fired on at least one case; {len(single)} fired on exactly one case (not yet shown to generalise):")
    for k, v in rows:
        suites = Counter(s for s, _ in v)
        print(f"  {len(v):3d} cases  {k:42} {dict(suites)}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--save")
    ap.add_argument("--compare")
    ap.add_argument("--rules", action="store_true")
    ap.add_argument("--no-models", action="store_true")
    a = ap.parse_args()
    results = run(load_suites(), use_models=not a.no_models)
    m = metrics(results)
    print_metrics(m)
    if a.save:
        os.makedirs(a.save, exist_ok=True)
        with open(os.path.join(a.save, "outputs.jsonl"), "w", encoding="utf-8") as f:
            for r in results:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        json.dump(m, open(os.path.join(a.save, "metrics.json"), "w", encoding="utf-8"), indent=1)
        json.dump(manifest(), open(os.path.join(a.save, "MANIFEST.json"), "w", encoding="utf-8"), indent=1)
        print(f"baseline saved to {a.save} ({len(results)} cases)")
    if a.rules:
        rule_report(results)
    if a.compare:
        return 1 if compare(a.compare, results) else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
