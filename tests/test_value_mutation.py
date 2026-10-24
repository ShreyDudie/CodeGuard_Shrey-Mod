"""Brittleness audit: swap a literal for another literal of the SAME KIND and check that the verdict and categories survive.

If a rule fires for '/tmp/bin' but not for '/tmp', or for 127.0.0.1 but not for localhost, it memorised a string instead of a concept.
Only existing positive cases are transformed (no new attack code is written); nothing is executed.
    python tests/test_value_mutation.py [-v]
"""
import json
import os
import re
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
sys.stdout.reconfigure(encoding="utf-8")

from codeguard import pipeline  # noqa: E402
import run_cases  # noqa: E402

# kind -> interchangeable literals (each list holds values of one semantic class)
CLASSES = {
    "loopback host": ["127.0.0.1", "localhost", "127.0.0.2", "0.0.0.0", "[::1]"],
    "private host": ["10.0.0.5", "172.16.4.9", "192.168.1.20", "10.1.2.3", "192.168.100.100"],
    "metadata host": ["169.254.169.254", "metadata.google.internal", "169.254.170.2"],
    "credential file": ["~/.aws/credentials", "/home/user/.ssh/id_rsa", "/home/user/.docker/config.json", "~/.kube/config", "~/.netrc", "~/.git-credentials", "~/.pgpass"],
    "account file": ["/etc/shadow", "/etc/passwd", "/etc/sudoers"],
    "data directory": ["/var/lib/mysql", "/srv/data", "/var/lib/postgresql", "/opt/app/db", "/home/app/data"],
    "secret env var": ["AWS_SECRET_ACCESS_KEY", "OPENAI_API_KEY", "GITHUB_TOKEN", "DB_PASSWORD", "STRIPE_SECRET_KEY", "SLACK_TOKEN"],
    "startup file": ["~/.bashrc", "~/.profile", "~/.zshrc", "/etc/profile"],
    "outside host": ["c2.example.com", "attacker.example", "collector.invalid", "telemetry.example.net"],
    "loop count": ["500", "1000", "5000", "100000"],
}
# calls that do the same thing for the purposes of every category (a different verb, a sibling function)
API_SWAPS = [("requests.post(", "requests.put("), ("requests.post(", "requests.patch("), ("requests.get(", "requests.head("), ("requests.get(", "requests.post("),
             ("subprocess.run(", "subprocess.call("), ("subprocess.run(", "subprocess.check_call("), ("subprocess.run(", "subprocess.Popen("),
             ("subprocess.run(", "subprocess.check_output("), (".sendall(", ".send("), ("os.system(", "os.popen("),
             ("shutil.rmtree(", "shutil.rmtree(ignore_errors=False, path=")]


def typos(name: str) -> list:
    base = re.sub(r"[^a-z]", "", name)
    out = []
    if len(base) > 5:
        out.append(name.replace(base[2:4], base[3] + base[2], 1))            # swap two letters
        out.append(name.replace(base[3], "", 1))                              # drop a letter
        out.append(name.replace(base[2], base[2] * 2, 1))                     # double a letter
    return [t for t in dict.fromkeys(out) if t != name]


def positives():
    rows = []
    for c in run_cases.load():
        if (c[3] if len(c) > 3 else "python") == "python" and c[1] not in ("benign", "", None):
            rows.append((c[0], c[2]))
    for f in ("user_test50.jsonl",):
        for l in open(os.path.join(HERE, "data", f), encoding="utf-8"):
            d = json.loads(l)
            if d["label"] == 1 and d["language"] == "python":
                rows.append((d["id"], d["code"]))
    for f in ("user_test50_v2.jsonl",):
        for l in open(os.path.join(HERE, "data", f), encoding="utf-8"):
            d = json.loads(l)
            if d["expected_output"]["verdict"] == "block" and d["language"] == "python":
                rows.append((d["id"], d["code"]))
    for f in ("blind_hidden25_code_only.json", "blind2_code_only.json"):
        exp = {}
        ef = f.replace("code_only", "expected")
        ef = "blind_hidden25_expected.json" if "hidden25" in f else "blind2_expected.json"
        for e in json.load(open(os.path.join(HERE, "data", ef), encoding="utf-8")):
            exp[e["id"]] = e["output"]
        for d in json.load(open(os.path.join(HERE, "data", f), encoding="utf-8")):
            if exp[d["id"]]["verdict"] == "block":
                rows.append((d["id"], d["code"]))
    for l in open(os.path.join(ROOT, "codeguard_dev.jsonl"), encoding="utf-8"):
        d = json.loads(l)
        if d["label"] == 1 and d["language"] == "python":
            rows.append((d["id"], d["code"]))
    seen, out = set(), []
    for i, c in rows:
        if c not in seen:
            seen.add(c)
            out.append((i, c))
    return out


def main():
    verbose = "-v" in sys.argv
    pipeline.warmup()
    stats = defaultdict(lambda: [0, 0])          # kind -> [tested, failed]
    fails = defaultdict(list)
    for id_, code in positives():
        base = pipeline.scan(code)
        if base["verdict"] != "block":
            continue
        variants = []
        for kind, vals in CLASSES.items():
            for v in vals:
                if v in code:
                    for w in vals:
                        if w != v and (kind != "loop count" or re.search(r"range\(\s*" + re.escape(v) + r"\s*\)", code)):
                            variants.append((kind, f"{v} -> {w}", code.replace(v, w)))
        for a, b in API_SWAPS:
            if a in code:
                variants.append(("equivalent API", f"{a} -> {b}", code.replace(a, b)))
        for kind, label, new in variants:
            r = pipeline.scan(new)
            ok = r["verdict"] == "block" and set(base["categories"]) <= set(r["categories"])
            stats[kind][0] += 1
            if not ok:
                stats[kind][1] += 1
                fails[kind].append((id_, label, r["verdict"], r["categories"], base["categories"]))
    tot = sum(v[0] for v in stats.values())
    bad = sum(v[1] for v in stats.values())
    print(f"{'kind':18} {'variants':>9} {'lost':>6} {'retention':>10}")
    for k, (n, f) in sorted(stats.items(), key=lambda kv: -kv[1][1] / max(kv[1][0], 1)):
        print(f"{k:18} {n:9d} {f:6d} {100 * (n - f) / max(n, 1):9.1f}%")
    print(f"{'TOTAL':18} {tot:9d} {bad:6d} {100 * (tot - bad) / max(tot, 1):9.1f}%")
    for k, items in fails.items():
        print(f"\n-- {k}: {len(items)} lost")
        for it in items[: (50 if verbose else 6)]:
            print("   ", *it)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
