"""False-positive check on real benign code: scan standard-library modules (read only, never executed)."""
import sys, glob, os, time, sysconfig, random, collections
sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from codeguard import pipeline

def corpus(n=400, seed=1):
    std = sysconfig.get_paths()["stdlib"]
    files = glob.glob(std + "/*.py") + glob.glob(std + "/*/*.py")
    files = [f for f in files if "test" not in f.lower() and os.path.getsize(f) < 120000]
    random.Random(seed).shuffle(files)
    return files[:n]

if __name__ == "__main__":
    use_models = "--models" in sys.argv
    files = corpus()
    rules = collections.Counter(); blocked = 0; t = []
    for f in files:
        code = open(f, encoding="utf-8", errors="replace").read()
        t0 = time.perf_counter(); a = pipeline.analyze(code, use_models=use_models); t.append((time.perf_counter() - t0) * 1000)
        if a.verdict == "block":
            blocked += 1
            for c in a.categories:
                for fd in a.fused["groups"].get(c, [])[:2]:
                    rules[fd.rule] += 1
    t.sort()
    print(f"{len(files)} files, blocked {blocked} ({100*blocked/len(files):.1f}%), p50 {t[len(t)//2]:.0f}ms p95 {t[int(.95*len(t))]:.0f}ms max {t[-1]:.0f}ms")
    for r, c in rules.most_common(25): print(f"  {c:3d} {r}")
