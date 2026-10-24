import sys, json
sys.stdout.reconfigure(encoding='utf-8')
from codeguard.ctx import Ctx
from codeguard import pyfe, textscan

def show(ctx):
    for e in ctx.events:
        ex = {k: v for k, v in e.extra.items() if k in ("witness", "score", "conf")}
        print(f"  L{e.line:<3} {e.cap:<12} {e.name:<22.22} t={str(e.target)!r:.48} tl={sorted(e.tlabels)} pl={sorted(e.plabels)} fl={sorted(e.flags)} host={e.hostc} pc={sorted(e.pathc)} x{e.mult} {ex or ''}")
    if ctx.notes: print("  NOTES", ctx.notes)

def py(text, label=""):
    ctx = Ctx()
    ok = pyfe.analyze_python_text(text, ctx)
    textscan.finalize_texts(ctx)
    print(label or repr(text)[:60], "parsed=", ok); show(ctx); print()
    return ctx

if __name__ == "__main__":
    ids = sys.argv[1:]
    rows=[json.loads(l) for l in open('data/dev.jsonl',encoding='utf-8') if l.strip()]
    for r in rows:
        if r['language']!='python': continue
        if ids and not any(i in r['id'] for i in ids): continue
        py(r['code'], f"== {r['id']} [{r['category']}] {r['label']}")
