"""A file of {"id": ..., "code": ..., "language": ...} objects must give one result per object, also when it went through a PDF (hard line wraps, 1-space indentation,
unescaped quotes inside a snippet).  A regression test for 'the upload only evaluated the first snippet'.   python tests/test_pdf_extract.py"""
import os
import sys
import textwrap

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from codeguard.pipeline import scan  # noqa: E402
from codeguard.snippets import extract_from_bytes, extract_snippets  # noqa: E402

WANT = {"2001": "block", "2002": "block", "2003": "block", "2004": "block", "2005": "block", "2006": "block", "2007": "block", "2008": "block", "2009": "block",
        "2010": "allow", "2011": "block", "2012": "block", "2013": "allow", "2014": "block", "2015": "block"}


def check(items, label):
    assert len(items) == 15, f"{label}: expected 15 snippets, got {len(items)}"
    for ident, code in items:
        got = scan(code)["verdict"]
        assert got == WANT[ident[-4:]], f"{label}: {ident} -> {got}, expected {WANT[ident[-4:]]}"


def main():
    path = os.path.join(ROOT, "tests", "data", "user_pdf15.jsonl")
    raw = open(path, "rb").read()
    check(extract_from_bytes(raw, "x.jsonl"), "plain file")
    for width in (70, 78, 86, 92):
        for keep in (True, False):
            lines = []
            for line in raw.decode("utf-8").split("\n"):
                lines.extend(textwrap.wrap(line, width=width, break_long_words=True, break_on_hyphens=False, drop_whitespace=not keep) or [""])
            check(extract_snippets("\n".join(lines), "x.pdf"), f"PDF-style wrap width {width} keep_whitespace={keep}")
    print("pdf extraction ok: 15 snippets, right verdicts, 9 layouts")


if __name__ == "__main__":
    main()
