"""Semantics-preserving mutation check on the PROVIDED dev samples (python only): rename every user-defined
function / class / variable, add noise comments and a docstring, then confirm verdict and categories are unchanged.
Nothing is executed; no new sample code is authored - the dev rows are only transformed."""
import ast
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(encoding="utf-8")
from codeguard import pipeline  # noqa: E402


class Renamer(ast.NodeTransformer):
    def __init__(self):
        self.defined = set()

    def collect(self, tree):
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self.defined.add(n.name)
            elif isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                self.defined.add(n.id)
            elif isinstance(n, ast.arg):
                self.defined.add(n.arg)

    def _r(self, name):
        if name in self.defined and not name.startswith("__") and name not in ("self", "cls"):
            return "z_" + name[::-1]
        return name

    def visit_FunctionDef(self, n):
        n.name = self._r(n.name)
        self.generic_visit(n)
        return n

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, n):
        n.name = self._r(n.name)
        self.generic_visit(n)
        return n

    def visit_Name(self, n):
        n.id = self._r(n.id)
        return n

    def visit_arg(self, n):
        n.arg = self._r(n.arg)
        return n


def mutate(code):
    tree = ast.parse(code)
    r = Renamer()
    r.collect(tree)
    r.visit(tree)
    ast.fix_missing_locations(tree)
    return '"""Utility module."""\n# helper functions below\n' + ast.unparse(tree) + "\n"


def main(path="data/dev.jsonl"):
    rows = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
    same = total = 0
    for r in rows:
        if r["language"] != "python":
            continue
        try:
            m = mutate(r["code"])
        except SyntaxError:
            continue
        a, b = pipeline.scan(r["code"]), pipeline.scan(m)
        total += 1
        if a["verdict"] == b["verdict"] and a["categories"] == b["categories"]:
            same += 1
        else:
            print("CHANGED", r["id"], a["verdict"], a["categories"], "->", b["verdict"], b["categories"])
    print(f"stable under rename+noise: {same}/{total}")


if __name__ == "__main__":
    main()
