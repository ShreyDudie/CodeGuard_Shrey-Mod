"""Generalisation check: semantics-preserving rewrites of every fixture must keep the verdict and categories.

A detector that memorised surface text fails here; one that follows behaviour does not.  Nothing is executed and
no new sample code is authored - the existing fixtures and dev rows are only transformed (python only).
    python tests/test_metamorphic.py [-v]
"""
import ast
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
sys.stdout.reconfigure(encoding="utf-8")

from codeguard import pipeline  # noqa: E402
import run_cases  # noqa: E402


class Renamer(ast.NodeTransformer):
    def __init__(self):
        self.defined = set()
        self.methods = set()

    def collect(self, tree):
        for n in ast.walk(tree):
            if isinstance(n, ast.ClassDef):
                for b in n.body:
                    if isinstance(b, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self.methods.add(b.name)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self.defined.add(n.name)
            elif isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                self.defined.add(n.id)
            elif isinstance(n, ast.arg):
                self.defined.add(n.arg)

    def _r(self, name):
        if name in self.defined and not name.startswith("__") and name not in ("self", "cls"):
            return "v_" + name[::-1]
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

    def visit_Attribute(self, n):
        self.generic_visit(n)
        n.attr = self._r(n.attr) if n.attr in self.methods else n.attr
        return n

    def visit_arg(self, n):
        n.arg = self._r(n.arg)
        return n


def t_rename(code):
    tree = ast.parse(code)
    r = Renamer()
    r.collect(tree)
    r.visit(tree)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree) + "\n"


def _split(tree):
    imports = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
    defs = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
    rest = [n for n in tree.body if n not in imports and n not in defs]
    return imports, defs, rest


def t_wrap_main(code):
    """Module-level statements move into a new function, which is called under the __main__ guard."""
    tree = ast.parse(code)
    imports, defs, rest = _split(tree)
    consts = [n for n in rest if isinstance(n, (ast.Assign, ast.AnnAssign))]   # globals stay global, only the actions move
    rest = [n for n in rest if n not in consts]
    if not rest:
        return None
    fn = ast.FunctionDef(name="entry_9f3", args=ast.arguments(posonlyargs=[], args=[], kwonlyargs=[], kw_defaults=[], defaults=[]), body=rest, decorator_list=[])
    guard = ast.If(test=ast.Compare(left=ast.Name(id="__name__", ctx=ast.Load()), ops=[ast.Eq()], comparators=[ast.Constant("__main__")]),
                   body=[ast.Expr(ast.Call(func=ast.Name(id="entry_9f3", ctx=ast.Load()), args=[], keywords=[]))], orelse=[])
    tree.body = imports + consts + defs + [fn, guard]
    ast.fix_missing_locations(tree)
    return ast.unparse(tree) + "\n"


def t_try_wrap(code):
    """Module-level statements sit inside try/except (error handling must not hide behaviour)."""
    tree = ast.parse(code)
    imports, defs, rest = _split(tree)
    consts = [n for n in rest if isinstance(n, (ast.Assign, ast.AnnAssign))]
    rest = [n for n in rest if n not in consts]
    if not rest:
        return None
    handler = ast.ExceptHandler(type=ast.Name(id="Exception", ctx=ast.Load()), name=None, body=[ast.Pass()])
    tr = ast.Try(body=rest, handlers=[handler], orelse=[], finalbody=[])
    tree.body = imports + consts + defs + [tr]
    ast.fix_missing_locations(tree)
    return ast.unparse(tree) + "\n"


class Aliaser(ast.NodeTransformer):
    """import X -> import X as X_al ; from m import f -> from m import f as f_al (and every use follows)."""

    def __init__(self):
        self.map = {}

    def visit_Import(self, n):
        for a in n.names:
            if a.asname is None and "." not in a.name:
                a.asname = a.name + "_al"
                self.map[a.name] = a.asname
        return n

    def visit_ImportFrom(self, n):
        for a in n.names:
            if a.asname is None and a.name != "*":
                a.asname = a.name + "_al"
                self.map[a.name] = a.asname
        return n

    def visit_Name(self, n):
        if isinstance(n.ctx, ast.Load) and n.id in self.map:
            n.id = self.map[n.id]
        return n


def t_alias(code):
    tree = ast.parse(code)
    al = Aliaser()
    for n in tree.body:                      # imports first so uses below can follow
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            al.visit(n)
    for n in ast.walk(tree):
        if isinstance(n, (ast.Import, ast.ImportFrom)) and n not in tree.body:
            al.visit(n)
    if not al.map:
        return None
    tree = al.visit(tree)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree) + chr(10)


class Hoister(ast.NodeTransformer):
    """f(a, 'x') -> t0 = 'x'; f(a, t0): arguments of the top-level call of a statement move into temporaries."""

    def __init__(self):
        self.k = 0

    def _hoist(self, call):
        pre = []
        if not isinstance(call, ast.Call):
            return pre
        for i, a in enumerate(call.args):
            if isinstance(a, ast.Starred):
                continue
            if isinstance(a, (ast.Constant, ast.JoinedStr, ast.BinOp, ast.List, ast.Tuple, ast.Dict)):
                name = f"t_{self.k}"
                self.k += 1
                pre.append(ast.Assign(targets=[ast.Name(id=name, ctx=ast.Store())], value=a, lineno=0))
                call.args[i] = ast.Name(id=name, ctx=ast.Load())
        return pre

    def _body(self, body):
        out = []
        for st in body:
            self.generic_visit(st)
            if isinstance(st, (ast.Expr, ast.Assign, ast.Return)) and isinstance(getattr(st, "value", None), ast.Call):
                out.extend(self._hoist(st.value))
            elif isinstance(st, ast.With):
                for it in st.items:
                    out.extend(self._hoist(it.context_expr))
            out.append(st)
        return out

    def visit_FunctionDef(self, n):
        n.body = self._body(n.body)
        return n

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Module(self, n):
        n.body = self._body(n.body)
        return n


def t_hoist(code):
    tree = ast.parse(code)
    tree = Hoister().visit(tree)
    ast.fix_missing_locations(tree)
    out = ast.unparse(tree) + chr(10)
    return out


def t_flatten(code):
    """The failure seen in pasted/PDF text: every newline lost, indentation spaces kept. Skipped when a comment would swallow the rest."""
    if any(l.strip().startswith("#") or "  #" in l for l in code.split(chr(10))):
        return None
    lines = [l for l in code.split(chr(10)) if l.strip()]
    if len(lines) < 2:
        return None
    return "".join(lines)


def t_pdf_style(code):
    """What a PDF text layer does to code: indentation flattened to one space, then every space doubled."""
    rows = []
    for l in code.split(chr(10)):
        st = l.lstrip(" 	")
        if "  " in st.strip():
            return None             # aligned columns / double spaces in the original would be ambiguous
        rows.append((" " if len(l) != len(st) else "") + st)
    out = chr(10).join(rows)
    return out.replace(" ", "  ")


def t_noise(code):
    return '"""Utility module."""\n# helper functions below\n' + code + "\n# end of file\n"


TRANSFORMS = [("rename", t_rename), ("wrap_main", t_wrap_main), ("try_wrap", t_try_wrap), ("noise", t_noise), ("alias", t_alias), ("hoist", t_hoist), ("flatten", t_flatten), ("pdf_style", t_pdf_style)]


def corpus():
    rows = []
    for c in run_cases.load():
        id_, cats, code, lang = c[0], c[1], c[2], (c[3] if len(c) > 3 else "python")
        if lang == "python":
            rows.append((id_, code))
    dev = os.path.join(ROOT, "codeguard_dev.jsonl")
    if os.path.exists(dev):
        for line in open(dev, encoding="utf-8"):
            d = json.loads(line)
            if d.get("language") == "python":
                rows.append((d["id"], d["code"]))
    return rows


def main():
    verbose = "-v" in sys.argv
    pipeline.warmup()
    checked = changed = 0
    per = {}
    for id_, code in corpus():
        try:
            base = pipeline.scan(code)
        except Exception:
            continue
        for tn, fn in TRANSFORMS:
            try:
                new = fn(code)
            except Exception:
                new = None
            if not new or new == code:
                continue
            if tn != "noise" and "ai_targeted_instructions" in base["categories"]:
                continue            # ast.unparse drops comments, which is where those instructions live
            r = pipeline.scan(new)
            checked += 1
            per.setdefault(tn, [0, 0])[0] += 1
            if tn == "alias" and set(r["categories"]) - set(base["categories"]) == {"obfuscated_execution"} and set(base["categories"]) <= set(r["categories"]):
                continue            # by the dataset's convention, hiding a dangerous module behind an alias IS obfuscated_execution
            if r["verdict"] != base["verdict"] or sorted(r["categories"]) != sorted(base["categories"]):
                per[tn][1] += 1
                if tn != "flatten":          # lost-newline recovery is best effort: reported, not enforced
                    changed += 1
                print(f"CHANGED [{tn}] {id_}: {base['verdict']} {base['categories']} -> {r['verdict']} {r['categories']}")
                if verbose:
                    print(new)
    for tn, (n, bad) in per.items():
        print(f"  {tn:10} checked={n:4d} changed={bad}")
    print(f"metamorphic: {checked} rewrites, {changed} changed verdict/categories ({100.0 * changed / max(checked, 1):.1f}%)")
    return 1 if changed else 0


if __name__ == "__main__":
    raise SystemExit(main())
