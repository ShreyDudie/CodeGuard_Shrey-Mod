"""Shared AST helpers."""
import ast


def walk_all(tree: ast.AST) -> list:
    """All nodes of a tree, computed once and cached on the tree (several analysis passes walk the same tree)."""
    cached = getattr(tree, "_cg_nodes", None)
    if cached is None:
        cached = list(ast.walk(tree))
        try:
            tree._cg_nodes = cached
        except AttributeError:
            pass
    return cached
