"""Core data structures shared by every front-end: abstract values (V) and behaviour events (Event).

A front-end lowers source code into a list of Events.  Rules (rules/*.yaml) are matched over events.
Abstract values carry a (possibly partial) constant string "skeleton" plus provenance labels, so the
analysis can reason about *what flows where* instead of matching text.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

HOLE = "￼"          # marks an unknown piece inside a partially known string
EMPTY: frozenset = frozenset()


class _Unknown:
    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover
        return "UNK"

    def __bool__(self) -> bool:
        return False


UNK = _Unknown()

# ---- provenance labels -------------------------------------------------------------------------
USER = "USER"            # attacker/user controllable input (params, argv, request, input())
ENV = "ENV"              # value from process environment
ENV_DUMP = "ENV_DUMP"    # whole environment (sensitive)
SECRET = "SECRET"        # credential-like value
SENS_SYS = "SENS_SYS"    # sensitive system data (/etc/passwd ...)
FILE = "FILE"            # data read from a file
NET = "NET"              # data received from the network
DB = "DB"                # rows read from a database
DECODED = "DECODED"      # produced by a decoder (base64/hex/zlib/rot13...)
BUILT = "BUILT"          # string assembled from pieces (concat / join) - used for dynamic names
COMPILED = "COMPILED"    # code object produced by compile()
DYNCODE = "DYNCODE"      # source obtained dynamically (inspect.getsource, loaded module source)
CMDSUB = "CMDSUB"        # output of a command substitution
VALIDATED = "VALIDATED"  # passed a dominating validation guard
QUOTED = "QUOTED"        # passed through a quoting/escaping sanitizer
SAFE_NUM = "SAFE_NUM"    # cast to a number (injection-proof)
META = "META"            # cloud metadata response
TRAVERSAL = "TRAVERSAL"  # path built from a fixed base plus a caller-supplied part (join/concat does not confine it)
ARBITRARY_FILE = "ARBITRARY_FILE"  # data read from a file whose path the caller chose

SENSITIVE_LABELS = frozenset({SECRET, ENV_DUMP, SENS_SYS})


def U(*sets: Iterable[str]) -> frozenset:
    out: set = set()
    for s in sets:
        if s:
            out |= set(s)
    return frozenset(out) if out else EMPTY


@dataclass(eq=False)
class V:
    """Abstract value."""
    c: Any = UNK                    # concrete value; for str may be a skeleton containing HOLE
    labels: frozenset = EMPTY
    q: Optional[str] = None         # qualified name of module/function/class references
    cls: Optional[str] = None       # class (qualified or user) of an instance
    items: Any = None               # list[V] | dict[Any, V] for containers
    attrs: Optional[dict] = None    # attributes of user-class instances
    lines: frozenset = EMPTY        # source lines where this value was produced
    n: Optional[int] = None         # known length of an iterable
    fn: Any = None                  # user function / class descriptor / bound info
    kind: Optional[str] = None      # list|tuple|dict|set|str|bytes|num|func|class|module|file|obj
    alias: Optional[str] = None     # import alias used to reach this value
    meta: Optional[dict] = None     # free-form extras (file mode/path, thread target ...)
    src: frozenset = EMPTY          # human-readable origins of tainted data ("file ~/.aws/credentials" ...)

    # -- helpers -------------------------------------------------------------------------------
    def is_str(self) -> bool:
        return isinstance(self.c, str)

    def exact(self) -> Optional[str]:
        """Exact string value or None."""
        if isinstance(self.c, str) and HOLE not in self.c:
            return self.c
        return None

    def skel(self) -> Optional[str]:
        return self.c if isinstance(self.c, str) else None

    def has(self, *labs: str) -> bool:
        return any(l in self.labels for l in labs)

    def all_src(self, _depth: int = 0) -> frozenset:
        if _depth > 4:
            return self.src
        out = set(self.src)
        it = self.items
        if isinstance(it, list):
            for x in it[:100]:
                out |= x.all_src(_depth + 1)
        elif isinstance(it, dict):
            for x in list(it.values())[:100]:
                out |= x.all_src(_depth + 1)
        return frozenset(out)

    def all_lines(self, _depth: int = 0) -> frozenset:
        if _depth > 4:
            return self.lines
        out = set(self.lines)
        it = self.items
        if isinstance(it, list):
            for x in it[:100]:
                out |= x.all_lines(_depth + 1)
        elif isinstance(it, dict):
            for x in list(it.values())[:100]:
                out |= x.all_lines(_depth + 1)
        return frozenset(out)

    def all_labels(self, _depth: int = 0) -> frozenset:
        """Labels including those of container members."""
        if _depth > 4:
            return self.labels
        out = set(self.labels)
        it = self.items
        if isinstance(it, list):
            for x in it[:200]:
                out |= x.all_labels(_depth + 1)
        elif isinstance(it, dict):
            for x in list(it.values())[:200]:
                out |= x.all_labels(_depth + 1)
        return frozenset(out)

    def with_labels(self, *labs: str) -> "V":
        nv = V(**{k: getattr(self, k) for k in self.__dataclass_fields__})
        nv.labels = U(self.labels, labs)
        return nv


def mk(c: Any = UNK, labels: Iterable[str] = (), lines: Iterable[int] = (), **kw) -> V:
    return V(c=c, labels=U(labels), lines=frozenset(lines), **kw)


def join_values(a: V, b: V) -> V:
    """Control-flow join of two abstract values."""
    if a is b:
        return a
    c = a.c if (a.c is not UNK and type(a.c) == type(b.c) and a.c == b.c) else UNK
    out = V(c=c, labels=U(a.labels, b.labels), lines=a.lines | b.lines, src=U(a.src, b.src))
    if a.q == b.q:
        out.q = a.q
    if a.cls == b.cls:
        out.cls = a.cls
    if a.kind == b.kind:
        out.kind = a.kind
    if a.alias == b.alias:
        out.alias = a.alias
    if a.fn is b.fn:
        out.fn = a.fn
    if a.attrs is not None and a.attrs is b.attrs:
        out.attrs = a.attrs
    if a.items is not None and a.items is b.items:
        out.items = a.items
        out.n = a.n
    if a.meta is not None and a.meta is b.meta:
        out.meta = a.meta
    return out


@dataclass
class Event:
    cap: str
    line: int = 0
    name: str = ""                       # api / command name
    target: Optional[str] = None         # skeleton of the primary target (url, path, command, package ...)
    tlabels: frozenset = EMPTY           # labels of the target
    plabels: frozenset = EMPTY           # labels of the payload / data
    flags: set = field(default_factory=set)
    hostc: Optional[str] = None          # host class (for network ops)
    pathc: set = field(default_factory=set)  # path classes (for file ops)
    desc: str = ""                       # short human description of the target
    pdesc: str = ""                      # human description of payload origin
    mult: int = 1                        # how many times (loop multiplicity)
    extra: dict = field(default_factory=dict)
    lines: set = field(default_factory=set)  # extra related lines (origin of tainted data ...)

    def all_lines(self) -> set:
        out = set(self.lines)
        if self.line:
            out.add(self.line)
        return out


@dataclass
class Finding:
    category: str
    weight: float
    rule: str
    tags: list
    lines: list
    does: str = ""
    why: str = ""
    would: str = ""
    event: Optional[Event] = None
    hard: bool = False
