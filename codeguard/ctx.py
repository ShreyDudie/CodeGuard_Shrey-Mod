"""Analysis context shared by all front-ends: collects events, texts and defects under a time budget."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from .events import Event, EMPTY


class Stop(Exception):
    """Raised when the analysis budget (steps or wall clock) is exhausted."""


@dataclass
class TextItem:
    line: int
    text: str
    kind: str          # comment | docstring | string | md_comment | prose | yaml_value | tool_desc
    lang: str = ""
    end: int = 0       # last line of a multi-line string or docstring


@dataclass
class Defect:
    line: int
    kind: str
    message: str


class Ctx:
    def __init__(self, budget_s: float = 0.35, max_steps: int = 60000):
        self.events: list[Event] = []
        self.texts: list[TextItem] = []
        self.defects: list[Defect] = []
        self.t0 = time.perf_counter()
        self.budget_s = budget_s
        self.max_steps = max_steps
        self.steps = 0
        self.in_decoded = 0            # >0 while analysing the text of a decoded payload
        self.depth = 0                 # nested-language recursion depth (decoded payloads, shell-in-python ...)
        self.seen: set = set()
        self.notes: list[str] = []     # analysis notes (parse failures, truncation)
        self.line_base = 0             # added to lines of nested snippets (yaml run blocks ...)
        self.pin_line = 0              # when set, every nested event is pinned to this line
        self.parsed_ok = True
        self.lang = ""

    # -- budget -------------------------------------------------------------------------------
    def tick(self, n: int = 1) -> None:
        self.steps += n
        if self.steps > self.max_steps:
            raise Stop("steps")
        if (self.steps & 0xFF) == 0 and time.perf_counter() - self.t0 > self.budget_s:
            raise Stop("time")

    # -- events -------------------------------------------------------------------------------
    def emit(self, ev: Event) -> Event:
        if self.in_decoded:
            ev.flags.add("from_decoded")
        self._fix_lines(ev)
        key = (ev.cap, ev.line, ev.name, ev.target, tuple(sorted(ev.flags)), tuple(sorted(ev.tlabels)), tuple(sorted(ev.plabels)))
        if key in self.seen:
            return ev
        self.seen.add(key)
        self.events.append(ev)
        return ev

    def _fix_lines(self, ev: Event) -> None:
        if self.pin_line:
            ev.line = self.pin_line
            ev.lines = {self.pin_line} if ev.lines else set()
        elif self.line_base:
            ev.line = ev.line + self.line_base if ev.line else ev.line
            ev.lines = {x + self.line_base for x in ev.lines}

    def text(self, line: int, text: str, kind: str, lang: str = "", end: int = 0) -> None:
        if not text or not text.strip():
            return
        if self.pin_line:
            line = self.pin_line
        elif self.line_base:
            line = line + self.line_base
        self.texts.append(TextItem(line, text, kind, lang, (end + (line - line)) if end else 0))

    def defect(self, line: int, kind: str, message: str) -> None:
        self.defects.append(Defect(line, kind, message))
