"""Plain-English explanations: what the code does -> why that is a problem -> what would happen if it ran."""
from __future__ import annotations

import re
from typing import Optional

from . import knowledge as K
from .events import ENV_DUMP, FILE, HOLE, DB, NET, SECRET, SENS_SYS, USER, Event, Finding

_TAG_OK = re.compile(r"^(T\d{4}(\.\d{3})?|AML\.T\d+|CWE-\d+|LLM\d+)$")


class _Safe(dict):
    def __missing__(self, k):
        return ""


def _clean(s: Optional[str], limit: int = 70) -> str:
    if s is None:
        return "the value"
    s = s.replace(HOLE, "<input>")
    s = " ".join(s.split())
    if len(s) > limit:
        s = s[: limit - 1] + "…"
    return s


def path_desc(ev: Event) -> str:
    t = (ev.target or "").lower()
    if "SECRET_STORE" in ev.pathc:
        if ".aws" in t:
            return "AWS cloud credentials"
        if ".ssh" in t or "id_rsa" in t or "id_ed25519" in t or ".pem" in t or ".key" in t:
            return "private keys"
        if ".docker" in t:
            return "Docker registry logins"
        if ".kube" in t:
            return "Kubernetes cluster credentials"
        if "shadow" in t:
            return "password hashes"
        if ".npmrc" in t or ".pypirc" in t:
            return "package-registry tokens"
        if ".netrc" in t or "git-credentials" in t:
            return "saved logins"
        if ".env" in t:
            return "environment secrets"
        if "gnupg" in t:
            return "encryption keys"
        if "cookie" in t or "login data" in t or "keychain" in t or "mozilla" in t:
            return "saved browser or system passwords"
        return "credentials or secrets"
    if "SYSTEM_SENSITIVE" in ev.pathc:
        return "system account information"
    return "sensitive data"


def host_desc(ev: Event) -> str:
    h = ev.extra.get("host") or ""
    if not h and ev.target and ev.hostc:
        _s, h2, _c = K.host_of_url(ev.target if "://" in ev.target else "http://" + ev.target)
        h = h2 or ev.target
    h = _clean(h, 60) if h else ""
    hc = ev.hostc
    if hc == "META":
        return f"the cloud metadata service ({h or '169.254.169.254'})"
    if hc in ("USER", "UNKNOWN", None) and (not h or h in ("<input>", "the value")):
        return "an address supplied by the caller"
    if hc == "SUSPICIOUS":
        return f"{h} (an attacker-looking address)"
    if hc == "DROPSITE":
        return f"{h} (a webhook/paste service often used for data theft)"
    if hc == "LOOPBACK":
        return f"the local machine ({h})"
    if hc in ("PRIVATE", "INTERNAL", "LINKLOCAL"):
        return f"the internal address {h}"
    return h or "an external server"


def src_desc(ev: Event) -> str:
    srcs = ev.extra.get("src") or ()
    out = []
    for s in sorted(srcs):
        s = s.replace(HOLE, "<input>") if isinstance(s, str) else str(s)
        if s and s not in out:
            out.append(s)
    if out:
        return " and ".join(out[:2])
    pl = ev.plabels
    if ENV_DUMP in pl:
        return "all environment variables (which usually include secrets)"
    if SENS_SYS in pl:
        return "system account data"
    if SECRET in pl:
        return "secret values"
    if DB in pl:
        return "database rows"
    if FILE in pl:
        return "file contents"
    return "local data"


def ctx_of(ev: Event) -> _Safe:
    return _Safe(
        target=_clean(ev.target),
        api=(ev.name or "").split(".")[-1] or "it",
        host=host_desc(ev),
        src=src_desc(ev),
        pathdesc=path_desc(ev),
        pkg=_clean(str(ev.extra.get("pkg") or ev.target or ""), 40),
        similar=_clean(str(ev.extra.get("similar") or ""), 40),
        count=f"{ev.mult:,}" if ev.mult and ev.mult > 1 else (str(ev.extra.get("count")) if ev.extra.get("count") else "many"),
        witness=_clean(str(ev.extra.get("witness") or "a crafted value such as x; id"), 90),
    )


def fill(tmpl: str, ev: Optional[Event]) -> str:
    if not tmpl:
        return ""
    if ev is None:
        return tmpl
    try:
        return tmpl.format_map(ctx_of(ev))
    except Exception:
        return re.sub(r"\{\w+\}", "", tmpl)


def _tags(findings: list) -> list:
    out = []
    for f in findings:
        for t in f.tags:
            if _TAG_OK.match(str(t)) and t not in out:
                out.append(t)
    return out


def _cap(s: str) -> str:
    s = s.strip()
    return s[:1].upper() + s[1:] if s else s


def build_reason(fused: dict, verdict: str, cats: list, events: list, max_len: int = 640) -> str:
    groups = fused["groups"]
    if verdict == "allow":
        return allow_reason(events)
    picked: list = []
    # strongest finding of each reported category (strongest category first); findings about the same lines are merged
    order = sorted(cats, key=lambda c: -fused["cat_scores"].get(c, 0.0))
    seen_rules = set()
    covered: set = set()

    def overlaps(f) -> bool:
        ls = set(f.lines)
        return bool(ls and ls & covered)
    cands = []
    for c in order:
        for f in groups.get(c, [])[:3]:
            if f.weight >= 0.45:
                cands.append(f)
    cands.sort(key=lambda f: -f.weight)
    for f in cands:
        if f.rule in seen_rules or overlaps(f) or len(picked) >= 3:
            continue
        picked.append(f)
        seen_rules.add(f.rule)
        covered |= set(f.lines)
    # make sure every reported category is represented even if its lines overlap with a stronger finding
    for c in order:
        if len(picked) >= 3:
            break
        if not any(p.category == c for p in picked):
            for f in groups.get(c, [])[:1]:
                if f.rule not in seen_rules:
                    picked.append(f)
                    seen_rules.add(f.rule)
    if not picked:
        for c in order:
            for f in groups.get(c, [])[:1]:
                picked.append(f)
    does = [fill(f.does, f.event) for f in picked if f.does]
    # drop repetitive clauses
    uniq = []
    for d in does:
        if d and d not in uniq:
            uniq.append(d)
    does = uniq[:3]
    if not does:
        s1 = "This code matches a known risky behaviour."
    elif len(does) == 1:
        s1 = "This code " + does[0] + "."
    elif len(does) == 2:
        s1 = "This code " + does[0] + ", and it " + does[1] + "."
    else:
        s1 = "This code " + does[0] + ", then it " + does[1] + ", and it " + does[2] + "."
    top = picked[0] if picked else None
    s2 = ""
    s3 = ""
    if top:
        why = fill(top.why, top.event)
        would = fill(top.would, top.event)
        if why:
            s2 = " This is dangerous because " + why.rstrip(".") + "."
        if would:
            w = would.rstrip(".")
            s3 = " If it ran, " + (w[:1].lower() + w[1:] if w[:1].isupper() and not w[:2].isupper() else w) + "."
    tags = _tags(picked)
    tag_s = f" [{', '.join(tags[:4])}]" if tags else ""
    out = (s1 + s2 + s3 + tag_s).strip()
    if len(out) > max_len:
        out = (s1 + s2 + tag_s).strip()
    if len(out) > max_len:
        out = out[: max_len - 2].rstrip() + "…"
    return out


def allow_reason(events: list) -> str:
    flags_all = set()
    for e in events:
        flags_all |= e.flags
    caps = {e.cap for e in events}
    if any(e.cap == "SQL_STMT" and "parameterized" in e.flags for e in events):
        return "This code only runs database queries that pass user values as separate parameters, so input cannot change the query itself, and nothing else in it is risky."
    if "VALIDATED" in " ".join(sorted({l for e in events for l in e.tlabels})):
        return "This code checks the outside value against an allowlist before using it, and nothing else in it is risky."
    if not events:
        return "Nothing in this code reads secrets, sends data out, deletes data, runs outside input, hides what it does, installs odd packages, exhausts resources or talks to internal addresses."
    kinds = []
    if "READ_FILE" in caps:
        kinds.append("reads ordinary files")
    if "WRITE_FILE" in caps:
        kinds.append("writes ordinary files")
    if caps & {"NET_FETCH", "NET_SEND"}:
        kinds.append("talks to normal external services")
    if "INSTALL_PKG" in caps:
        kinds.append("installs well-known packages")
    if "SQL_STMT" in caps:
        kinds.append("runs scoped database statements")
    if caps & {"EXEC_PROC", "EXEC_SHELL"}:
        kinds.append("runs fixed commands")
    if "SPAWN" in caps:
        kinds.append("starts a bounded number of workers")
    if kinds:
        return "This code " + ", ".join(kinds[:3]) + ". None of that touches secrets, runs untrusted input, deletes broadly or reaches internal addresses, so it looks safe."
    return "This code does ordinary work and nothing in it matches a risky behaviour."
