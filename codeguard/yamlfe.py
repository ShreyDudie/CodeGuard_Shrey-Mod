"""YAML front-end: CI workflows (GitHub Actions, GitLab, CircleCI), docker-compose, Kubernetes, Ansible.

Uses PyYAML's *composer* (nodes with line marks) and never loads Python objects.  Shell strings in run/script/command
fields are handed to the shell analyser with their true line numbers; configuration is checked for privilege
and supply-chain problems; every free-text value and comment is queued for the AI-instruction scorer.
"""
from __future__ import annotations

import re
from typing import Optional

import yaml

from . import knowledge as K
from . import textscan
from .ctx import Ctx
from .events import ENV, FILE, HOLE, SECRET, USER, V, Event, U

_SHELL_KEYS = {"run", "script", "before_script", "after_script", "command", "cmd", "entrypoint", "shell", "raw", "args", "commands", "exec", "install", "build",
               "init", "postinstall", "preinstall", "prestart", "post_install", "setup", "test", "deploy", "start", "pre", "post", "prepare", "pre_install"}
_GH_UNTRUSTED = re.compile(r"\$\{\{\s*(github\.event\.(issue|pull_request|comment|review|review_comment|discussion|head_commit|commits|pages|workflow_run)[^}]*\.(title|body|head\.ref|label|name|message|email|body)|github\.head_ref|github\.event\.inputs\.[\w-]+|inputs\.[\w-]+)\s*\}\}", re.I)
_GH_SECRET = re.compile(r"\$\{\{\s*secrets\.([\w-]+)\s*\}\}", re.I)
_GH_EXPR = re.compile(r"\$\{\{[^}]*\}\}")
_THIRD_PARTY_ACTION = re.compile(r"^([\w.\-]+)/([\w.\-/]+)@(.+)$")
_TRUSTED_OWNERS = {"actions", "github", "docker", "aws-actions", "azure", "google-github-actions", "hashicorp", "codecov", "gradle", "ruby", "astral-sh", "pypa", "dtolnay"}


def _scalar_text(node) -> tuple:
    """-> (text, first_content_line_1based) for a scalar node"""
    val = node.value
    style = getattr(node, "style", None)
    start = node.start_mark.line + 1
    if style in ("|", ">"):
        start += 1
    return val, start


def _prep_shell(text: str):
    """Replace CI expression syntax by shell variables carrying the right provenance."""
    pre = {}

    def sec(m):
        name = "__GHSECRET_" + re.sub(r"\W", "_", m.group(1))
        pre[name] = V(c=HOLE, labels=U({SECRET}), src=frozenset({"the CI secret " + m.group(1)}))
        return "$" + name

    def untr(m):
        name = "__GHUSER_" + str(len(pre))
        pre[name] = V(c=HOLE, labels=U({USER}), src=frozenset({"attacker-controlled workflow input (" + m.group(0)[3:-2].strip() + ")"}))
        return "$" + name

    def other(m):
        name = "__GHEXPR_" + str(len(pre))
        pre[name] = V(c=HOLE, labels=U({ENV}))
        return "$" + name
    t = _GH_SECRET.sub(sec, text)
    t = _GH_UNTRUSTED.sub(untr, t)
    t = _GH_EXPR.sub(other, t)
    return t, pre


def _run_shell(text: str, line: int, ctx: Ctx, as_block: bool) -> None:
    from . import shfe
    t, pre = _prep_shell(text)
    old = ctx.line_base
    ctx.line_base = old + (line - 1 if as_block else 0)
    old_pin = ctx.pin_line
    if not as_block and not old_pin:
        ctx.pin_line = line + old
    try:
        sh = shfe.Shell(ctx, frozenset(), frozenset(), depth=ctx.depth)
        sh.vars.update(pre)
        shfe.analyze_shell(t, ctx, sh=sh)
    except Exception as e:
        ctx.notes.append(f"yaml shell error: {type(e).__name__}")
    finally:
        ctx.line_base = old
        ctx.pin_line = old_pin


def _walk(node, path: tuple, ctx: Ctx, state: dict) -> None:
    ctx.tick()
    if isinstance(node, yaml.MappingNode):
        keys = {}
        for k, v in node.value:
            if isinstance(k, yaml.ScalarNode):
                keys[k.value] = v
        _check_mapping(node, keys, path, ctx, state)
        for k, v in node.value:
            kname = k.value if isinstance(k, yaml.ScalarNode) else ""
            _walk(v, path + (kname,), ctx, state)
    elif isinstance(node, yaml.SequenceNode):
        for i, v in enumerate(node.value):
            _walk(v, path + (str(i),), ctx, state)
    elif isinstance(node, yaml.ScalarNode):
        _scalar(node, path, ctx, state)


def _is_shellish_key(path: tuple) -> bool:
    for p in reversed(path):
        if not p.isdigit():
            return p.lower() in _SHELL_KEYS
    return False


def _scalar(node, path: tuple, ctx: Ctx, state: dict) -> None:
    text, line = _scalar_text(node)
    if not isinstance(text, str) or not text.strip():
        return
    key = next((p for p in reversed(path) if not p.isdigit()), "")
    if _is_shellish_key(path) and len(text) < 20000:
        multiline = "\n" in text
        _run_shell(text, line, ctx, as_block=multiline or getattr(node, "style", None) in ("|", ">"))
        return
    if key == "uses":
        _check_uses(text, line, ctx, state)
        return
    if key in ("image",) and isinstance(text, str):
        if text.endswith(":latest") or ":" not in text.split("/")[-1]:
            pass
    if len(text) >= 24 and " " in text:
        ctx.text(line, text, "yaml_value", "yaml")


def _check_uses(text: str, line: int, ctx: Ctx, state: dict) -> None:
    m = _THIRD_PARTY_ACTION.match(text.strip())
    if not m:
        return
    owner, name, ref = m.group(1), m.group(2), m.group(3)
    pinned = bool(re.fullmatch(r"[0-9a-f]{40}", ref))
    if owner.lower() in _TRUSTED_OWNERS:
        return
    fl = {"ci_action"}
    if pinned:
        return
    if ref in ("main", "master", "latest", "HEAD", "develop", "dev"):
        fl |= {"unpinned_branch"}
        ctx.emit(Event(cap="INSTALL_PKG", line=line, name="uses", target=text, flags={"vcs_source", "ci_action", "unpinned_branch"}, hostc="EXTERNAL",
                       extra={"eco": "action", "pkg": f"{owner}/{name}", "rep": "UNKNOWN"}))


def _check_mapping(node, keys: dict, path: tuple, ctx: Ctx, state: dict) -> None:
    def val(k):
        n = keys.get(k)
        return n.value if isinstance(n, yaml.ScalarNode) else None

    def line_of(k):
        n = keys.get(k)
        return (n.start_mark.line + 1) if n is not None else node.start_mark.line + 1

    def truthy(k):
        v = val(k)
        return isinstance(v, str) and v.strip().lower() in ("true", "yes", "on", "1")
    # ---- containers / kubernetes / compose
    if truthy("privileged") or truthy("hostPID") or truthy("hostIPC") or truthy("hostNetwork") and False:
        ctx.emit(Event(cap="PRIV", line=line_of("privileged") if "privileged" in keys else (line_of("hostPID") if "hostPID" in keys else line_of("hostIPC")),
                       name="privileged", target="privileged container", flags={"container_escape", "privileged"}))
    if truthy("allowPrivilegeEscalation"):
        ctx.emit(Event(cap="PRIV", line=line_of("allowPrivilegeEscalation"), name="allowPrivilegeEscalation", target="allowPrivilegeEscalation: true", flags={"container_escape"}))
    if val("network_mode") == "host" or val("pid") == "host" or val("ipc") == "host" or val("userns_mode") == "host":
        ctx.emit(Event(cap="PRIV", line=line_of("network_mode" if "network_mode" in keys else "pid" if "pid" in keys else "ipc"), name="host namespace", target="host namespace sharing", flags={"container_escape", "host_ns"}))
    if "hostPath" in keys:
        pn = keys["hostPath"]
        pth = None
        if isinstance(pn, yaml.MappingNode):
            for k2, v2 in pn.value:
                if isinstance(k2, yaml.ScalarNode) and k2.value == "path" and isinstance(v2, yaml.ScalarNode):
                    pth = v2.value
        if pth is not None:
            pc = K.classify_path(pth)
            if pth in ("/", "/etc", "/root", "/var/run/docker.sock", "/proc", "/sys", "/var/lib/docker", "/home") or pc & {"ROOT", "SYSTEM_DIR", "SECRET_STORE"} or "docker.sock" in pth:
                ctx.emit(Event(cap="PRIV", line=line_of("hostPath"), name="hostPath", target=pth, pathc=pc, flags={"container_escape", "host_mount"}))
    if "cap_add" in keys or "capabilities" in keys:
        for n in ast_scalars(keys.get("cap_add")) + ast_scalars(keys.get("add") if "add" in keys else None) + ast_scalars(keys.get("capabilities")):
            if str(n).upper() in ("ALL", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_ADMIN", "DAC_READ_SEARCH"):
                ctx.emit(Event(cap="PRIV", line=line_of("cap_add" if "cap_add" in keys else "capabilities"), name="cap_add", target=str(n), flags={"container_escape", "cap_add"}))
    if val("runAsUser") == "0" or val("user") in ("root", "0") and ("image" in keys or "build" in keys):
        pass   # running as root alone is common; only a signal in combination
    if "volumes" in keys:
        for s in ast_scalars_with_lines(keys["volumes"]):
            vtext, vline = s
            if re.match(r"^\s*(/:|/etc|/root|/var/run/docker\.sock|/proc|/sys|/home|/var/lib/docker|/boot)\b", vtext) or "docker.sock" in vtext or re.match(r"^\s*/:/", vtext):
                ctx.emit(Event(cap="PRIV", line=vline, name="volume", target=vtext, flags={"container_escape", "host_mount"}))
    # ---- GitHub Actions specifics
    if "jobs" in keys and ("on" in keys or "true" in keys or True in keys):
        state["gha"] = True
    if "on" in keys or "true" in keys:
        on_node = keys.get("on") or keys.get("true")
        if _mentions(on_node, "pull_request_target"):
            state["pr_target"] = line_of("on") if "on" in keys else line_of("true")
    if val("permissions") in ("write-all",):
        ctx.emit(Event(cap="PRIV", line=line_of("permissions"), name="permissions", target="write-all", flags={"ci_permissions", "container_escape"}))
    if "uses" in keys and isinstance(keys["uses"], yaml.ScalarNode) and "checkout" in keys["uses"].value and state.get("pr_target"):
        w = keys.get("with")
        ref_txt = ""
        if isinstance(w, yaml.MappingNode):
            for k2, v2 in w.value:
                if isinstance(k2, yaml.ScalarNode) and k2.value == "ref" and isinstance(v2, yaml.ScalarNode):
                    ref_txt = v2.value
        if "head" in ref_txt or "pull_request" in ref_txt:
            ctx.emit(Event(cap="PRIV", line=line_of("uses"), name="pull_request_target", target="checkout of untrusted PR code with write token", flags={"container_escape", "pr_target_checkout"}))
    # ---- ansible-ish
    for mod, cap in (("shell", None), ("command", None), ("raw", None), ("script", None)):
        pass
    if "authorized_key" in keys:
        ctx.emit(Event(cap="PERSIST", line=line_of("authorized_key"), name="authorized_key", target="authorized_key", flags={"authorized_keys"}))
    if "cron" in keys:
        ctx.emit(Event(cap="PERSIST", line=line_of("cron"), name="cron", target="cron", flags={"crontab_install"}))
    if "pip" in keys and isinstance(keys["pip"], yaml.MappingNode):
        for k2, v2 in keys["pip"].value:
            if isinstance(k2, yaml.ScalarNode) and k2.value == "name":
                for t, ln in ast_scalars_with_lines(v2):
                    _install_py(t, ln, ctx)
    if "get_url" in keys or "uri" in keys:
        pass
    if "lineinfile" in keys and isinstance(keys["lineinfile"], yaml.MappingNode):
        d = {k2.value: v2 for k2, v2 in keys["lineinfile"].value if isinstance(k2, yaml.ScalarNode)}
        pth = d.get("path").value if isinstance(d.get("path"), yaml.ScalarNode) else ""
        line = d.get("line").value if isinstance(d.get("line"), yaml.ScalarNode) else ""
        pc = K.classify_path(pth)
        if pc & {"PRIVFILE", "PERSIST"}:
            ctx.emit(Event(cap="WRITE_FILE", line=line_of("lineinfile"), name="lineinfile", target=pth, pathc=pc, flags={"append"}, extra={"content": line}))
    # ---- k8s command/args arrays are covered via shell keys


def _install_py(spec: str, line: int, ctx: Ctx) -> None:
    from . import shfe
    sh = shfe.Shell(ctx, frozenset(), frozenset())
    sh._install("pypi", [V(c=spec, lines=frozenset({line}))], line, set(), "pip")


def _mentions(node, word: str) -> bool:
    if node is None:
        return False
    if isinstance(node, yaml.ScalarNode):
        return node.value == word
    if isinstance(node, yaml.SequenceNode):
        return any(_mentions(n, word) for n in node.value)
    if isinstance(node, yaml.MappingNode):
        return any(_mentions(k, word) for k, _v in node.value)
    return False


def ast_scalars(node) -> list:
    out = []
    if node is None:
        return out
    if isinstance(node, yaml.ScalarNode):
        out.append(node.value)
    elif isinstance(node, yaml.SequenceNode):
        for n in node.value:
            out += ast_scalars(n)
    elif isinstance(node, yaml.MappingNode):
        for _k, v in node.value:
            out += ast_scalars(v)
    return out


def ast_scalars_with_lines(node) -> list:
    out = []
    if node is None:
        return out
    if isinstance(node, yaml.ScalarNode):
        out.append((node.value, node.start_mark.line + 1))
    elif isinstance(node, yaml.SequenceNode):
        for n in node.value:
            out += ast_scalars_with_lines(n)
    elif isinstance(node, yaml.MappingNode):
        for _k, v in node.value:
            out += ast_scalars_with_lines(v)
    return out


def analyze_yaml_text(text: str, ctx: Ctx) -> None:
    for ln, body in textscan.extract_hash_comments(text):
        ctx.text(ln, body, "comment", "yaml")
    docs = []
    try:
        for d in yaml.compose_all(text, Loader=yaml.SafeLoader):
            if d is not None:
                docs.append(d)
    except Exception as e:
        ctx.notes.append(f"yaml parse failed: {type(e).__name__}")
        from . import genericfe
        genericfe.analyze_generic_text(text, ctx, "yaml")
        return
    state: dict = {}
    for d in docs:
        _walk(d, (), ctx, state)
    # long free-text scalars that are not code
    for m in re.finditer(r"^\s*(?:-\s+)?[\w.\-]+:\s*(['\"])(.{24,}?)\1\s*$", text, re.M):
        pass
