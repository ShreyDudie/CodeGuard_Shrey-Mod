"""Node.js / browser library semantics for the abstract interpreter (mixed into Interp for JS analysis)."""
from __future__ import annotations

import re
from typing import Optional

from . import knowledge as K
from .events import (BUILT, CMDSUB, DECODED, EMPTY, ENV, ENV_DUMP, FILE, HOLE, NET, QUOTED, SAFE_NUM, SECRET, UNK, USER, V, U)

JS_GLOBALS = {"fetch", "eval", "atob", "btoa", "Function", "setTimeout", "setInterval", "setImmediate", "XMLHttpRequest", "WebSocket", "process", "require", "module",
              "exports", "document", "window", "navigator", "localStorage", "sessionStorage", "Buffer", "console", "JSON", "Object", "Math", "Array", "String", "Number",
              "parseInt", "parseFloat", "encodeURIComponent", "decodeURIComponent", "escape", "unescape", "globalThis", "location", "history", "Promise", "Date", "Error",
              "Symbol", "Map", "Set", "URL", "URLSearchParams", "FormData", "Blob", "Image", "EventSource", "indexedDB", "crypto", "performance", "worker", "importScripts",
              "alert", "prompt", "confirm", "isNaN", "Boolean", "RegExp", "Reflect", "Proxy", "WebAssembly", "TextDecoder", "TextEncoder", "Uint8Array", "ArrayBuffer",
              "queueMicrotask", "structuredClone", "__dirname", "__filename", "global", "self"}
_SECRET_KEY = re.compile(r"(token|auth|jwt|session|passw|secret|api[_-]?key|credential|bearer|refresh|access)", re.I)


def _arg(args, kws, idx, name=None):
    if idx is not None and idx < len(args):
        return args[idx]
    if name and name in kws:
        return kws[name]
    return None


def _dict_get(v: Optional[V], key: str) -> Optional[V]:
    if v is not None and isinstance(v.items, dict):
        return v.items.get(key)
    return None


class JSLibMixin:
    def js_require(self, q, callee, args, kws, n, recv):
        a = args[0] if args else V()
        name = a.exact()
        if name is None:
            self.emit("LOAD_MODULE", n.lineno, "require", target=HOLE, tl=a.all_labels(), flags={"dynamic_name"} | ({"tainted"} if a.all_labels() & {USER} else set()), lines=a.all_lines())
            return V(c=UNK, kind="module", labels=a.all_labels(), src=a.all_src())
        from .jsparse import normalize_module
        name = normalize_module(name)
        v = V(q=name, kind="module", c=UNK, lines=frozenset({n.lineno}))
        if a.labels & {BUILT, DECODED}:
            self.emit("LOAD_MODULE", n.lineno, "require", target=name, tl=a.all_labels(), flags={"dynamic_name", "built_string"})
            if name in ("child_process", "fs", "net", "vm", "os", "http", "https", "dns"):
                v.alias = "<dyn>"
        return v

    # ---- eval-ish ----------------------------------------------------------------------------------
    def js_function_ctor(self, q, callee, args, kws, n, recv):
        body = args[-1] if args else V()
        spec = {"cap": "EVAL", "flags": ["exec", "function_ctor"]}
        self.do_eval(q, spec, body, args, kws, n, {"exec", "function_ctor"})
        return V(c=UNK, kind="func", labels=body.all_labels())

    def js_timer(self, q, callee, args, kws, n, recv):
        a = args[0] if args else V()
        if a.is_str() or (a.kind is None and a.c is not UNK and isinstance(a.c, str)):
            spec = {"cap": "EVAL", "flags": ["exec", "timer_string"]}
            self.do_eval(q, spec, a, args, kws, n, {"exec", "timer_string"})
        elif q.endswith("setInterval"):
            delay = args[1] if len(args) > 1 else None
            if delay is not None and isinstance(delay.c, (int, float)) and delay.c <= 1 and a.kind == "func" and isinstance(a.fn, object):
                self.emit("LOOP", n.lineno, "setInterval", flags={"unbounded", "busy"}, extra={"interval": delay.c})
        return V(c=UNK, kind="num", labels=U({SAFE_NUM}))

    def js_vm(self, q, callee, args, kws, n, recv):
        a = args[0] if args else V()
        spec = {"cap": "EVAL", "flags": ["exec", "vm"]}
        self.do_eval(q, spec, a, args, kws, n, {"exec", "vm"})
        return V(c=UNK, labels=a.all_labels())

    # ---- child_process -------------------------------------------------------------------------------
    def js_exec(self, q, callee, args, kws, n, recv):
        cmd = args[0] if args else V()
        spec = {"cap": "EXEC_SHELL", "flags": list(callee.alias and ["aliased_import"] or [])}
        rv = self.do_exec(q, spec, "EXEC_SHELL", cmd, args, kws, n, set(self.spec_flags(spec, callee, "EXEC_SHELL")), {CMDSUB})
        return V(c=HOLE, kind="str", cls="subprocess.Popen", labels=U({CMDSUB}), lines=frozenset({n.lineno}))

    def js_spawn(self, q, callee, args, kws, n, recv):
        cmd = args[0] if args else V()
        argv = args[1] if len(args) > 1 and isinstance(args[1].items, list) else None
        opts = None
        for a in args[1:]:
            if isinstance(a.items, dict):
                opts = a
        shell_opt = _dict_get(opts, "shell")
        fl = set(self.spec_flags({"flags": []}, callee, "EXEC_PROC"))
        if q.endswith("fork"):
            self.emit("SPAWN", n.lineno, q, flags={"fork_child"})
            return V(c=UNK, kind="obj", cls="subprocess.Popen")
        if shell_opt is not None and (shell_opt.c is True or shell_opt.c == "true"):
            text = cmd.skel() or HOLE
            if argv is not None:
                text = text + " " + " ".join(x.c if isinstance(x.c, str) else HOLE for x in argv.items)
            tv = V(c=text, kind="str", labels=U(cmd.all_labels(), argv.all_labels() if argv else EMPTY), src=U(cmd.all_src(), argv.all_src() if argv else EMPTY))
            self.do_exec(q, {"cap": "EXEC_SHELL"}, "EXEC_SHELL", tv, args, kws, n, fl | {"shell_true"}, {CMDSUB})
        else:
            items = [cmd] + (list(argv.items) if argv is not None else [])
            tv = V(c=UNK, kind="list", items=items, n=len(items), labels=EMPTY)
            self.do_exec(q, {"cap": "EXEC_PROC"}, "EXEC_PROC", tv, args, kws, n, fl, {CMDSUB})
        return V(c=UNK, kind="obj", cls="subprocess.Popen", labels=U({CMDSUB}))

    # ---- fs ----------------------------------------------------------------------------------------------
    def js_fs_read(self, q, callee, args, kws, n, recv):
        p = args[0] if args else V()
        path = p.skel() if p.is_str() else None
        pc = K.classify_path(path) if path else set()
        lab, srcs = self.path_labels(path or "")
        if path is None or path == HOLE:
            lab, srcs = U({FILE}), frozenset({"a file chosen by the caller"})
        self.emit("READ_FILE", n.lineno, q, target=path if path is not None else HOLE, tl=p.all_labels(), pathc=pc, pl=lab, extra={"src": srcs}, lines=p.all_lines())
        obj = V(c=HOLE, kind="str", labels=lab, src=srcs, lines=frozenset({n.lineno}))
        if "createReadStream" in q:
            obj.kind = "file"
            obj.meta = {"path": path, "mode": "r", "pathv": p, "write": False, "pc": pc}
        return obj

    def js_fs_write(self, q, callee, args, kws, n, recv):
        p = args[0] if args else V()
        data = args[1] if len(args) > 1 else V()
        path = p.skel() if p.is_str() else None
        pc = K.classify_path(path) if path else set()
        fl = {"append"} if "append" in q.lower() else {"truncate"}
        if "createWriteStream" in q:
            obj = V(c=UNK, kind="file", cls="io.File", meta={"path": path, "mode": "a" if len(args) > 1 else "w", "pathv": p, "write": True, "pc": pc}, lines=frozenset({n.lineno}))
            if pc & {"PERSIST", "PRIVFILE", "SECRET_STORE"}:
                self.emit("WRITE_FILE", n.lineno, q, target=path, pathc=pc, flags={"open_write"} | fl, extra={"content": ""})
            return obj
        self.emit("WRITE_FILE", n.lineno, q, target=path if path is not None else HOLE, tl=p.all_labels(), pathc=pc, pl=data.all_labels(), flags=fl,
                  extra={"content": data.skel() if data.is_str() else "", "src": data.all_src()}, lines=p.all_lines() | data.all_lines())
        return V()

    def js_fs_delete(self, q, callee, args, kws, n, recv):
        p = args[0] if args else V()
        opts = None
        for a in args[1:]:
            if isinstance(a.items, dict):
                opts = a
        rec = _dict_get(opts, "recursive")
        fl = set()
        if (rec is not None and rec.c is True) or q.endswith(("rmdirSync", "rmdir")) and rec is not None and rec.c is True or "rimraf" in q or "remove" in q.lower() and "fs-extra" in q:
            fl.add("recursive")
        if q.endswith(("rm", "rmSync")) and opts is not None and _dict_get(opts, "force") is not None:
            fl.add("force")
        path = p.skel() if p.is_str() else (HOLE if p.labels else None)
        pc = K.classify_path(path) if path else set()
        lab = p.all_labels()
        if USER in lab and VALIDATED_LABEL not in lab:
            fl.add("tainted")
        self.emit("DELETE", n.lineno, q, target=path if path is not None else HOLE, tl=lab, pathc=pc, flags=fl, extra={"src": p.all_src()}, lines=p.all_lines())
        return V()

    def js_fs_chmod(self, q, callee, args, kws, n, recv):
        p = args[0] if args else V()
        m = args[1] if len(args) > 1 else V()
        path = p.skel() if p.is_str() else None
        pc = K.classify_path(path) if path else set()
        mode = m.c if isinstance(m.c, int) and not isinstance(m.c, bool) else None
        if isinstance(m.c, str) and re.fullmatch(r"[0-7]{3,4}", m.c):
            mode = int(m.c, 8)
        if mode is not None and (mode & 0o4000 or mode & 0o2000):
            self.emit("PRIV", n.lineno, q, target=path or HOLE, pathc=pc, flags={"chmod", "setuid"})
        elif mode is not None and mode & 0o002 and pc & {"ROOT", "SYSTEM_DIR", "PRIVFILE", "SECRET_STORE", "PERSIST"}:
            self.emit("PRIV", n.lineno, q, target=path or HOLE, pathc=pc, flags={"chmod", "world_writable"})
        return V()

    def js_fs_list(self, q, callee, args, kws, n, recv):
        p = args[0] if args else V()
        lab, srcs = self.path_labels(p.skel() or "")
        pc = K.classify_path(p.skel() or "") if p.is_str() else set()
        if pc & {"ROOT", "HOME_DIR", "USER_DATA", "SYSTEM_DIR"}:
            lab = U(lab, {"BROAD_WALK"})
        return V(c=UNK, kind="list", labels=U(lab, p.labels), src=srcs, lines=frozenset({n.lineno}))

    # ---- network ------------------------------------------------------------------------------------------
    def _net_event(self, q, cap, url_v: V, payload: list, n, fl: set, extra_host: Optional[str] = None) -> V:
        url = url_v.skel() if url_v.is_str() else None
        tl = url_v.all_labels()
        hostc = None
        host = extra_host
        if url is not None:
            scheme, h, hostc = K.host_of_url(url if "://" in url or url.startswith(HOLE) else "http://" + url)
            host = host or h
            if scheme in K.DANGEROUS_SCHEMES:
                fl.add("dangerous_scheme")
            if scheme == "http":
                fl.add("plain_http")
            if hostc == "USER" or (url.startswith(HOLE) and "://" not in url):
                hostc = "USER"
        else:
            hostc = "USER" if tl & {USER, NET, FILE} else "UNKNOWN"
        if tl & {USER} and hostc in ("USER", "UNKNOWN") and VALIDATED_LABEL not in tl:
            fl.add("user_url")
        if VALIDATED_LABEL in tl:
            fl.add("validated")
        pl = set()
        psrc = set()
        for x in payload:
            if x is not None:
                pl |= x.all_labels()
                psrc |= x.all_src()
        pl |= tl & {SECRET, ENV_DUMP}
        self.emit(cap, n.lineno, q, target=url if url is not None else (host or HOLE), tl=tl, pl=U(pl), hostc=hostc, flags=fl,
                  extra={"host": host, "src": U(psrc, url_v.all_src())}, lines=url_v.all_lines())
        if hostc == "META":
            return V(c=UNK, kind="obj", cls="requests.Response", labels=U({NET, SECRET}), src=frozenset({"cloud credentials from the metadata service"}), lines=frozenset({n.lineno}))
        return V(c=UNK, kind="obj", cls="requests.Response", labels=U({NET}), src=frozenset({"a network response"}), lines=frozenset({n.lineno}))

    def js_fetch(self, q, callee, args, kws, n, recv):
        url = args[0] if args else kws.get("url") or V()
        opts = args[1] if len(args) > 1 else kws.get("options")
        method = _dict_get(opts, "method")
        body = _dict_get(opts, "body") or _dict_get(opts, "data")
        m = (method.exact() or "").upper() if method is not None else "GET"
        cap = "NET_SEND" if (body is not None and body.c is not None) or m in ("POST", "PUT", "PATCH") else "NET_FETCH"
        headers = _dict_get(opts, "headers")
        fl = set()
        if headers is not None and headers.all_labels() & {SECRET}:
            fl.add("secret_in_header")
        return self._net_event(q, cap, url, [body] if body is not None else [], n, fl)

    def js_axios(self, q, callee, args, kws, n, recv):
        name = q.rsplit(".", 1)[-1].lower()
        post_like = name in ("post", "put", "patch")
        if name in ("get", "head", "delete", "options"):
            url = args[0] if args else V()
            body = None
            opts = args[1] if len(args) > 1 else None
        elif post_like:
            url = args[0] if args else V()
            body = args[1] if len(args) > 1 else None
            opts = args[2] if len(args) > 2 else None
        else:        # axios(config) / axios.request(config) / request(url, opts)
            first = args[0] if args else V()
            if isinstance(first.items, dict):
                url = _dict_get(first, "url") or V()
                body = _dict_get(first, "data") or _dict_get(first, "body")
                mm = _dict_get(first, "method")
                post_like = (mm is not None and (mm.exact() or "").upper() in ("POST", "PUT", "PATCH")) or body is not None
                opts = first
            else:
                url = first
                opts = args[1] if len(args) > 1 else None
                body = _dict_get(opts, "data") or _dict_get(opts, "body") or _dict_get(opts, "form") or _dict_get(opts, "json")
                mm = _dict_get(opts, "method")
                post_like = (mm is not None and (mm.exact() or "").upper() in ("POST", "PUT", "PATCH")) or body is not None
        fl = set()
        hdr = _dict_get(opts, "headers")
        if hdr is not None and hdr.all_labels() & {SECRET}:
            fl.add("secret_in_header")
        return self._net_event(q, "NET_SEND" if post_like else "NET_FETCH", url, [body] if body is not None else [], n, fl)

    def js_http_request(self, q, callee, args, kws, n, recv):
        a0 = args[0] if args else V()
        is_get = q.endswith(".get")
        cap = "NET_FETCH" if is_get else "NET_SEND"
        url = a0
        host_override = None
        if isinstance(a0.items, dict):
            h = _dict_get(a0, "hostname") or _dict_get(a0, "host")
            path = _dict_get(a0, "path")
            m = _dict_get(a0, "method")
            scheme = "https://" if q.startswith("https") else "http://"
            hs = (h.skel() if h is not None and h.is_str() else HOLE)
            ps = (path.skel() if path is not None and path.is_str() else "")
            url = V(c=scheme + hs + ps, kind="str", labels=U(a0.all_labels()), src=a0.all_src(), lines=a0.all_lines())
            if m is not None and (m.exact() or "").upper() in ("GET", "HEAD"):
                cap = "NET_FETCH"
        req = V(c=UNK, kind="obj", cls="http.client.ClientRequest", meta={"url": url, "cap": cap}, lines=frozenset({n.lineno}))
        if is_get or cap == "NET_FETCH":
            self._net_event(q, "NET_FETCH", url, [], n, set())
        else:
            req.meta["pending"] = True
        return req

    def js_xhr_new(self, q, callee, args, kws, n, recv):
        return V(c=UNK, kind="obj", cls="xhr", meta={"url": None}, lines=frozenset({n.lineno}))

    def js_ws_new(self, q, callee, args, kws, n, recv):
        url = args[0] if args else V()
        self._net_event(q, "NET_CONNECT", url, [], n, set())
        host = None
        if url.is_str():
            host = K.split_url(url.skel() or "")[1]
        return V(c=UNK, kind="obj", cls="websocket.WebSocket", meta={"host": host}, lines=frozenset({n.lineno}))

    def js_beacon(self, q, callee, args, kws, n, recv):
        url = args[0] if args else V()
        body = args[1] if len(args) > 1 else None
        return self._net_event(q, "NET_SEND", url, [body] if body is not None else [], n, {"beacon"})

    def js_net_connect(self, q, callee, args, kws, n, recv):
        # net.connect(port, host) / net.connect({host, port})
        host_v = V()
        for a in args:
            if isinstance(a.items, dict):
                host_v = _dict_get(a, "host") or host_v
            elif a.is_str():
                host_v = a
        if host_v.c is UNK and args and args[-1].is_str():
            host_v = args[-1]
        h = host_v.skel() if host_v.is_str() else None
        hostc = K.classify_host(h) if h else "UNKNOWN"
        self.emit("NET_CONNECT", n.lineno, q, target=h or HOLE, tl=host_v.all_labels(), hostc=hostc, flags=set(), extra={"host": h}, lines=host_v.all_lines())
        return V(c=UNK, kind="obj", cls="socket.socket", meta={"host": h}, lines=frozenset({n.lineno}))

    def js_dns(self, q, callee, args, kws, n, recv):
        a = args[0] if args else V()
        fl = set()
        if a.all_labels() & {SECRET, ENV_DUMP, FILE, CMDSUB}:
            fl.add("data_in_query")
        h = a.skel() if a.is_str() else None
        self.emit("DNS", n.lineno, q, target=h or HOLE, tl=a.all_labels(), pl=a.all_labels() & {SECRET, ENV_DUMP, FILE, CMDSUB, "SENS_SYS"}, hostc=K.classify_host(h.split("/")[0]) if h and HOLE not in h else None,
                  flags=fl, extra={"src": a.all_src()})
        return V(c=HOLE, labels=U({NET}))

    def js_dgram_send(self, q, callee, args, kws, n, recv):
        return V()

    # ---- decoders / misc ------------------------------------------------------------------------------------
    def js_atob(self, q, callee, args, kws, n, recv):
        return self.s_decode("base64.b64decode", callee, args[:1], kws, n, recv)

    def js_btoa(self, q, callee, args, kws, n, recv):
        return self.s_encode("base64.b64encode", callee, args[:1], kws, n, recv)

    def js_buffer_from(self, q, callee, args, kws, n, recv):
        a = args[0] if args else V()
        enc = args[1].exact() if len(args) > 1 and args[1].exact() else "utf8"
        if enc == "base64":
            return self.s_decode("base64.b64decode", callee, [a], kws, n, recv)
        if enc == "hex":
            return self.s_decode("binascii.unhexlify", callee, [a], kws, n, recv)
        return V(c=a.c if isinstance(a.c, str) else HOLE, kind="bytes", labels=a.all_labels(), src=a.all_src(), lines=frozenset({n.lineno}))

    def js_zlib(self, q, callee, args, kws, n, recv):
        a = args[0] if args else V()
        return V(c=HOLE, kind="str", labels=U(a.all_labels(), {DECODED}), src=a.all_src())

    def js_storage_get(self, q, callee, args, kws, n, recv):
        k = args[0] if args else V()
        kn = k.exact() or ""
        lab = {SECRET} if (not kn or _SECRET_KEY.search(kn)) else {FILE}
        return V(c=HOLE, kind="str", labels=U(lab), src=frozenset({"browser storage " + (kn or "")}), lines=frozenset({n.lineno}))

    def js_parse_num(self, q, callee, args, kws, n, recv):
        a = args[0] if args else V()
        if isinstance(a.c, (int, float)):
            return V(c=a.c, kind="num")
        if isinstance(a.c, str) and HOLE not in a.c:
            m = re.match(r"\s*(-?\d+(?:\.\d+)?)", a.c)
            if m:
                return V(c=float(m.group(1)) if "." in m.group(1) else int(m.group(1)), kind="num")
        return V(c=UNK, kind="num", labels=U({SAFE_NUM}))

    def js_os_homedir(self, q, callee, args, kws, n, recv):
        return V(c="~", kind="str")

    def js_os_tmpdir(self, q, callee, args, kws, n, recv):
        return V(c="/tmp", kind="str")

    def js_path_join(self, q, callee, args, kws, n, recv):
        return self.s_pathjoin("os.path.join", callee, args, kws, n, recv)

    def js_json_stringify(self, q, callee, args, kws, n, recv):
        return self.s_dumps(q, callee, args[:1], kws, n, recv)

    def js_json_parse(self, q, callee, args, kws, n, recv):
        return self.s_loads("json.loads", callee, args[:1], kws, n, recv)

    def js_encode_uri(self, q, callee, args, kws, n, recv):
        a = args[0] if args else V()
        return V(c=HOLE, kind="str", labels=U(a.all_labels(), {QUOTED}), src=a.all_src())

    def s_js_string(self, q, callee, args, kws, n, recv):
        return self.b_str(callee, args, kws, n)

    def js_noop(self, q, callee, args, kws, n, recv):
        return V()

    def js_exit(self, q, callee, args, kws, n, recv):
        return V()

    def b___require__(self, callee, args, kws, n):
        return self.js_require("require", callee, args, kws, n, None)

    def b___unknown__(self, callee, args, kws, n):
        return V()

    def b_property(self, callee, args, kws, n):
        return V()

    b_staticmethod = b_classmethod = b_property

    # ---- callbacks ------------------------------------------------------------------------------------------
    def run_callbacks(self, args: list, kws: dict, result: V, recv: Optional[V]) -> None:
        from .pyfe import FuncInfo, HANDLE_NAMES
        cbs = []
        for a in list(args) + list(kws.values()):
            if a.kind == "func" and isinstance(a.fn, FuncInfo) and (a.meta is None or a.meta.get("self") is None):
                key = id(a.fn.node)
                if key in self.cb_done or a.fn.qual in self.called and not a.fn.is_lambda:
                    continue
                cbs.append(a.fn)
        for fi in cbs[:4]:
            self.cb_done.add(id(fi.node))
            lab = U(result.all_labels() if result is not None else EMPTY, recv.all_labels() if recv is not None else EMPTY)
            src = U(result.all_src() if result is not None else EMPTY, recv.all_src() if recv is not None else EMPTY)
            params = list(fi.node.args.posonlyargs) + list(fi.node.args.args)
            vals = []
            for p in params:
                nm = p.arg
                if re.fullmatch(r"(request|req|http_request|event|evt|e|ev|msg|message|data|payload|body|params|input|chunk|buf|buffer)", nm) and nm not in ("e",):
                    vals.append(self.param_value(p, None, None))
                elif nm in HANDLE_NAMES or nm in ("res", "reply", "next", "done", "cb", "callback", "err", "error", "ws", "socket", "stream"):
                    vals.append(V(c=UNK, kind="obj"))
                else:
                    vals.append(V(c=HOLE, labels=lab, src=src, lines=frozenset({getattr(fi.node, "lineno", 0)})))
            try:
                self.call_user(fi, vals, {}, fi.node)
            except Exception:
                pass


VALIDATED_LABEL = "VALIDATED"

JS_SPECIAL = {
    "builtins.__require__": "js_require",
    "js.require": "js_require",
    "js.eval": "js_vm", "js.Function": "js_function_ctor", "js.setTimeout": "js_timer", "js.setInterval": "js_timer", "js.setImmediate": "js_timer",
    "vm.runInNewContext": "js_vm", "vm.runInThisContext": "js_vm", "vm.runInContext": "js_vm", "vm.Script": "js_vm", "vm.compileFunction": "js_vm",
    "child_process.exec": "js_exec", "child_process.execSync": "js_exec",
    "child_process.spawn": "js_spawn", "child_process.spawnSync": "js_spawn", "child_process.execFile": "js_spawn", "child_process.execFileSync": "js_spawn",
    "child_process.fork": "js_spawn",
    "fs.readFileSync": "js_fs_read", "fs.readFile": "js_fs_read", "fs.createReadStream": "js_fs_read", "fs.readFileAsync": "js_fs_read",
    "fs.writeFileSync": "js_fs_write", "fs.writeFile": "js_fs_write", "fs.appendFileSync": "js_fs_write", "fs.appendFile": "js_fs_write", "fs.createWriteStream": "js_fs_write",
    "fs.unlinkSync": "js_fs_delete", "fs.unlink": "js_fs_delete", "fs.rmSync": "js_fs_delete", "fs.rm": "js_fs_delete", "fs.rmdirSync": "js_fs_delete", "fs.rmdir": "js_fs_delete",
    "rimraf": "js_fs_delete", "rimraf.sync": "js_fs_delete", "fs-extra.removeSync": "js_fs_delete", "fs-extra.remove": "js_fs_delete", "del": "js_fs_delete", "del.sync": "js_fs_delete",
    "fs-extra.readFileSync": "js_fs_read", "fs-extra.writeFileSync": "js_fs_write",
    "fs.chmodSync": "js_fs_chmod", "fs.chmod": "js_fs_chmod",
    "fs.readdirSync": "js_fs_list", "fs.readdir": "js_fs_list",
    "js.fetch": "js_fetch", "node-fetch": "js_fetch", "node-fetch.default": "js_fetch", "cross-fetch": "js_fetch", "isomorphic-fetch": "js_fetch", "undici.fetch": "js_fetch",
    "axios": "js_axios", "axios.get": "js_axios", "axios.post": "js_axios", "axios.put": "js_axios", "axios.patch": "js_axios", "axios.delete": "js_axios",
    "axios.request": "js_axios", "axios.head": "js_axios", "request": "js_axios", "request.get": "js_axios", "request.post": "js_axios", "request.put": "js_axios",
    "got": "js_axios", "got.get": "js_axios", "got.post": "js_axios", "got.put": "js_axios", "superagent.get": "js_axios", "superagent.post": "js_axios",
    "needle.get": "js_axios", "needle.post": "js_axios", "needle": "js_axios", "node-fetch": "js_fetch", "ky": "js_axios", "ky.get": "js_axios", "ky.post": "js_axios",
    "http.request": "js_http_request", "https.request": "js_http_request", "http.get": "js_http_request", "https.get": "js_http_request",
    "js.XMLHttpRequest": "js_xhr_new", "js.WebSocket": "js_ws_new", "ws.WebSocket": "js_ws_new", "ws": "js_ws_new", "js.navigator.sendBeacon": "js_beacon",
    "net.connect": "js_net_connect", "net.createConnection": "js_net_connect", "tls.connect": "js_net_connect",
    "dns.lookup": "js_dns", "dns.resolve": "js_dns", "dns.resolve4": "js_dns", "dns.resolveTxt": "js_dns", "dns.promises.lookup": "js_dns",
    "js.atob": "js_atob", "js.btoa": "js_btoa", "js.Buffer.from": "js_buffer_from", "zlib.gunzipSync": "js_zlib", "zlib.inflateSync": "js_zlib", "zlib.unzipSync": "js_zlib",
    "js.localStorage.getItem": "js_storage_get", "js.sessionStorage.getItem": "js_storage_get",
    "js.parseInt": "js_parse_num", "js.parseFloat": "js_parse_num", "js.Number": "js_parse_num",
    "os.homedir": "js_os_homedir", "os.tmpdir": "js_os_tmpdir", "path.join": "js_path_join", "path.resolve": "js_path_join",
    "js.JSON.stringify": "js_json_stringify", "js.JSON.parse": "js_json_parse", "js.encodeURIComponent": "js_encode_uri", "js.encodeURI": "js_encode_uri",
    "js.process.exit": "js_exit", "js.console.log": "js_noop", "js.console.error": "js_noop", "js.console.warn": "js_noop", "js.console.info": "js_noop",
    "js.String": "s_js_string",
}
