"""Behaviour motifs: small multi-step patterns over the *API calls* a Python program makes (structural, never executed).

Single calls are weak evidence; a few specific calls that only make sense together are strong.  Each motif below is a set of
API roles (e.g. "connect a socket" + "duplicate it onto stdin/stdout" + "start a shell") resolved through the program's own
import aliases, so renaming imports does not hide it.  The idea of auditing code as a *combination of capabilities* comes from
public malware-audit tools such as hexora and from MITRE ATT&CK technique descriptions; the implementation is ours.
Every motif emits a MOTIF event; rules/motifs.rules.yaml decides category and weight.
"""
from __future__ import annotations

import ast

from .astutil import walk_all
import re

from .ctx import Ctx
from .events import Event

# ---------------------------------------------------------------------------------------------- API role tables
SOCKET_NEW = {"socket.socket", "socket.create_connection"}
SHELL_START = {"pty.spawn", "os.system", "os.popen", "subprocess.call", "subprocess.run", "subprocess.Popen", "subprocess.check_call", "subprocess.check_output"}
NET_DOWNLOAD = {"requests.get", "requests.post", "requests.request", "urllib.request.urlopen", "urllib.request.urlretrieve", "urllib.urlopen", "urllib.urlretrieve",
                "urllib2.urlopen", "httpx.get", "wget.download", "http.client.HTTPSConnection", "http.client.HTTPConnection", "urllib3.request", "pycurl.Curl"}
NET_SEND = {"requests.post", "requests.put", "requests.get", "requests.request", "requests.patch", "urllib.request.urlopen", "urllib.urlopen", "urllib2.urlopen",
            "httpx.post", "httpx.get", "http.client.HTTPSConnection", "http.client.HTTPConnection", "ftplib.FTP", "ftplib.FTP_TLS", "smtplib.SMTP", "smtplib.SMTP_SSL",
            "socket.create_connection", "socket.socket", "telnetlib.Telnet", "paramiko.SSHClient", "urllib3.request"}
RUN_PROGRAM = {"subprocess.call", "subprocess.run", "subprocess.Popen", "subprocess.check_call", "subprocess.check_output", "os.system", "os.startfile", "os.popen",
               "os.execv", "os.execve", "os.execl", "os.spawnl", "os.spawnv", "ctypes.windll.shell32.ShellExecuteW", "ctypes.windll.shell32.ShellExecuteA"}
EXEC_SUFFIX = (".exe", ".dll", ".so", ".dylib", ".bin", ".ps1", ".bat", ".cmd", ".scr", ".cpl", ".msi", ".jar", ".sh", ".apk", ".vbs", ".hta")
FINGERPRINT = {"platform.node", "platform.system", "platform.release", "platform.version", "platform.platform", "platform.machine", "platform.processor", "platform.uname",
               "platform.architecture", "getpass.getuser", "os.getlogin", "os.getcwd", "os.uname", "os.getuid", "socket.gethostname", "socket.gethostbyname", "socket.getfqdn",
               "uuid.getnode", "os.cpu_count", "psutil.cpu_count", "psutil.virtual_memory", "psutil.net_if_addrs", "netifaces.interfaces", "getmac.get_mac_address",
               "os.environ.get", "os.getenv", "sys.platform", "sys.version", "locale.getdefaultlocale"}
KEYLOG = {"pynput.keyboard.Listener", "keyboard.on_press", "keyboard.hook", "keyboard.record", "keyboard.add_hotkey", "keyboard.wait", "pyxhook.HookManager",
          "ctypes.windll.user32.GetAsyncKeyState", "ctypes.windll.user32.SetWindowsHookExA", "ctypes.windll.user32.SetWindowsHookExW", "ctypes.windll.user32.GetKeyState",
          "win32api.GetAsyncKeyState", "pynput.mouse.Listener"}
SCREEN = {"PIL.ImageGrab.grab", "ImageGrab.grab", "pyautogui.screenshot", "pyscreenshot.grab", "mss.mss", "d3dshot.create", "pygetwindow.getAllWindows", "cv2.VideoCapture",
          "pyautogui.locateOnScreen", "win32gui.GetWindowDC"}
CLIPBOARD = {"pyperclip.paste", "win32clipboard.GetClipboardData", "clipboard.paste", "tkinter.Tk.clipboard_get", "pyclip.paste", "xerox.paste"}
BROWSER_API = {"browser_cookie3.chrome", "browser_cookie3.firefox", "browser_cookie3.edge", "browser_cookie3.opera", "browser_cookie3.brave", "browser_cookie3.load",
               "browser_cookie3.safari", "browser_cookie3.chromium", "win32crypt.CryptUnprotectData"}
INJECT_API = {"OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx", "QueueUserAPC", "SetThreadContext",
              "NtWriteVirtualMemory", "NtAllocateVirtualMemory", "RtlCreateUserThread", "LoadLibraryA", "LoadLibraryW", "ResumeThread", "NtUnmapViewOfSection", "GetProcAddress"}
SHELLCODE_LOAD = {"VirtualAlloc", "VirtualProtect", "RtlMoveMemory", "CreateThread", "CFUNCTYPE", "memmove", "WaitForSingleObject", "mmap", "mprotect", "from_buffer",
                  "cast", "WINFUNCTYPE", "PROT_EXEC"}
OBFUSCATOR_MARKERS = re.compile(r"\bpyarmor(_runtime\w*)?\b|__pyarmor__|\bblankobf\b|\bobfuscated\s+by\b|\bhyperion\b|\bpyobfuscate\b|_obfuscator_\b|__obfuscator__", re.I)
BROWSER_PATH = re.compile(r"login data|local state|web data|user data[\\/]|[\\/]cookies(\.sqlite)?\b|logins\.json|key[34]\.db|places\.sqlite|\bleveldb\b|[\\/]tdata\b|wallet\.dat|"
                          r"exodus|metamask|nkbihfbeogaeaoehlefnkodbefgpgknn|keystore|electrum|\.solana|atomic[\\/]|discordcanary|discordptb|Network[\\/]Cookies", re.I)
CHAT_WEBHOOK = re.compile(r"discord(app)?\.com/api/webhooks/|api\.telegram\.org/bot|hooks\.slack\.com/services/", re.I)   # ordinary notification endpoints: only a drop point when sensitive data is sent
LOCAL_DATA = re.compile(r"os\.environ|getenv|environ\b|open\(|\.read\(|expanduser|/etc/|id_rsa|\.ssh|\.aws|passw|secret|token|credential|api_?key", re.I)
WEBHOOK = re.compile(r"discord(app)?\.com/api/webhooks/|api\.telegram\.org/bot|hooks\.slack\.com/services/|webhook\.site|pastebin\.com/api|transfer\.sh|ngrok(-free)?\.(io|app|dev)|requestbin|pipedream\.net|oast\.(pro|live|site|fun)|interact\.sh|burpcollaborator", re.I)
HEXESC = re.compile(r"(?:\\x[0-9a-fA-F]{2}){16,}")


def _dotted(node) -> str:
    """a.b.c -> 'a.b.c'; mss.mss().grab -> 'mss.mss().grab'; anything else -> ''."""
    parts = []
    while True:
        if isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        elif isinstance(node, ast.Call):
            inner = _dotted(node.func)
            if not inner:
                return ""
            parts.append(inner + "()")
            return ".".join(reversed(parts))
        elif isinstance(node, ast.Name):
            parts.append(node.id)
            return ".".join(reversed(parts))
        else:
            return ""


class _Index:
    """Resolved call list: (lineno, canonical dotted name, node)."""

    def __init__(self, tree: ast.AST):
        self.alias: dict = {}
        for n in walk_all(tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    self.alias[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
                    if a.asname is None and "." in a.name:
                        self.alias[a.name.split(".")[0]] = a.name.split(".")[0]
            elif isinstance(n, ast.ImportFrom) and n.module:
                for a in n.names:
                    self.alias[a.asname or a.name] = f"{n.module}.{a.name}"
        self.calls: list = []
        self.names: set = set()
        for n in walk_all(tree):
            if isinstance(n, ast.Call):
                d = self.canon(n.func)
                if d:
                    self.calls.append((n.lineno, d, n))
            if isinstance(n, ast.Attribute):
                self.names.add(n.attr)
            elif isinstance(n, ast.Name):
                self.names.add(n.id)

    def canon(self, func) -> str:
        d = _dotted(func)
        if not d:
            return ""
        head, _, rest = d.partition(".")
        base = self.alias.get(head, head)
        return base + ("." + rest if rest else "")

    def has(self, names) -> list:
        return [(ln, d) for ln, d, _n in self.calls if d in names or d.split(".")[-1] in {x.split(".")[-1] for x in names if "." not in x}]

    def lines(self, names) -> list:
        return sorted({ln for ln, d, _n in self.calls if d in names})


def _str_consts(tree: ast.AST):
    for n in walk_all(tree):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            yield n.lineno, n.value
        elif isinstance(n, ast.JoinedStr):
            txt = "".join(v.value for v in n.values if isinstance(v, ast.Constant) and isinstance(v.value, str))
            if txt:
                yield n.lineno, txt


def scan_motifs(tree: ast.AST, ctx: Ctx, source: str = "") -> None:
    ix = _Index(tree)

    def emit(kind: str, lines, **extra) -> None:
        lines = sorted({int(x) for x in lines if x})
        if not lines:
            return
        ctx.emit(Event(cap="MOTIF", line=lines[0], name=kind, target=extra.pop("target", kind), flags={"motif_" + kind} | set(extra.pop("flags", ())), lines=set(lines), extra=extra))

    # ------------------------------------------------------------------------------------------ reverse shell
    sock_lines = ix.lines(SOCKET_NEW)
    connects = [n.lineno for n in walk_all(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in ("connect", "connect_ex")]
    dup2 = [ln for ln, d, n in ix.calls if d == "os.dup2" and len(n.args) >= 2 and isinstance(n.args[1], ast.Constant) and n.args[1].value in (0, 1, 2)]
    pty = ix.lines({"pty.spawn"})
    shell_strs = [ln for ln, s in _str_consts(tree) if re.search(r"(^|[\s/])(/bin/)?(ba|z|k|c|da)?sh(\s+-i)?$|/dev/tcp/|nc\s+(-\w+\s+)*-e\b|mkfifo", s.strip())]
    redirected = []
    for ln, d, n in ix.calls:
        if d in SHELL_START:
            for kw in n.keywords:
                if kw.arg in ("stdin", "stdout", "stderr") and isinstance(kw.value, (ast.Name, ast.Call)):
                    redirected.append(ln)
    if (sock_lines and (connects or sock_lines)) and (len(dup2) >= 2 or (pty and (connects or dup2)) or (redirected and connects and shell_strs)):
        emit("reverse_shell", sock_lines[:1] + connects[:1] + dup2[:3] + pty[:1] + redirected[:1] + shell_strs[:1])
    elif connects and len(dup2) >= 2:
        emit("reverse_shell", connects[:1] + dup2[:3])
    elif any("/dev/tcp/" in s for _l, s in _str_consts(tree)):
        emit("reverse_shell", [ln for ln, s in _str_consts(tree) if "/dev/tcp/" in s][:2])

    # ------------------------------------------------------------------------------------------ downloader / dropper
    dl_calls = [(ln, d, n) for ln, d, n in ix.calls if d in NET_DOWNLOAD or d.endswith((".urlretrieve", "urlretrieve"))]
    exe_urls = []
    for ln, s in _str_consts(tree):
        low = s.lower().split("?")[0].split("#")[0]
        if low.endswith(EXEC_SUFFIX) and ("/" in low or "\\" in low or low.count(".") == 1):
            exe_urls.append((ln, s))
    url_exe = [(ln, s) for ln, s in exe_urls if re.match(r"https?://", s, re.I)]
    runs = ix.lines(RUN_PROGRAM)
    writes_bin = [n.lineno for n in walk_all(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in ("write", "write_bytes", "copyfileobj", "save")]
    tmp_use = any(x in (source or "") for x in ("NamedTemporaryFile", "gettempdir", "/tmp/", "mkstemp", "%TEMP%", "\\Temp\\", "TemporaryDirectory"))
    if dl_calls and (url_exe or exe_urls) and (writes_bin or any("urlretrieve" in d for _l, d, _n in dl_calls)):
        emit("binary_download", [dl_calls[0][0]] + [x[0] for x in (url_exe or exe_urls)[:2]] + writes_bin[:1] + (runs[:1] if runs else []), flags={"executed"} if runs else set())
    elif dl_calls and writes_bin and runs and tmp_use:
        emit("download_and_run", [dl_calls[0][0]] + writes_bin[:1] + runs[:1], flags={"executed"})
    elif any("urlretrieve" in d for _l, d, _n in dl_calls) and tmp_use and runs:
        emit("download_and_run", [dl_calls[0][0]] + runs[:1], flags={"executed"})

    # ------------------------------------------------------------------------------------------ install-time hooks
    hook_bases = {"install", "develop", "egg_info", "build_py", "sdist", "bdist_wheel", "build_ext", "easy_install", "bdist_egg", "install_lib", "install_scripts"}
    for cls in [n for n in walk_all(tree) if isinstance(n, ast.ClassDef)]:
        bases = {(_dotted(b).split(".")[-1]) for b in cls.bases}
        if not (bases & hook_bases):
            continue
        inner = _Index(cls)
        names = inner.calls
        has_net = [ln for ln, d, _n in names if d in NET_SEND or d in NET_DOWNLOAD]
        has_exec = [ln for ln, d, _n in names if d in RUN_PROGRAM or d in ("exec", "eval", "builtins.exec", "builtins.eval", "os.system")]
        has_env = [ln for ln, d, _n in names if d in ("os.environ.get", "os.getenv") or d in FINGERPRINT]
        if has_net or has_exec:
            emit("install_hook", [cls.lineno] + has_net[:2] + has_exec[:2] + has_env[:1], flags={"net"} if has_net else {"exec"})
    # ------------------------------------------------------------------------------------------ process injection
    inj = {d.split(".")[-1] for _l, d, _n in ix.calls} & INJECT_API
    inj |= ix.names & {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC", "NtWriteVirtualMemory"}
    if len(inj) >= 2 and (inj & {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx", "QueueUserAPC", "NtWriteVirtualMemory", "SetThreadContext"}):
        lines = [ln for ln, d, _n in ix.calls if d.split(".")[-1] in INJECT_API]
        emit("process_injection", lines[:4] or [1])

    # ------------------------------------------------------------------------------------------ keylogger / screen / clipboard / browser data
    kl = ix.lines(KEYLOG)
    if kl or (ix.names & {"on_press", "GetAsyncKeyState", "SetWindowsHookEx"} and "pynput" in ix.alias.values()):
        emit("keylogger", kl[:3] or [1])
    sc = [ln for ln, d, _n in ix.calls if d in SCREEN or d.endswith(("ImageGrab.grab", "mss.mss", "mss.mss().grab")) or d.startswith("mss.mss()")]
    if sc:
        emit("screen_capture", sc[:3])
    cb = ix.lines(CLIPBOARD)
    if cb:
        emit("clipboard_read", cb[:3])
    bw = ix.lines(BROWSER_API)
    bp = [ln for ln, s in _str_consts(tree) if BROWSER_PATH.search(s)]
    if bw:
        emit("browser_data", bw[:3])
    elif bp and any(re.search(r"open|copy|read|sqlite3|shutil|listdir|walk|glob", d) for _l, d, _n in ix.calls):
        emit("browser_data", bp[:3], flags={"path"})

    # ------------------------------------------------------------------------------------------ host fingerprint collection + network use
    fp = sorted({d for _l, d, _n in ix.calls if d in FINGERPRINT and d not in ("os.environ.get", "os.getenv", "os.getcwd", "os.cpu_count")})
    fp += [d for _l, d, _n in ix.calls if d in ("os.getcwd",)][:1]
    fp_attr = [n.lineno for n in walk_all(tree) if isinstance(n, ast.Attribute) and _dotted(n) in ("sys.platform", "sys.version")]
    net = ix.lines(NET_SEND)
    if len(set(fp)) >= 3 and net:
        emit("fingerprint_exfil", [ln for ln, d, _n in ix.calls if d in FINGERPRINT][:4] + net[:2], count=len(set(fp)))

    # ------------------------------------------------------------------------------------------ shellcode / packed payload
    esc_lines = [n.lineno for n in walk_all(tree) if isinstance(n, ast.Constant) and isinstance(n.value, (bytes, str)) and len(n.value) >= 24 and
                 (HEXESC.search(source.split("\n")[n.lineno - 1] if source and n.lineno - 1 < len(source.split("\n")) else "") is not None or _dense_binary(n.value))]
    int_lists = [n.lineno for n in walk_all(tree) if isinstance(n, (ast.List, ast.Tuple)) and len(n.elts) >= 48 and all(isinstance(e, ast.Constant) and isinstance(e.value, int) and 0 <= e.value <= 255 for e in n.elts)]
    loaders = ix.names & SHELLCODE_LOAD
    if (esc_lines or int_lists) and (len(loaders & {"VirtualAlloc", "VirtualProtect", "CFUNCTYPE", "RtlMoveMemory", "CreateThread", "memmove", "mmap", "PROT_EXEC", "mprotect"}) >= 1):
        emit("shellcode", (esc_lines + int_lists)[:2] + [ln for ln, d, _n in ix.calls if d.split(".")[-1] in SHELLCODE_LOAD][:2], flags={"loader"})
    elif esc_lines or int_lists:
        names = {n.id.lower() for n in walk_all(tree) if isinstance(n, ast.Name)}
        if any("shellcode" in x or "payload" in x for x in names):
            emit("shellcode", (esc_lines + int_lists)[:2], flags={"named"})

    # ------------------------------------------------------------------------------------------ typosquatted imports
    import sys
    from . import knowledge as K
    stdlib = set(getattr(sys, "stdlib_module_names", ()))
    local = {n.name for n in walk_all(tree) if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
    for n in walk_all(tree):
        mods = []
        if isinstance(n, ast.Import):
            mods = [a.name.split(".")[0] for a in n.names]
        elif isinstance(n, ast.ImportFrom) and n.module and n.level == 0:
            mods = [n.module.split(".")[0]]
        for m in mods:
            if m in stdlib or m in local or len(m) < 5 or m.startswith("_"):
                continue
            verdict, similar = K.package_reputation(m, "pypi")
            if verdict == "TYPOSQUAT":
                emit("import_typosquat", [n.lineno], target=m, similar=similar)

    # ------------------------------------------------------------------------------------------ obfuscator markers
    for i, line in enumerate((source or "").split("\n"), 1):
        if len(line) < 400 and OBFUSCATOR_MARKERS.search(line):
            emit("obfuscator_marker", [i], target=OBFUSCATOR_MARKERS.search(line).group(0))
            break

    # ------------------------------------------------------------------------------------------ out-of-band webhook / bot / tunnel destinations
    wh = [ln for ln, s in _str_consts(tree) if WEBHOOK.search(s) and (not CHAT_WEBHOOK.search(s) or LOCAL_DATA.search(source or ""))]
    if wh and (net or ix.has({"requests.post"})):
        emit("exfil_channel", wh[:2] + net[:1], target=WEBHOOK.search(next(s for ln, s in _str_consts(tree) if WEBHOOK.search(s) and (not CHAT_WEBHOOK.search(s) or LOCAL_DATA.search(source or "")))).group(0))


def _dense_binary(v) -> bool:
    """A literal that is mostly non-printable bytes/characters (packed code, not text)."""
    try:
        data = v if isinstance(v, bytes) else v.encode("latin-1", "ignore")
    except Exception:
        return False
    if len(data) < 24:
        return False
    nonprint = sum(1 for b in data if b < 9 or 13 < b < 32 or b > 126)
    return nonprint / len(data) > 0.6
