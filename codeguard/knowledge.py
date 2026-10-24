"""Knowledge classifiers: hosts, paths, packages, secrets.  Pure functions, no I/O at call time.

Everything here is *analysis*, not a blocklist lookup: hosts are classified structurally (numeric forms,
suffixes, reserved ranges), paths by semantic role, package names by edit-distance/homoglyph reasoning
against a popularity list plus structural install-source checks.
"""
from __future__ import annotations

import ipaddress
import math
import os
import re
from functools import lru_cache
from typing import Optional

from .events import HOLE

_HERE = os.path.dirname(os.path.abspath(__file__))
RULES_DIR = os.path.join(os.path.dirname(_HERE), "rules")


# ======================================================================================== hosts
_SUSPICIOUS_WORDS = re.compile(
    r"(attacker|evil|malicious|malware|exfil|badguy|hacker|hackme|c2\b|c2[-.]|[-.]c2|\bcnc\b|steal|stealer|pwn|phish|"
    r"backdoor|beacon|leak|payload|trojan|rogue|shady|badsite|collector|dropzone|loot|ransom)", re.I)
_DROPSITES = re.compile(
    r"(discord(app)?\.com|hooks\.slack\.com|webhook\.site|requestbin|pipedream|ngrok|serveo|localtunnel|"
    r"pastebin|paste\.ee|hastebin|ghostbin|transfer\.sh|anonfiles|file\.io|0x0\.st|temp\.sh|"
    r"interact\.sh|oast\.|burpcollaborator|canarytokens|dnslog|requestcatcher|telegram\.org|api\.telegram|"
    r"termbin|ix\.io|webhook\.|hookbin|beeceptor|mockbin)", re.I)
_INTERNAL_SUFFIX = (".internal", ".local", ".lan", ".corp", ".intranet", ".home.arpa", ".svc", ".cluster.local", ".localdomain", ".private")
_META_NAMES = {"metadata.google.internal", "metadata", "instance-data", "metadata.azure.com", "kubernetes.default.svc",
               "kubernetes.default", "metadata.tencentyun.com", "metadata.packet.net"}
_META_IPS = {"169.254.169.254", "169.254.170.2", "100.100.100.200", "192.0.0.192", "fd00:ec2::254", "169.254.169.123"}


def _parse_int_host(h: str) -> Optional[int]:
    try:
        if re.fullmatch(r"0[xX][0-9a-fA-F]+", h):
            return int(h, 16)
        if re.fullmatch(r"0[0-7]+", h):
            return int(h, 8)
        if re.fullmatch(r"\d{1,10}", h):
            v = int(h)
            return v if v < 2 ** 32 else None
    except ValueError:
        return None
    return None


def _parse_ipv4_loose(h: str) -> Optional[ipaddress.IPv4Address]:
    """Parse dotted forms with octal/hex segments and short forms as browsers/libc do."""
    parts = h.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    nums = []
    for p in parts:
        if not p:
            return None
        try:
            if re.fullmatch(r"0[xX][0-9a-fA-F]+", p):
                nums.append(int(p, 16))
            elif re.fullmatch(r"0[0-7]+", p):
                nums.append(int(p, 8))
            elif re.fullmatch(r"\d+", p):
                nums.append(int(p))
            else:
                return None
        except ValueError:
            return None
    try:
        if len(nums) == 1:
            val = nums[0]
        else:
            if any(n > 255 for n in nums[:-1]):
                return None
            last_bytes = 5 - len(nums)
            if nums[-1] >= 256 ** last_bytes:
                return None
            val = 0
            for n in nums[:-1]:
                val = (val << 8) | n
            val = (val << (8 * last_bytes)) | nums[-1]
        if val >= 2 ** 32:
            return None
        return ipaddress.IPv4Address(val)
    except ValueError:
        return None


def classify_ip(ip) -> str:
    s = str(ip)
    if s in _META_IPS:
        return "META"
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return classify_ip(ip.ipv4_mapped)
    if ip.is_loopback or s in ("0.0.0.0", "::"):
        return "LOOPBACK"
    if ip.is_link_local:
        return "LINKLOCAL"
    if ip.is_private or ip.is_reserved or getattr(ip, "is_site_local", False):
        return "PRIVATE"
    return "EXTERNAL_IP"


def split_url(url: str):
    """Return (scheme, host, port, path) from a (possibly partial) URL.  host may contain HOLE."""
    m = re.match(r"^\s*(?:([a-zA-Z][a-zA-Z0-9+.\-]*)://)?(?:[^/@?#\s]*@)?(\[[^\]]*\]|[^/:?#\s]*)(?::(\d+|" + HOLE + r"+))?([/?#].*)?$", url, re.S)
    if not m:
        return None, None, None, None
    return (m.group(1) or "").lower(), m.group(2), m.group(3), m.group(4) or ""


@lru_cache(maxsize=4096)
def classify_host(host: str) -> str:
    """META | LINKLOCAL | LOOPBACK | PRIVATE | INTERNAL | SUSPICIOUS | DROPSITE | EXTERNAL | EXTERNAL_IP | USER"""
    if not host:
        return "UNKNOWN"
    h = host.strip().strip("[]").lower().rstrip(".")
    if HOLE in h:
        return "USER"
    if h in _META_NAMES:
        return "META"
    if h == "localhost" or h.endswith(".localhost") or h == "ip6-localhost":
        return "LOOPBACK"
    try:
        ip = ipaddress.ip_address(h.split("%")[0])
        return classify_ip(ip)
    except ValueError:
        pass
    if re.fullmatch(r"[0-9a-fx.]+", h):
        ip4 = _parse_ipv4_loose(h)
        if ip4 is not None:
            return classify_ip(ip4)
        n = _parse_int_host(h)
        if n is not None:
            return classify_ip(ipaddress.IPv4Address(n))
    if h.endswith(_INTERNAL_SUFFIX):
        return "META" if h.endswith("metadata.google.internal") else "INTERNAL"
    if "." not in h:
        return "INTERNAL"
    if _DROPSITES.search(h):
        return "DROPSITE"
    if _SUSPICIOUS_WORDS.search(h):
        return "SUSPICIOUS"
    return "EXTERNAL"


def host_of_url(url: str) -> tuple[str, str, str]:
    """-> (scheme, host, host_class) for a URL skeleton."""
    scheme, host, _port, _path = split_url(url or "")
    if host is None:
        return "", "", "UNKNOWN"
    return scheme, host, classify_host(host)


DANGEROUS_SCHEMES = {"gopher", "file", "dict", "ldap", "ldaps", "tftp", "sftp", "jar", "netdoc", "php", "expect", "data"}


# ======================================================================================== paths
def _norm_path(p: str) -> str:
    p = p.strip().replace("\\", "/")
    p = re.sub(r"^\$\{?HOME\}?", "~", p)
    p = re.sub(r"^(%USERPROFILE%|%HOMEPATH%|\$env:USERPROFILE)", "~", p, flags=re.I)
    p = re.sub(r"^/(home|Users)/[^/]+(?=/|$)", "~", p)
    p = re.sub(r"^/root(?=/|$)", "~", p) if not p.startswith("/root/..") else p
    p = re.sub(r"/{2,}", "/", p)
    if "/../" in p and p.startswith("/") and HOLE not in p:      # '/srv/app/../../etc/shadow' really means /etc/shadow
        import posixpath
        p = posixpath.normpath(p)
    return p


_SECRET_PATH = [
    r"(^|/)\.aws/(credentials|config|sso)", r"(^|/)\.ssh/(id_[a-z0-9]+|identity|[a-z0-9_.-]*\.pem|[a-z0-9_.-]*_key)$",
    r"(^|/)\.ssh/?$", r"(^|/)\.docker/config\.json", r"(^|/)\.kube/(config|cache)", r"(^|/)\.netrc$", r"(^|/)_netrc$",
    r"(^|/)\.npmrc$", r"(^|/)\.pypirc$", r"(^|/)\.pgpass$", r"(^|/)\.git-credentials$", r"(^|/)\.config/(gcloud|gh|hub|doctl|heroku)",
    r"(^|/)\.azure/", r"(^|/)\.gnupg", r"(^|/)\.config/git/credentials", r"(^|/)\.my\.cnf$", r"(^|/)\.s3cfg$", r"(^|/)\.boto$",
    r"^/etc/(shadow|gshadow|master\.passwd)", r"^/etc/ssh/ssh_host_[a-z0-9_]+_key$", r"^/etc/(ssl|pki)/private",
    r"(^|/)\.env(\.[a-z0-9_.-]+)?$", r"(^|/)[a-z0-9_.-]+\.env$", r"(^|/)id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$".replace("(\\.pub)?", ""),
    r"\.(pem|key|p12|pfx|jks|keystore|ppk|kdbx|asc)$", r"(^|/)(credentials?|secrets?|tokens?|passwords?|apikeys?)(\.[a-z]+)?$",
    r"(^|/)(secrets?|credentials?)[._-][a-z0-9._-]*\.(json|ya?ml|txt|ini|conf|toml|env)$", r"(^|/)(client_)?secrets?\.(json|ya?ml)$",
    r"(^|/)service[-_]?account[a-z0-9._-]*\.json$", r"(^|/)(kubeconfig|vault[-_]?token|\.vault-token)$",
    r"^/proc/(self|\d+)/(environ|cmdline|maps|mem)$", r"(^|/)(Login Data|Cookies|Web Data|logins\.json|key[34]\.db|cookies\.sqlite|Local State)$",
    r"Library/Keychains", r"(^|/)wallet\.dat$", r"(^|/)(Chrome|Firefox|Brave|Edge)/.*(User Data|Profiles)",
    r"(^|/)\.terraform/.*\.tfstate", r"(^|/)terraform\.tfstate", r"(^|/)\.config/(rclone|filezilla)", r"(^|/)\.mozilla/", r"(^|/)\.password-store",
]
_SECRET_PATH_RE = [re.compile(x, re.I) for x in _SECRET_PATH]
_SYSSENS = re.compile(r"^(/etc/(passwd|group|hosts\.allow|sudoers\.d/.*)$|/var/log/(auth|secure|syslog|messages)|/etc/mysql/|/etc/ssh/sshd_config$)|(^|/)\.(bash|zsh|mysql|psql|python)_history$|(^|/)\.viminfo$", re.I)
_PERSIST = re.compile(
    r"(^|/)(etc/cron[a-z.]*|var/spool/cron|etc/crontab|etc/anacrontab|etc/systemd/system|lib/systemd|usr/lib/systemd|\.config/systemd/user|etc/init\.d|etc/rc\.local|etc/rc[0-6S]\.d|"
    r"etc/profile(\.d)?|etc/environment|etc/ld\.so\.preload|etc/xdg/autostart|\.config/autostart|etc/inittab|etc/at\.|Library/(LaunchAgents|LaunchDaemons|StartupItems)|"
    r"\.bashrc|\.bash_profile|\.bash_login|\.bash_logout|\.profile|\.zshrc|\.zprofile|\.zshenv|\.zlogin|\.cshrc|\.config/fish/config\.fish|\.xinitrc|\.xsessionrc|\.ssh/authorized_keys2?|"
    r"\.git/hooks/|\.git/config$|etc/pam\.d/|etc/motd|etc/update-motd\.d|etc/bash\.bashrc|etc/skel|usr/local/bin/|Start Menu/Programs/Startup|Startup/|"
    r"AppData/Roaming/Microsoft/Windows/Start Menu|Windows/System32/Tasks|\.vimrc|\.config/nvim/init|\.npmrc|sitecustomize\.py|usercustomize\.py|\.pth$)", re.I)
_PRIVFILE = re.compile(r"^(/etc/(sudoers(\.d/[^/]+)?|doas\.conf|sudo\.conf|passwd-?|shadow-?|group|gshadow|security/.*|polkit-1/.*|pam\.d/[^/]+))$", re.I)
_DEVICE = re.compile(r"^/dev/(sd[a-z]\d*|hd[a-z]\d*|vd[a-z]\d*|xvd[a-z]\d*|nvme\d+n\d+(p\d+)?|mmcblk\d+(p\d+)?|disk\d+|mapper/.*|md\d+|loop\d+|dm-\d+|sr\d+|rdisk\d+)$")
_DEVSRC = re.compile(r"^/dev/(zero|urandom|random|full|null)$")
_SYSTEM_DIRS = ("/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/var", "/opt", "/sys", "/proc", "/dev", "/root", "/home", "/srv", "/mnt", "/media", "/Users", "/System", "/Library", "/Applications", "/Windows", "/Program Files")
_TEMP = re.compile(r"^(/tmp|/var/tmp|/dev/shm|%TEMP%|\$TMPDIR|~/\.cache/tmp)(/|$)", re.I)
_USER_DOC = re.compile(r"^~/(Documents|Desktop|Downloads|Pictures|Music|Videos|Projects|Code|work|\.git|src|repos)(/|$)", re.I)


def classify_path(path: str) -> set:
    """Set of semantic path classes."""
    out: set = set()
    if not path:
        return out
    if HOLE in path:
        out.add("DYNAMIC")
        if path.startswith(HOLE):
            out.add("USER_PATH")
    p = _norm_path(path)
    pl = p.rstrip("/") if len(p) > 1 else p
    for rx in _SECRET_PATH_RE:
        if rx.search(p):
            out.add("SECRET_STORE")
            break
    if _SYSSENS.search(p):
        out.add("SYSTEM_SENSITIVE")
    if _PERSIST.search(p):
        out.add("PERSIST")
    if _PRIVFILE.search(p):
        out.add("PRIVFILE")
    if _DEVICE.match(p):
        out.add("DEVICE")
    if _DEVSRC.match(p):
        out.add("DEVSRC")
    if _TEMP.match(p):
        out.add("TEMP")
    # broadness for deletion semantics
    q = pl
    if re.fullmatch(r"(/|/\*|/\.\*|~|~/\*|~/|\*|/\.|\.\./\.\.|C:/?|C:/\*|C:/Windows(/System32)?/?)", q, re.I) or q in ("", "/*", "~/*"):
        out.add("ROOT")
    elif q.startswith("/"):
        for d in _SYSTEM_DIRS:
            if q == d or q == d + "/*" or q.startswith(d + "/") and q.count("/") <= 1:
                out.add("SYSTEM_DIR")
        top = re.match(r"^/[^/]+", q)
        if top and q.count("/") == 1:
            out.add("SYSTEM_DIR")
    if re.match(r"^/(etc|boot|bin|sbin|lib|lib64|sys|proc|dev|root)/[^/]+|^/usr/(bin|sbin|lib|lib64|libexec)/[^/]+|^[A-Za-z]:/Windows/System32/[^/]+", q, re.I):
        out.add("SYSTEM_FILE")         # a file that belongs to the operating system itself
    if q.startswith("~") and q.count("/") <= 1:
        out.add("HOME_DIR")
    if _USER_DOC.match(p):
        out.add("USER_DATA")
    if q.endswith("/*") or q.endswith("/.*") or q.endswith("/**") or q == "*":
        out.add("WILDCARD")
    if re.search(r"(^|/)\.\.(/|$)", p):
        out.add("TRAVERSAL")
    if re.search(r"\.git(/|$)", p):
        out.add("GIT")
    if re.search(r"^/var/log(/|$)|^/var/adm(/|$)|(^|/)\.(bash|zsh)_history$|^/var/(run|log)/(wtmp|btmp|lastlog|utmp)", p):
        out.add("LOGS")
    if re.search(r"(/|^)(var/lib/(mysql|postgresql|docker)|var/lib/.*\.db$|.*\.(db|sqlite3?|mdb)$)", p, re.I):
        out.add("DATABASE")
    return out


def is_secret_path(path: str) -> bool:
    return "SECRET_STORE" in classify_path(path)


# ======================================================================================== secrets
_PLACEHOLDER = re.compile(
    r"^(\s*|<[^>]*>|\{\{.*\}\}|\$\{?[A-Za-z_]\w*\}?|%\(.*\)s|%s|x{3,}|\*{3,}|\.{3,}|changeme|change[-_ ]?me|change[-_ ]?this|"
    r"your[-_ ].*|my[-_ ]?(secret|password|token|key).*|insert[-_ ].*|put[-_ ].*|replace[-_ ].*|todo|tbd|none|null|nil|undefined|"
    r"example|dummy|placeholder|sample|test|testing|password|secret|token|api[-_]?key|key|username|user|admin|"
    r"enter[-_ ].*|xxx+|redacted|\[redacted\]|env|environment|n/a|na)\s*$", re.I)

TOKEN_PATTERNS = [
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|AIPA|ABIA|ACCA)[0-9A-Z]{16}\b"), 0.92),
    ("slack_token", re.compile(r"\bxox[abprso]-[A-Za-z0-9-]{10,}"), 0.92),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,})"), 0.92),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{16,}"), 0.92),
    ("stripe_key", re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{12,}"), 0.92),
    ("stripe_test_key", re.compile(r"\b[sr]k_test_[0-9a-zA-Z]{12,}"), 0.7),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{30,}"), 0.9),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"), 0.95),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{6,}"), 0.8),
    ("openai_key", re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_\-]{24,}"), 0.88),
    ("sendgrid_key", re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}"), 0.9),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{30,}"), 0.9),
    ("hf_token", re.compile(r"\bhf_[A-Za-z0-9]{30,}"), 0.9),
    ("telegram_bot_token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_\-]{34,36}\b"), 0.85),
    ("twilio_key", re.compile(r"\bSK[0-9a-f]{32}\b"), 0.85),
    ("azure_storage_key", re.compile(r"AccountKey=[A-Za-z0-9+/=]{40,}"), 0.9),
    ("basic_auth_url", re.compile(r"[a-z][a-z0-9+.\-]*://[^/\s:@'\"]{1,40}:[^/\s@'\"]{3,}@[A-Za-z0-9.\-]+"), 0.8),
    ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]{24,}=*"), 0.75),
]
_SECRET_NAME_LAST = {"password", "passwd", "pwd", "secret", "secrets", "token", "apikey", "credential", "credentials", "passphrase",
                     "pass", "bearer", "apitoken", "authtoken", "accesstoken", "secretkey", "privatekey", "accesskey", "clientsecret"}
_SECRET_NAME_PAIRS = {("api", "key"), ("access", "key"), ("secret", "key"), ("private", "key"), ("auth", "key"), ("client", "secret"),
                      ("auth", "token"), ("access", "token"), ("api", "token"), ("api", "secret"), ("signing", "key"), ("encryption", "key"),
                      ("master", "key"), ("license", "key"), ("session", "key"), ("bot", "token"), ("refresh", "token"), ("secret", "access", "key")}


def _name_tokens(name: str) -> list:
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return [t for t in re.split(r"[^A-Za-z0-9]+", name.lower()) if t]


def secret_like_name(name: str) -> bool:
    toks = _name_tokens(name)
    if not toks:
        return False
    if toks[-1] in _SECRET_NAME_LAST:
        return True
    if len(toks) >= 2 and (toks[-2], toks[-1]) in _SECRET_NAME_PAIRS:
        return True
    if len(toks) >= 3 and (toks[-3], toks[-2], toks[-1]) in _SECRET_NAME_PAIRS:
        return True
    return False


_ENV_SECRET = re.compile(r"(secret|token|passw|pwd|api[_-]?key|apikey|private|credential|auth|access[_-]?key|session[_-]?key|bearer|cookie|jwt|signing|encryption[_-]?key|_key$|^key$|ssh|github_pat|gh_token|(?:database|db|redis|mongo(?:db)?|postgres(?:ql)?|mysql|amqp|broker|sqlalchemy_database)[a-z_]*(?:url|uri|dsn)$|connection[_-]?string|conn[_-]?str)", re.I)


def secret_like_env(name: str) -> bool:
    return bool(_ENV_SECRET.search(name or ""))


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def is_placeholder(v: str) -> bool:
    return bool(_PLACEHOLDER.match(v or ""))


_SEGMENT_SPLIT = re.compile(r"[\s/?&=:@,;\"'<>()\[\]{}|]+")
_KEYISH_BEFORE = re.compile(r"(?:key|token|secret|passw(?:or)?d|pwd|auth|signature|sig|credential)[\w\-]*\s*[=:]\s*[\"']?$", re.I)


def _decodes_to_content(seg: str) -> bool:
    """An encoded payload (readable text or compressed data once decoded) is obfuscation, not a credential: a random token decodes to noise."""
    import base64
    import zlib
    try:
        raw = base64.b64decode(seg + "=" * (-len(seg) % 4), validate=True)
    except Exception:
        return False
    if not raw:
        return False
    try:
        zlib.decompress(raw)
        return True
    except Exception:
        pass
    return sum(32 <= b < 127 or b in (9, 10, 13) for b in raw) / len(raw) >= 0.85


def embedded_secret(value: str) -> tuple:
    """Local entropy spike inside a longer string (a token in a URL query, a header value, a connection string).  Global entropy misses these because the
    surrounding words dilute the score, so the string is cut at its delimiters and each piece is judged on its own: 24-64 characters, mixed upper/lower/digits,
    high character entropy, and not a hash, UUID, path or word list.  A piece that follows a key-like name (api_key=...) needs less evidence."""
    if len(value) < 24 or len(value) > 2000 or value.startswith("data:"):
        return ()
    pos = 0
    for seg in _SEGMENT_SPLIT.split(value):
        start = value.find(seg, pos) if seg else pos
        pos = start + len(seg)
        if not (20 <= len(seg) <= 64) or not seg.isascii():
            continue
        if re.fullmatch(r"[0-9a-fA-F]+", seg) or re.fullmatch(r"[0-9a-fA-F\-]{32,36}", seg) or is_placeholder(seg):
            continue
        if _decodes_to_content(seg):
            continue
        classes = sum(bool(re.search(rx, seg)) for rx in ("[a-z]", "[A-Z]", "[0-9]"))
        ent = shannon_entropy(seg)
        keyed = bool(_KEYISH_BEFORE.search(value[max(0, start - 24):start]))
        if classes >= 3 and (ent >= 4.1 or (keyed and ent >= 3.6)) and not re.search(r"[A-Za-z]{12,}", seg.replace("_", " ").replace("-", " ")) :
            return 0.8, "embedded_high_entropy_token"
    return ()


def literal_secret(name: str, value: str) -> tuple[float, str]:
    """Judge a string literal bound to `name`.  Returns (confidence, kind) or (0,'')."""
    if not isinstance(value, str) or HOLE in value:
        return 0.0, ""
    for kind, rx, w in TOKEN_PATTERNS:
        if rx.search(value):
            return w, kind
    emb = embedded_secret(value)
    if emb:
        return emb
    if re.fullmatch(r"(AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9_]{6,}", (value or "").strip()):
        return 0.7, "aws_key_like"       # an AWS access-key-id shape is a credential whatever the variable is called
    if not name or not secret_like_name(name):
        return 0.0, ""
    if re.fullmatch(r"(AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9_]{6,}", value.strip()):
        return 0.7, "aws_key_like"       # an access-key-id shape bound to a key-like name, even if it reads like a sample
    v = value.strip()
    if len(v) < 6 or len(v) > 400 or "\n" in v:
        return 0.0, ""
    if is_placeholder(v) or re.fullmatch(r"[A-Z][A-Z0-9_]{3,}", v) and secret_like_name(v) is True:
        return 0.0, ""
    if v.startswith(("http://", "https://")) and "@" not in v:
        return 0.0, ""
    if re.fullmatch(r"[a-z][a-z0-9_\-]*", v) and len(v) < 10 and v in ("password", "secret", "token"):
        return 0.0, ""
    if os.sep in v and " " not in v and v.count("/") >= 2 and not re.search(r"[A-Za-z0-9+/]{30,}", v):
        return 0.0, ""   # a path, not a secret
    if re.fullmatch(r"[\d.\-_/:]+", v):
        return 0.0, ""     # OIDs, versions, dates, ports - not secrets
    ent = shannon_entropy(v)
    if len(v) >= 20 and ent >= 3.6:
        return 0.88, "high_entropy_secret"
    if len(v) >= 12 and ent >= 3.2 and re.search(r"[A-Za-z]", v) and re.search(r"\d", v):
        return 0.8, "hardcoded_credential"
    return 0.62, "hardcoded_password"


# ======================================================================================== packages
def _load_list(fn: str) -> set:
    out: set = set()
    try:
        with open(os.path.join(RULES_DIR, fn), encoding="utf-8") as f:
            for line in f:
                if line.startswith("#"):
                    continue
                out.update(t.lower() for t in line.split())
    except OSError:
        pass
    return out


_POP = {"pypi": None, "npm": None}


def _pop(eco: str) -> set:
    if _POP[eco] is None:
        _POP[eco] = _load_list("pkg_pypi.txt" if eco == "pypi" else "pkg_npm.txt")
    return _POP[eco]


def norm_pkg(name: str) -> str:
    n = name.strip().lower()
    n = re.sub(r"\[.*?\]", "", n)
    n = re.sub(r"[_.]+", "-", n)
    return n


_HOMOGLYPH = [("rn", "m"), ("vv", "w"), ("cl", "d"), ("0", "o"), ("1", "l"), ("l", "i"), ("5", "s"), ("3", "e")]


def _dl(a: str, b: str, limit: int = 2) -> int:
    """Damerau-Levenshtein (optimal string alignment), early-exit above `limit`."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2 = None
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[-1]


def _keyboard_squash(s: str) -> str:
    s = s.replace("-", "")
    for a, b in _HOMOGLYPH:
        s = s.replace(a, b)
    return re.sub(r"(.)\1+", r"\1", s)


_TOP_N_TARGETS = 3000          # the most downloaded projects are the ones squatters imitate
_PKG_INDEX: dict = {}
_RANK: dict = {}
_TOP_EXACT = 300                  # a difference only in the last letter (plural / missing letter) is a squat only of a very well known name


def _top_pypi() -> list:
    out = []
    try:
        with open(os.path.join(RULES_DIR, "pkg_pypi_top.txt"), encoding="utf-8") as f:
            for line in f:
                if line.strip() and not line.startswith("#"):
                    out.append(norm_pkg(line))
    except OSError:
        pass
    return out


def _deletes(w: str, k: int) -> set:
    """All strings reachable from w by deleting up to k characters (symmetric-delete index: two names within edit distance k share one)."""
    out = {w}
    frontier = {w}
    for _ in range(k):
        nxt = set()
        for x in frontier:
            for i in range(len(x)):
                nxt.add(x[:i] + x[i + 1:])
        out |= nxt
        frontier = nxt
    return out


def _base_names(eco: str) -> set:
    return _pop(eco)


def _pkg_index(eco: str) -> tuple:
    """-> (known names, target names, delete index, squash index). Built once, lazily."""
    if eco in _PKG_INDEX:
        return _PKG_INDEX[eco]
    base = _pop(eco)
    top = _top_pypi() if eco == "pypi" else []
    known = set(base) | set(top)
    _RANK[eco] = {p: i for i, p in enumerate(top)}
    targets = set(base) | set(top[:_TOP_N_TARGETS])
    index: dict = {}
    squash: dict = {}
    for p in targets:
        if len(p) < 4:
            continue
        for v in _deletes(p, 1 if len(p) < 12 else 2):
            index.setdefault(v, []).append(p)
        squash.setdefault(_keyboard_squash(p), []).append(p)
        squash.setdefault(p.replace("-", ""), []).append(p)
    _PKG_INDEX[eco] = (known, targets, index, squash)
    return _PKG_INDEX[eco]


@lru_cache(maxsize=4096)
def package_reputation(name: str, eco: str = "pypi") -> tuple[str, str]:
    """-> (verdict, detail). verdict in POPULAR | TYPOSQUAT | UNKNOWN.
    A name is POPULAR if it is one of the ~15,000 most downloaded projects; it is a TYPOSQUAT if it is within a small edit distance of a very popular
    one (or equal to it after folding look-alike characters / separators) and is not itself a known project."""
    n = norm_pkg(name)
    known, targets, index, squash = _pkg_index(eco)
    if n in known or n.lstrip("@") in known:
        return "POPULAR", n
    if n.startswith("@") and "/" in n:  # scoped npm package: judge the scope-less part loosely
        return "UNKNOWN", ""
    if len(n) < 4 or len(n) > 64 or n.startswith("types-") or n.endswith("-stubs"):
        return "UNKNOWN", ""
    best = None
    cands = set()
    for v in _deletes(n, 2):
        cands.update(index.get(v, ()))
    for p in cands:
        if abs(len(p) - len(n)) > 2 or len(p) < 5:
            continue
        d = _dl(n, p, 2)
        lim = 1 if len(p) < 12 else 2
        if d == 1 and (n[:-1] == p or p[:-1] == n or (len(n) == len(p) and n[:-1] == p[:-1])) and p not in _base_names(eco) and _RANK.get(eco, {}).get(p, 0) >= _TOP_EXACT:
            continue
        if 0 < d <= lim and (best is None or d < best[0]):
            best = (d, p)
    nsq = _keyboard_squash(n)
    for key in (nsq, n.replace("-", "")):
        for p in squash.get(key, ()):
            if p != n and len(p) >= 4 and (best is None or best[0] > 1):
                best = (1, p)
    if best:
        return "TYPOSQUAT", best[1]
    # popular name decorated with a suspicious affix
    if n.endswith(("-fix", "-hotfix", "-patch", "-secure", "-free", "-pro", "-crypto", "-miner", "-updater", "-dev-tools")):
        stem = re.sub(r"-(fix|hotfix|patch|secure|free|pro|crypto|miner|updater|dev-tools)$", "", n)
        if len(stem) >= 5 and stem in targets:
            return "TYPOSQUAT", stem
    # combosquatting: the name of a very popular package followed only by 'trust' words (requests-v2-auth, numpy-official, flask-secure-login)
    toks = [t for t in re.split(r"[-]+", n) if t]
    if len(toks) >= 2 and toks[0] in targets and _RANK.get(eco, {}).get(toks[0], 10 ** 9) < 1500 and len(toks[0]) >= 4:
        rest = toks[1:]
        if all(t in _COMBO_WORDS or re.fullmatch(r"v?\d+", t) for t in rest) and any(t in _COMBO_STRONG or re.fullmatch(r"v\d+", t) for t in rest):
            return "TYPOSQUAT", toks[0]
    return "UNKNOWN", ""


# words squatters add to a popular name to look official; ordinary plugin names (pytest-cov, flask-cors, django-filter) use other words and are not touched
_COMBO_WORDS = frozenset({"v2", "v3", "v4", "new", "official", "secure", "security", "auth", "authentication", "login", "oauth", "pro", "plus", "free", "crypto", "helper", "helpers",
                          "update", "updater", "fix", "hotfix", "patch", "mirror", "latest", "premium", "enterprise", "beta", "lite", "extra", "extended", "improved", "fast", "faster", "real", "original"})

_COMBO_STRONG = frozenset({"v2", "v3", "v4", "new", "official", "pro", "plus", "free", "latest", "premium", "original", "real", "mirror", "updater", "hotfix", "fix", "patch"})

_PKG_SPEC = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._\-]*(?:\[[^\]]*\])?)\s*(?:(===|==|~=|!=|<=|>=|<|>|@)\s*(.*))?$")


def parse_pkg_spec(spec: str) -> dict:
    """pip/npm requirement specifier -> {name, pinned, url, vcs, version}"""
    s = spec.strip().strip("'\"")
    info = {"name": s, "pinned": False, "url": False, "vcs": False, "local": False, "version": ""}
    if re.match(r"^(git\+|hg\+|svn\+|bzr\+)", s) or re.match(r"^(github:|gitlab:|bitbucket:)", s) or s.endswith(".git") or "git://" in s:
        info.update(vcs=True, url=True)
        m = re.search(r"[#&]egg=([A-Za-z0-9._\-]+)", s)
        info["name"] = m.group(1) if m else s
        info["pinned"] = bool(re.search(r"@[0-9a-f]{7,40}\b", s) or re.search(r"#[0-9a-f]{40}", s))
        return info
    if re.match(r"^[a-z][a-z0-9+.\-]*://", s, re.I):
        info.update(url=True)
        info["name"] = s
        return info
    if s.startswith(("./", "/", "../", "~", ".")) or s.endswith((".whl", ".tar.gz", ".tgz", ".zip")):
        info.update(local=True)
        info["name"] = s
        return info
    if re.fullmatch(r"[\w.\-]+/[\w.\-]+(#.*)?", s) and not s.startswith("@"):  # npm user/repo shorthand
        info.update(vcs=True, url=True)
        return info
    m = _PKG_SPEC.match(s)
    if m:
        info["name"] = m.group(1)
        if m.group(2) in ("==", "===", "@"):
            info["pinned"] = True
            info["version"] = (m.group(3) or "").strip()
        elif m.group(2):
            info["version"] = (m.group(3) or "").strip()
    else:
        # npm style name@version
        m2 = re.match(r"^(@?[^@\s]+)@(.+)$", s)
        if m2:
            info["name"] = m2.group(1)
            info["version"] = m2.group(2)
            info["pinned"] = bool(re.fullmatch(r"v?\d+(\.\d+){0,3}([\-+][\w.]+)?", m2.group(2)))
    return info

# ---------------------------------------------------------------------------------------------- provider secret formats
# Data adapted from gitleaks (MIT) by scripts/import_gitleaks.py: ~220 provider-specific credential formats with keyword prefilters.
_PROVIDER = {"rules": None, "kw_re": None}


def _load_provider_rules() -> None:
    import json
    p = os.path.join(RULES_DIR, "secret_patterns.json")
    rules = []
    try:
        data = json.load(open(p, encoding="utf-8"))["rules"]
    except Exception:
        data = []
    kws = set()
    for r in data:
        try:
            rx = re.compile(r["regex"], re.I if r["flags"] else 0)
        except re.error:
            continue
        rules.append((r["id"], rx, tuple(r["keywords"]), float(r.get("entropy") or 0)))
        kws.update(k for k in r["keywords"] if k)
    _PROVIDER["rules"] = rules
    _PROVIDER["kw_re"] = re.compile("|".join(re.escape(k) for k in sorted(kws, key=len, reverse=True))) if kws else None


def provider_secret(line: str):
    """-> (rule_id, secret_text) for the first provider credential format found on the line, else None."""
    if _PROVIDER["rules"] is None:
        _load_provider_rules()
    kw = _PROVIDER["kw_re"]
    if kw is None or len(line) > 4000:
        return None
    low = line.lower()
    found = set(kw.findall(low))
    if not found:
        return None
    for rid, rx, kws_, ent in _PROVIDER["rules"]:
        if kws_ and not (found & set(kws_)):
            continue
        m = rx.search(line)
        if not m:
            continue
        secret = m.group(m.lastindex) if m.lastindex else m.group(0)
        if not secret or is_placeholder(secret) or (ent and shannon_entropy(secret) < ent):
            continue
        return rid, secret
    return None
