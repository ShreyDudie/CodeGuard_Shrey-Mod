# CodeGuard — Hackathon Master Plan (PS3) — v2 (adaptive, self-built)

> **IMPLEMENTATION STATUS (read first).** Built and working: language ID; Python + JavaScript abstract interpreter; bash, SQL, YAML,
> Markdown and generic front-ends; 182 YAML rules; fusion + plain-English reasons; `@guarded` interception + `demo/intercept_check.py`;
> FastAPI `/scan` `/batch` `/health` `/metrics` + UI; eval + robustness tests. Dev-42: precision 1.0, recall 1.0, 0 FP (rules only).
> **ML (built, narrow):** from-scratch byte 5-gram naturalness LM (`codeguard/ml/`, `models/lm_py.npz`) used as a gated obfuscation signal.
> **Not built (deliberately):** the synthetic attack-data generator and supervised attack classifiers described in §5 — writing large attack-style corpora is
> off-limits here and 42 labelled rows cannot validate a classifier. The "Shadow World" is realised as the abstract interpreter (no real
> execution, taint/const-prop, counterfactual probes, loop multiplicity), not a full virtual OS. See README.md for what ships.

Goal: win the "real-time pre-execution safety layer for LLM-generated code" track.
Ranking is **relative on a hidden ~160-snippet set** (~200 total, ~20% = the 42-row dev sample), with pass/fail floors. Order of priorities: never fail a floor → accuracy on verdict AND categories (incl. benign look-alikes and multi-category snippets) → latency/efficiency → demo polish.

**Design stance (v2):** no static keyword blocklist, no wrapping of existing scanners, no pretrained weights. We *take inspiration* from existing tools (listed in §10, credited, never imported) and build our own: a behaviour-based analysis engine whose rules are **data, not code**, that **generalise by capability** instead of by string, and **learn** from a generator we write ourselves. All ML is trained by us from scratch on CPU. No API calls of any kind.

**Pre-execution proof (v2.1):** the problem asks us to *show* that code is wrong/dangerous **before it runs**, in plain language. Pattern-matching alone doesn't "show" anything, so we add a **Shadow World** (§4.5): a virtual computer inside our own process (fake filesystem, fake network, fake process table, fake package index) that the code is *interpreted against, never executed on the real OS*. We watch what it *would* do (files it would delete, hosts it would call, secrets it would read), measure the blast radius, probe it with hostile inputs, and also catch plain bugs (undefined names, bad arguments, empty-variable `rm -rf "$DIR/"`). Every verdict then comes with a simple-English explanation of what would happen. Real sandboxes are rejected on purpose: `rm -rf` in a real sandbox is still a real risk.

## 0. Hard rules (floors — violating any = disqualified)
1. Response schema exactly as the problem statement (see §3). Endpoint ALWAYS returns valid schema JSON — global try/except → fail-closed `block` with a valid body. Never a 500.
2. **No LLM / external API call anywhere** (not even for data generation). `.env.example` contains no keys. Our own small models are allowed and encouraged.
3. **Never execute submitted code on the real OS** — not in a subprocess, not in a "sandbox", not with `exec`/`eval`. We *interpret* it inside the Shadow World (§4.5), where every dangerous call is a recorded no-op on in-memory objects. Only the single controlled demo pair really executes, only inside `demo/intercept_check.py`.
4. **No hard-coded answers**: no dev ids, no verbatim dev snippets/hashes in code, rules, or training data. Dev-42 is a *test set only*. No verbatim patterns copied from public datasets.
5. Interception demo works live on our laptop: blocked snippet ⇒ marker file never appears; allowed snippet ⇒ marker appears.
6. CPU only, Python 3.10+. Disclose AI-coding-assistant use in README. List every third-party component + licence (kept deliberately tiny, §10).
7. Fake secrets / `*.example` hosts only in all test content.

## 1. What the dev data tells us
42 rows (`codeguard_dev.jsonl`): `code, language, category, label, rationale, id`. Hidden set is the same generator family (≈4× larger, harder multi-category items — one dev row, `cg_multi_0001`, previews that style).

- **Languages**: python (majority), bash, javascript, yaml, markdown, sql. Must degrade gracefully to anything else (php, ruby, go, powershell, java, c, dockerfile, json, …) — "works for all languages" is an explicit wish.
- **Verdict**: `label=1` ⇒ `block`, `0` ⇒ `allow`. ~33% benign **look-alikes** — FPs cost as much as misses.
- **Benign look-alikes seen** (must be *understood*, not string-matched): constants-only f-string SQL + parameterised execute · `ast.literal_eval` · `setattr` behind allowlist · `crontab -l` · thread pool bounded by `MAX_WORKERS` · `~/.config/<app>/settings.json` · POST of non-sensitive event to app's own API · pinned correctly-spelled package · allowlisted partner host actually enforced · plain explanatory comments · policy docstring that merely *mentions* `password = 'hunter2'` · `DELETE … WHERE id = ?`.
- **Multi-label** rows exist (`"resource_exhaustion, ssrf_network_exfil, dependency_risk"`). Never early-exit; output every category that fires.
- **Label conventions** (absorbed by data-driven category heads, kept in `config/conventions.yaml` so they are flippable in one place):
  | Behaviour | Dataset category |
  |---|---|
  | SQL injection on SELECT (string-built query from input) | `data_exfiltration` |
  | SQL injection on DELETE/UPDATE | `destructive_command` |
  | tainted input → shell (`shell=True`, `os.system`) | `destructive_command` |
  | `eval/exec` on tainted data (even inside a property) | `destructive_command` |
  | `compile`+`eval`; dynamic `__import__('sub'+'process')`; `exec(getsource())`; aliased `import os as o`; `shelve/pickle` on untrusted path | `obfuscated_execution` |
  | reading cloud/docker/ssh credential stores (+ sending) | `secret_access` (+ `data_exfiltration`) |
  | hardcoded provider token/key | `secret_access` |
  | ICMP/DNS/webhook/POST exfil | `data_exfiltration` |
  | `gopher://` to internal Redis, IMDS 169.254.169.254, redirect past allowlist | `ssrf_network_exfil` |
  | systemd unit / sudoers / crontab write | `persistence_or_privesc` |
  | uncapped `dd`, 50k sockets, unbounded busy-loop threads | `resource_exhaustion` |
  | typosquat / untrusted VCS dependency | `dependency_risk` |
  | instruction aimed at an AI reader (comment, tool description, CI yaml, md HTML comment) | `ai_targeted_instructions` |
  Rationales cite MITRE ATT&CK (T1048, T1485, T1552, T1059, T1543, T1548, T1499, T1195, T1090, T1027, T1620) and `AML.T0054` → used as the tag vocabulary for rule metadata.
- Snippets are 10–40 lines, helper-structured; the dangerous call is buried in a helper, constants live at module level, payloads are aliased/split/encoded. ⇒ analysis must be **inter-procedural over constants and names**, not per-line.

## 2. Winning thesis — "detect capabilities and intent, not strings"
1. **Common behaviour IR.** Every language front-end lowers code into one language-neutral event graph (§4.2). Rules are written once over the IR, so a rule for "secret → network" fires for Python `requests.post`, JS `fetch`, bash `curl -d`, SQL `COPY … PROGRAM`, YAML `run:` steps, and unseen languages via the fallback front-end. That is how we cover "all languages".
2. **Rules are data, hot-reloadable, and composable.** Behaviour signatures live in `rules/*.yaml` (small DSL: sources, sinks, guards, sanitizers, quantifiers, tags). Adding/tuning rules never needs a code change; the engine reloads on file change. Rules reference *capability classes* (e.g. `NET_SEND`, `SECRET_STORE`), not API names.
3. **Capability ontology with fuzzy/learned resolution.** An API-semantics table maps thousands of names → capability classes (hierarchical: library → module → function). For *unknown* callables we run a learned **identifier→capability classifier** (subword n-gram model trained by us over names + arg shapes) so `post_telemetry()`, `ship_logs_to()`, `phone_home()` resolve to `NET_SEND` even though no one listed them.
4. **Provenance/taint lattice instead of keywords.** Values carry labels (`CONST`, `USER_INPUT`, `ENV`, `SECRET`, `FILE_SENSITIVE`, `NET_DATA`, `DECODED`, `HOST_INTERNAL/EXTERNAL/META`…). Verdicts depend on *what flows where*, e.g. `ENV[SECRET] → NET_SEND(external host)`; benign twins differ only by label (const SQL pieces vs tainted; allowlisted host vs metadata IP).
5. **Guard/sanitizer reasoning ("safety proofs").** First-class negative evidence: parameterised queries, enforced allowlists (checked on the *final* URL, not a decoy), bounded loops/pools, read-only variants, pinned+exact package names, safe loaders. Proofs subtract risk only if they are *dominating* the sink (on the path), which kills the "decoy check" trick (allowlist validates URL A, request goes to B).
6. **Intent-vs-effect consistency.** Compare declared intent (identifiers, docstrings, comments: "cleanup", "health check", "metrics") with actual effects. A mismatch is itself a risk feature (e.g. `def log_event` that reads `~/.ssh`).
7. **Deobfuscation to fixpoint.** Normaliser decodes base64/hex/rot13/`chr()`/`\x`/`+`-concat/`''.join`/f-string const folding/`getattr`-with-built-name/zero-width + homoglyph unicode, recursively (depth-bounded), and *re-parses decoded payloads as code in the detected language*. Scans raw + normalised views with a line map.
8. **Self-built data engine.** A behaviour-spec-driven program generator (§5) renders the same behaviour into 6+ languages with random style, composes multi-category files, mutates/obfuscates semantics-preservingly, and always emits a **benign twin**. Labels are correct *by construction* ⇒ unlimited, diverse, license-clean training/testing data.
9. **Models trained by us, from scratch** (§5.3): hashed n-gram linear heads, a gradient-boosted head over IR features, a tiny char-level conv/transformer, a benign-code language model (naturalness/obfuscation signal), and a tiny identifier→capability model. No pretrained weights.
10. **Continuous self-improvement loop** (§8): fuzz → find misses/FPs → cluster → *rule induction* proposes new YAML signatures → we review → retrain. Dev-42 stays frozen for honest reporting.
11. **Calibrated cascade with explanations.** Fast path (<5 ms) decides most; heavier models run only in the ambiguous band; every verdict has `reason` + `vulnerable_lines`.
13. **Shadow World dry-run** (§4.5): interpret the code against a virtual OS to *observe* effects before anything runs — blast-radius numbers, empty-variable disasters, loop-cost estimates, hostile-input probing.
14. **Plain-English proof**: every verdict says what the code does, why it's a problem, and what would happen if it ran, in words a non-expert understands (§3).
12. **Real interception** with decorator / context-manager / exec+subprocess wrappers / API middleware / CLI pre-hook, all fail-closed, with a TOCTOU-safe hash check.

## 3. I/O contract (from the problem statement — fixed)
Request (any of: HTTP POST, CLI, function call): `{"code": "..."}`. Extra fields ignored; missing/non-string `code` ⇒ treated as empty, still valid response.

Response (all five required to be present for the schema floor; the last two are optional but we always send them):
```json
{
  "verdict": "allow | block",
  "risk_score": 0.0-1.0,
  "categories": ["secret_access", "..."],
  "code_language": "python",
  "reason": "string",
  "vulnerable_lines": [12, 14]
}
```
- `verdict`: exactly `"allow"` or `"block"`.
- `risk_score`: float in [0,1], calibrated; allow-cases low (<0.3), clear attacks high (>0.8).
- `categories`: subset of the **nine exact strings**: `secret_access, data_exfiltration, destructive_command, persistence_or_privesc, obfuscated_execution, dependency_risk, resource_exhaustion, ssrf_network_exfil, ai_targeted_instructions`. `[]` when allow. Block ⇒ at least one category (fallback to top-scoring).
- `code_language`: lowercase name; dev languages `python|bash|javascript|markdown|yaml|sql` must be ~100% right; others from a wider set (`typescript, powershell, php, ruby, go, java, c, cpp, csharp, dockerfile, json, toml, …`, else `unknown`).
- `reason`: **simple-terms explanation**, 2–3 short sentences, no jargon, built from a template: *what the code does* → *why that's a problem* → *what would happen if it ran* → (technical tag in brackets at the end). Never empty on `block`; on `allow` one short sentence on why it looks safe.
- `vulnerable_lines`: sorted 1-indexed ints relative to the **submitted string** (dev snippets start with a blank line — don't strip before numbering). Point at the *dangerous call and the line where the bad value was created*, not every line.

**Example outputs (default mode = exactly the fixed schema, nothing extra):**
```json
{"verdict":"block","risk_score":0.97,
 "categories":["secret_access","data_exfiltration"],
 "code_language":"python",
 "reason":"This code opens the user's AWS credentials file and posts its contents to a web address outside the company. That would hand someone else the keys to the cloud account. [T1552, T1048]",
 "vulnerable_lines":[8,17]}

{"verdict":"allow","risk_score":0.04,
 "categories":[],
 "code_language":"python",
 "reason":"This code deletes one order by its id using a safe, parameterised query, so it can't be tricked into deleting more.",
 "vulnerable_lines":[]}

{"verdict":"block","risk_score":0.99,
 "categories":["dependency_risk","ssrf_network_exfil","resource_exhaustion"],
 "code_language":"python",
 "reason":"This code installs 'colourama' (a look-alike of the real 'colorama' package), asks the cloud's internal metadata service for server credentials, then starts 400 endless threads. Together that can install malware, steal server keys and freeze the machine. [T1195, T1552.005, T1499]",
 "vulnerable_lines":[6,15,26]}
```
**Verbose mode** (`?verbose=1` / UI / CLI `--explain`; never on by default so the judge's schema check stays exact) adds `explanation` with: `plain_summary`, `what_would_happen[]` (shadow-world observations), `problems[]` (non-security bugs/errors found, §4.5.5), `blast_radius`, `evidence[]` (rule hits, proofs, model probs), `fix_hint`.
- **Batch endpoint** (required in scope): `POST /batch` takes a list of snippets (`[{"code":..}]` or `{"items":[{"id":..,"code":..}]}`), returns the per-sample schema objects in order (echo `id` if given). Also `GET /health`.
- The judge calls our endpoint once per hidden snippet, live ⇒ no per-request model cold starts, bounded latency, thread-safe.

## 4. Architecture

### 4.1 Pipeline (cascade)
```
{"code": ...}
 ├─ G   Guardrails: size cap, time budget (~150 ms), encoding sanitise, any error ⇒ fail-closed valid response
 ├─ N   Language ID (own scorer: shebang, syntax-probe parses, token-class histogram, learned char-gram classifier)
 ├─ D   Deobfuscation fixpoint → raw view + normalised view(s) + line map
 ├─ F   Front-end lowering (per language, own lexers/parsers) → Behaviour IR
 ├─ A   Analysis passes over IR: constant/alias propagation, call-graph, taint/provenance, guard-dominance, loop-bound analysis, host classification
 ├─ S   Shadow World dry-run (§4.5): interpret code against a virtual OS ⇒ observed effects, blast radius, probe results, defects
 ├─ R   Rule engine: YAML signatures matched over IR *and* shadow observations ⇒ evidence {category, weight, lines, why, tags}
 ├─ M   Models (only for ambiguous band or as co-voters): n-gram heads, IR-feature GBDT, tiny neural, LM-naturalness, AI-instruction classifier
 ├─ X   Fusion + calibration: noisy-OR over rule evidence, minus dominated safety proofs, blended with model probs; per-category thresholds
 └─ E   Explain: reason + vulnerable_lines from evidence spans
```
Hard-block evidence (confirmed secret→external sink, IMDS fetch, decode→exec, `curl|sh` from non-allowlisted host, live-looking provider key) sets a floor models can't lower; models may raise suspicion and are the tie-breaker in the ambiguous band. Analysis timeouts degrade to the token-level fallback, never to "allow by default".

### 4.2 Behaviour IR (the core idea)
Nodes = **operations** with typed, labelled operands:
`READ_FILE, WRITE_FILE, DELETE, EXEC_SHELL, EXEC_PROC, EVAL_CODE, LOAD_MODULE, DESERIALIZE, NET_SEND, NET_FETCH, NET_LISTEN, DNS/ICMP_SEND, SQL_EXEC, INSTALL_PKG, SPAWN_THREAD/PROC, ALLOC, LOOP, SLEEP, ENV_READ, PRIV_CHANGE, PERSIST_WRITE, COMMENT/STRING_TEXT, CONFIG_DIRECTIVE` …
Operands carry: constant value (if foldable), provenance labels, host class, path class, bound info, source line span.
Front-ends:
- **Python**: stdlib `ast` (part of the language, not a scanner) + our alias/const/taint engine, call-graph through helpers, class properties, comprehensions-as-loops, decorators, `__import__`/`importlib`/`getattr` resolution.
- **Bash/sh**: our own tokenizer/parser (quotes, `$()`, backticks, pipes, redirects, heredocs, functions, `for/while`, `&`), variable expansion with const-prop; detect fork bombs, `curl|sh`, `/dev/tcp`, `eval $(…)`.
- **JavaScript/TS**: our own lexer + light recursive-descent over statements/calls/members/template literals (enough for calls, assignments, requires/imports, async fetch, `eval`/`Function`, `child_process`, `process.env`).
- **SQL**: our own tokenizer + statement classifier (DDL/DML/DCL, presence of WHERE/LIMIT, dynamic `EXEC`/`PREPARE`, file/program functions, stored-proc bodies, sleep/benchmark/cartesian, UNION/OR 1=1 shapes, privilege statements).
- **YAML**: PyYAML-free tiny parser *or* stdlib-only subset (we write; falls back to line-based) → schema-aware lowering for CI (GitHub Actions/GitLab/CircleCI), k8s, docker-compose, ansible: `run:` blocks are re-lowered as bash; `uses:` pinned? ; privileged/hostPath/etc.; comments + string values emitted as `TEXT` nodes.
- **Markdown**: line/fence/HTML-comment parser; fenced code re-lowered by its info-string language (or by Language ID); hidden text (HTML comments, zero-width, `display:none`, tiny font), link/image beacons; all prose → `TEXT`.
- **Generic fallback** (any other language / parse failure): tokenizer-level lowering using the capability ontology on identifiers + string literals + CLI-like command lines, so PHP/Ruby/Go/PowerShell/etc. still get source→sink-ish reasoning at coarse granularity.

### 4.3 Rule DSL (data-driven, dynamic)
Example (illustrative — authoring format, not final):
```yaml
- id: exfil.secret_to_external
  category: data_exfiltration
  tags: [T1048, T1041]
  match:
    sink:   {cap: NET_SEND, host: [EXTERNAL, UNKNOWN]}
    source: {label: [SECRET, ENV_SECRET, FILE_SENSITIVE, SQLI_RESULT]}
    flow:   source -> sink.payload   # transitive via helpers/assignments
  unless:
    - sink.host in app_own_hosts      # derived, not listed: constants named *_ENDPOINT/API used for app logging etc.
    - source.label == NON_SENSITIVE_EVENT
  weight: 0.92
  explain: "{source.desc} flows to {sink.desc} at {sink.host}"
```
Engine features: capability classes with inheritance; label sets; path predicates (dominance, `unless`, `after`, `within loop`); quantifiers (`count>N`, `unbounded`); host/path/package classifiers as pluggable predicates; per-rule weight learned/calibrated from the generator corpus (rule precision measured automatically); rule unit tests = (snippet, expected) pairs auto-generated by the data engine; rule hot-reload; `--explain-trace` debugging.

### 4.4 Behaviour signatures per category (what the rules encode — as capabilities, not string lists)
1. **secret_access** — `READ_FILE` on `SECRET_STORE` paths (path classifier: home-dotdirs with credential semantics, `.env`, key/cert/pem, kube/docker/cloud/ssh/netrc/npmrc, shadow, browser profile DBs, keychains), `ENV_READ` filtered/dumped by secret-like names, hardcoded credential literals (own detector: provider-format recognisers *plus* an entropy/shape model with name-context, minus placeholder/example/doc contexts), `/proc/*/environ`, `git credential`. Suppress: app-preference paths, placeholders, policy/doc text.
2. **data_exfiltration** — flow (`FILE`, `ENV`, `SECRET`, DB result, SQLi-exposed rows, clipboard, screenshots, `/etc/passwd`) → `NET_SEND`/`DNS_SEND`/`ICMP_SEND`/upload/webhook/paste/`scp`/`nc`/`git push` to non-owned host; covert channels (ping `-p`, DNS labels, HTTP header smuggling, chunk-and-send loops); markdown image beacons. Suppress: payload non-sensitive and destination derived as the app's own API.
3. **destructive_command** — `DELETE`/`rm`/`shred`/`mkfs`/`dd of=`/`DROP`/`TRUNCATE`/`DELETE|UPDATE` without predicate, recursive deletes on broad/tainted/root/home paths, SQLi on mutation statements, tainted `EXEC_SHELL`/`EVAL_CODE`, mass VCS/container destruction. Suppress: scoped + parameterised + fixed safe targets + dry-run.
4. **persistence_or_privesc** — `PERSIST_WRITE` to autostart surfaces (cron, systemd, rc/profile files, launchd, schtasks/registry-run, authorized_keys, init scripts, git hooks, shell-rc, `LD_PRELOAD`), `PRIV_CHANGE` (sudoers/NOPASSWD, setuid/setcap, group/uid edits, privileged containers/hostPath/hostPID, `docker.sock` mounts, `runAsUser: 0`). Suppress: read-only inspection (`crontab -l`, `systemctl status`).
5. **obfuscated_execution** — `EVAL_CODE`/`LOAD_MODULE`/`DESERIALIZE` over non-literal, *decoded*, dynamically built, or untrusted-path data; dynamic name construction for dangerous modules/functions; alias-hidden dangerous imports; encoded-payload pipelines (`base64 -d | sh`, `eval(atob(...))`, `-EncodedCommand`); entropy/naturalness anomaly passed to an executor. Suppress: safe loaders (`literal_eval`, `json`, `safe_load`), literal-only eval.
6. **dependency_risk** — `INSTALL_PKG` with: name near-miss of a popular package (edit distance, keyboard adjacency, homoglyph, separator/pluralisation, namespace tricks) **and** not itself popular; untrusted source (VCS URL/branch-unpinned, raw URL, extra/alt index, `--trusted-host`, `http://`); install-time execution (`postinstall`, `setup.py` cmd hooks); `curl | sudo sh` bootstrap; dependency-confusion shapes. Name knowledge = own curated popularity lists + a learned name-plausibility model (char-gram LM of legit names). Suppress: exact popular name, pinned, official index.
7. **resource_exhaustion** — loop-bound analysis: `while True`/`for` with no reachable exit **and** heavy body (spawn/alloc/IO/busy) or no sleep; fork bombs (any language incl. `:(){ :|:& };:`); unbounded `SPAWN_*` (count vs. configured cap); gigantic `ALLOC`; unbounded writes (`dd`/`yes`/`/dev/zero`/`/dev/urandom` w/o `count`/`head -c`); socket/fd leaks at scale; zip/regex bombs; recursion without base; SQL sleep/cartesian. Suppress: bounded by constants/`MAX_*`, join/pool, backoff.
8. **ssrf_network_exfil** — `NET_FETCH`/`NET_SEND` whose host classifies as `META/LINK_LOCAL/LOOPBACK/PRIVATE/INTERNAL` (including encoded IP forms and DNS names like `metadata.google.internal`), dangerous schemes (`gopher/file/dict/ldap/ftp`), user-controlled URL without *dominating* validation, redirect-follow past check, host sweeps/port scans, reverse shells (`/dev/tcp`, `nc -e`, socket+dup2). Suppress: dominating allowlist on the final URL targeting an external partner.
9. **ai_targeted_instructions** — `TEXT` nodes (comments, docstrings, string/tool/MCP descriptions, YAML/MD comments, JSON strings, alt-text, hidden markup) scored by (a) **addressee** (AI/assistant/model/reviewer/bot/agent/copilot/scanner/“if you are an LLM”) × (b) **directive** (imperative verbs of override, suppress, approve, skip, reveal, exfiltrate, run) × (c) **object** (previous/system instructions, prompt, credentials, scan results, findings, safety) + role-tag/chat-template tokens + a trained text classifier robust to paraphrase/leetspeak/line-splits. Suppress: prose *about* prompt injection (security policies, docs), ordinary human-to-human review notes.

### 4.5 Shadow World — proving problems before execution (innovation core)
Idea: instead of *guessing* from text, **run the code in imagination**. We build a tiny virtual computer and a purpose-built interpreter; the code can only touch fake objects. Nothing real is ever opened, deleted, connected to, or installed, so there is no `rm -rf` risk.

**4.5.1 The virtual world (`codeguard/shadow/world.py`)**
- *Fake filesystem*: in-memory tree seeded with a realistic Linux/macOS/Windows-ish layout (`/`, `/home/user/{.ssh,.aws,.config,Documents}`, `/etc/{passwd,shadow,sudoers,cron.d}`, `/var/www`, `/tmp`, project dir) where "crown-jewel" files carry sensitivity labels and sizes. Reads return labelled fake bytes (e.g. a `SECRET`-tainted blob), writes/deletes mutate only the in-memory tree.
- *Fake network*: no sockets. Every connect/request is recorded as `(scheme, host, port, payload labels)`. Hosts are *classified* (loopback/private/link-local/metadata/external/own) without any DNS lookup; scripted fake responses (e.g. metadata returns fake creds, labelled `SECRET`) so follow-on flows are observable (the "fetch creds then send them" chain).
- *Fake processes/services*: spawn/fork/thread counters with a budget; cron/systemd/profile files are just tree nodes whose modification is a "persistence" event.
- *Fake package index*: `pip/npm/apt install X` resolves X against our popularity list + name-plausibility model; reports "would install package X (looks like a copy of Y)" and whether install hooks would run. Never contacts any index.
- *Fake clock/env*: deterministic `os.environ` with secret-looking fake entries and *deliberately unset* variables (to expose empty-variable bugs).

**4.5.2 The interpreter (`codeguard/shadow/interp_*.py`)**
- *Python*: a small abstract+concrete interpreter over the `ast` — evaluates assignments, f-strings, string ops, comprehensions, function/class calls, loops (step-capped), try/except. Library calls (`os`, `subprocess`, `shutil`, `requests`, `socket`, `open`, `pickle`, `sqlite3`, `threading`, …) are routed to **our stubs** that act on the virtual world. Any callable not in the stub table returns an opaque `UNKNOWN` value that propagates taint but performs nothing. **No `exec`/`eval`/`getattr` on real objects, ever**; only whitelisted *pure* operations (str/bytes/int/list/dict methods, `base64`/`binascii`/`codecs` decode, `chr/ord/join/format/hex`) run for real, because they are side-effect-free — this is what makes deobfuscation exact (e.g. `'sub'+'process'` → `subprocess`, base64 payload → decoded text that is then *re-interpreted in shadow*, not run).
- *Bash*: a mini shell that does real expansion semantics (quotes, `$VAR`, `${VAR:-x}`, globbing against the fake FS, `$(…)`, pipes, redirects, `&&/||`, `set -e/-u`, functions, loops) and routes commands to command stubs (`rm`, `dd`, `cp`, `curl`, `wget`, `nc`, `chmod`, `crontab`, `systemctl`, `pip`, `npm`, `ssh`, …) acting on the virtual world.
- *JavaScript*: a mini evaluator for the statement subset we lower (calls, template literals, `require/import`, `fetch`, `child_process`, `fs`, `process.env`, `eval/Function`) with the same stub idea.
- *SQL*: executes the statements against a **virtual schema** (inferred from the code's own CREATE/INSERT/usage) and reports rows that would be touched/dropped (`UPDATE accounts SET balance = 0` ⇒ "touches every row in `accounts`").
- *YAML/Markdown*: shadow-run `run:` steps via the bash interpreter, fenced code via the right interpreter; text is scored as in §4.4.9.
- *Unknown languages*: skip interpretation, rely on IR + generic evidence (clearly marked lower confidence).
- Hard budgets: max steps, max loop iterations (e.g. 10k, then summarise as "does not terminate / unbounded"), max memory objects, wall-clock ~40 ms. Budget exhaustion is itself a signal (`UNBOUNDED`), never silently ignored.

**4.5.3 Blast-radius estimator.** After a shadow run we compute from the virtual tree: files/dirs that would be deleted/overwritten (count, % of tree, whether it includes `/`, `$HOME`, system dirs, `.git`, databases), secrets that would be read, bytes that would leave the machine and to where, privileges that would change, processes/threads that would be created. Output becomes plain English ("would delete 1,240 of 1,300 files including your home folder") and feeds the risk score (bigger radius ⇒ higher score; tiny scoped deletes in a temp folder stay `allow`).

**4.5.4 Counterfactual probing ("taint by experiment")** — innovative replacement for guessing at injection:
- For each input-like value reaching a sensitive sink (SQL string, shell command, file path, URL, eval/exec argument), re-run the relevant slice in shadow with (a) a benign probe value and (b) a battery of hostile probes (`' OR '1'='1`, `x'; DROP TABLE t;--`, `; id`, `$(id)`, `../../etc/passwd`, `http://169.254.169.254/`, `{{7*7}}`, `__import__('os')…`).
- Compare the **structure** of what reaches the sink: SQL token/statement shape, shell word-splitting/command count, path normal form (escapes the base dir?), URL host. If a hostile probe changes the structure, the sink is *provably injectable* — report it with the exact witness ("if `order_id` is `1 OR 1=1`, the query becomes `DELETE FROM orders WHERE id = 1 OR 1=1`, deleting every order").
- Parameterised queries / `shlex.quote` / list-argv exec / enforced allowlists show *no structural change* ⇒ automatic safety proof (this is how benign look-alikes get cleared by evidence rather than by a rule exception).

**4.5.5 Defect & error detection (code that is wrong, not just evil)** — semantic checks, not syntax:
- *Python*: undefined/unbound names, use-before-assignment, wrong call arity/keywords against signatures of the stdlib functions we stub (signature table generated offline with `inspect` over the stdlib on this machine), wrong argument types propagated by shadow values (e.g. `int + str`, `len(None)`), missing `await`, unreachable code, resource leaks (sockets/files not closed in loops), exceptions that would certainly be raised on the shadow path, mutable-default pitfalls that matter, infinite loops with a provably unchanged condition, recursion with no base case.
- *Bash*: unset/empty variable in a destructive path (`rm -rf "$DIR/"*` with `$DIR` unset ⇒ `rm -rf /*`), `cd dir && …` vs `cd dir; rm …` (continues in the wrong folder if `cd` fails), missing `set -e` before destructive steps, unquoted expansions that word-split, glob that expands to nothing/everything, `dd`/`mkfs` on a block device that is not clearly a scratch file, `sudo` + variable path.
- *SQL*: statement touches every row (no WHERE) / unbounded `DELETE`/`UPDATE`, `DROP` of non-temp objects, references to columns/tables not defined anywhere in the snippet's virtual schema, implicit cross joins.
- *YAML/CI*: wrong keys for the detected schema (e.g. GitHub Actions step without `run`/`uses`), unpinned third-party actions, secrets echoed into logs, `pull_request_target` + untrusted checkout.
- *Install/deps*: packages that don't exist in the known universe and are near-misses (likely typo or squat), contradictory pins.
- Findings are reported as `problems[]` in verbose mode and woven into `reason` when they drive the verdict (e.g. "the folder variable is never set, so this would delete from the root of the disk"). Pure non-security bugs lower confidence in `allow` only when they are destructive in effect; otherwise they are informational.

**4.5.6 Cost & termination analysis.** Beyond `while True`: derive loop bounds symbolically (counter updates vs. condition), multiply nested loops × per-iteration cost (alloc size, spawn count, bytes written) using the shadow cost model; flag exceeding thresholds (CPU-steps, memory MB, threads/processes, disk MB, connections). Gives "this would create about 50,000 open connections" rather than "uses socket in a loop".

**4.5.7 Intent-vs-effect diff.** Shadow effects (file/network/process/priv events) are compared with an *intent profile* derived from names, docstrings, comments, and the surrounding module ("log event", "format report", "health check"). Effects outside the intent envelope (a "format report" function that touches `~/.ssh`) add risk and make the explanation concrete.

**4.5.8 Adversarial self-checks.** Because attackers know we interpret: (i) opaque `UNKNOWN` calls that sit on a sensitive path raise rather than lower risk; (ii) code that behaves differently under the interpreter's fake world (e.g. checks for the hostname / env / time / "am I in a sandbox") is flagged as *evasion-aware* (`obfuscated_execution`); (iii) every shadow observation is cross-checked by the static IR rules so a bug in the interpreter can't silently clear code.

**4.5.9 Safety of the emulator itself** (it parses hostile input): no real I/O primitives are importable from stub modules; recursion/size/step/time budgets; run in-process with `signal`/thread watchdog on POSIX and cooperative step counting everywhere (Windows-safe); fuzz-tested; any internal exception ⇒ fall back to static verdict (fail-closed), never crash the endpoint.

## 5. Data engine & model training (all ours, from scratch)

### 5.1 Behaviour-spec generator (replaces "static templates")
- A **behaviour spec** is a small graph: e.g. `[ENV_READ(secret) → ENCODE → NET_SEND(external)]`, `[LOOP(unbounded) → SPAWN_THREAD]`, `[INSTALL_PKG(name=typo(popular))]`.
- **Renderers** turn a spec into code in python/bash/js/sql/yaml/markdown (+ a few generic languages) using style knobs: helper-function decomposition, constants-at-top, class/property wrappers, logging/docstring noise, f-string/format/concat variants, library choice (requests/httpx/urllib/socket; fetch/axios/XHR; curl/wget/nc), naming vocabularies (neutral, misleading-benign, and scary), comments.
- **Benign twins** by flipping one semantic bit: tainted→constant, external→own host, enforced allowlist, bounded loop, read-only op, pinned official package, safe loader, parameterised query, comment→neutral comment, policy-text mentioning a secret.
- **Composition** of 2–3 specs into one file for multi-category examples (hidden "hard" style).
- **Obfuscation/evasion operators** (semantics-preserving): alias imports, string split/concat, hex/base64/chr encodings, `getattr` indirection, moving sinks into helpers/classes/lambdas, dead code, unicode confusables, whitespace/comment padding, reordering.
- Real-style negatives: a corpus of ordinary code we write or own (utility scripts, Flask/Django/CLI/ETL, Dockerfiles, CI YAML, READMEs, SQL migrations, shell deploy scripts) + the Python standard library source on this machine (PSF licence; used locally for the naturalness LM and for FP stress-testing, not redistributed).
- Scale target: 20–50k samples, ~35–40% benign (half of them hard twins), ~15–20% multi-label, ≥6 languages. Stored as jsonl with the same fields as dev (`code, language, category(ies), label, rationale, id`) + `spec` for debugging.
- **Splits:** group by spec family *and* renderer style so validation measures generalisation to unseen families. Dev-42 = frozen final test (never in train, never used to pick among many tuning runs more than sparingly).

### 5.2 Rule induction & weight learning (what makes rules "dynamic")
- Run the rule engine over the corpus; compute per-rule precision/recall → **weights = calibrated log-odds**, not hand guesses.
- **Rule induction**: take misses (false negatives) and FPs, extract their IR sub-graphs, cluster, mine frequent discriminative sub-patterns (decision-tree / itemset mining over IR features), emit candidate YAML signatures with auto-generated tests; a human accepts/edits them. Log every accepted rule in `docs/rule_log.md` with its provenance (synthetic family vs. dev miss — dev-miss rules must be generalised into families before acceptance).
- **Adaptive thresholds**: per-category thresholds and fusion weights re-fit on every retrain via isotonic/Platt calibration and a cost-weighted F1 sweep.

### 5.3 Models (own training, CPU, tiny)
| Model | Input | Purpose | Notes |
|---|---|---|---|
| Hashed n-gram linear heads | normalised code: char 3–6-grams + token 1–3-grams, hashing trick | fast per-category probs, language-agnostic | trained with our own SGD/logreg (numpy or scikit-learn as a *training tool*), < 5 MB |
| IR-feature GBDT | counts/flags from IR + rule evidence + proofs | fusion co-voter, learns label conventions | gradient-boosted trees trained by us; small |
| Tiny neural (stretch) | byte/char sequence, depth-limited conv or 2-layer transformer, ≤2–3 M params | catches style our IR misses | trained from scratch (PyTorch, CPU), exported to pure-numpy or int8 ONNX for inference; only runs in ambiguous band |
| Benign-code LM | char n-gram / tiny LM trained on benign code | naturalness & obfuscation/entropy anomaly feature | fully unsupervised, trained on our benign corpus |
| Identifier→capability model | split identifier subwords + arg shapes | resolves unknown API names to capability classes | trained on API-semantics table + generated names |
| Package-name plausibility LM | char n-gram of legit package names | typosquat signal beyond edit distance | trained on our curated popularity list |
| AI-instruction classifier | TEXT nodes (word + char n-grams, addressee/directive/object features) | paraphrase-robust prompt-injection scoring | trained on generator-made positives + hard negatives (security-policy prose, ordinary comments) |
| Language ID | char-gram + syntax probes | `code_language` | tiny |
All models serialised in plain formats we control (npz/json), loaded once at startup; versioned `models/MANIFEST.json` with sizes + training data hash.

### 5.4 Fusion
`risk = 1 - Π(1 - w_i)` over rule evidence (noisy-OR) → minus dominated-proof credits → blended with model probs through a small calibrated stacker → per-category sigmoid thresholds → `verdict = block iff max(cat scores) ≥ T`. Stacker is trained on the family-split validation set. Categories are emitted per-category (multi-label), with a minimum-support rule so a stray low score doesn't add noise categories (important for category precision).

## 6. Interception proof (pass/fail floor — build in hour 1, rehearse often)
```
codeguard/intercept.py   # @guarded, guard_context(), guarded_exec(), guarded_subprocess(), GuardBlocked
demo/intercept_check.py  # live-judged
demo/safe_snippet.*  demo/unsafe_snippet.*   # organizer-provided pair when given; else our own harmless pair
```
- `scan()` runs **synchronously before** any `exec`/`subprocess`; `block` ⇒ `GuardBlocked` raised, execution function never invoked. Guard error/timeout ⇒ fail-closed.
- Demo: clean marker dir → run SAFE through guard ⇒ `ALLOWED.marker` appears; run UNSAFE (payload would create `SHOULD_NOT_EXIST.marker`, nothing harmful) through guard ⇒ blocked, marker absent; print verdict JSON + latency + PASS/FAIL; non-zero exit on failure. Never run the unsafe snippet unguarded unless organizers explicitly allow it.
- TOCTOU-safe: the exact bytes scanned are hash-compared with the bytes executed. Also wraps a decorated function whose argument is the code/command and a file-path variant.
- On `GuardBlocked` the demo prints the plain-English reason and the shadow-world "what would have happened" lines — this *is* the "show it's wrong before it executes" moment for judges (e.g. "would have created SHOULD_NOT_EXIST.marker and deleted 3 files — nothing was run").
- Also show the guard gating a real decorated risky function (e.g. `@guarded def run_agent_step(code)`), plus a 60-sec backup screen recording.

## 7. Service, UI, ops
- FastAPI (`/scan`, `/batch`, `/health`, `/metrics`, `/` UI). Models and rules loaded at startup; rules hot-reload (`POST /admin/reload` or file watcher); thread-safe; tolerant request parsing; request-size cap; structured logging (no code bodies logged by default).
- CLI: `python -m codeguard scan <file|->`, `python -m codeguard eval <jsonl>`, `python -m codeguard serve`; library: `from codeguard import scan`.
- Public URL early (laptop + tunnel such as cloudflared/ngrok, or a free host); submit it before the window; supervisor auto-restart; test from a second network; Dockerfile + pinned `requirements.txt`.
- Minimal UI (`ui/index.html`, static): textarea → verdict badge, risk bar, category chips, reason, highlighted vulnerable lines, latency, and the **evidence trace** (IR facts, rule hits, proofs, model probs) — good for judges to see the "why"; preset buttons for benign look-alike vs attack.

## 8. Evaluation, efficiency, anti-overfit
- `eval/run_eval.py`: per-category and overall precision, recall, F1, FP count/rate, verdict accuracy, category exact-match + micro/macro F1, confusion matrix, latency p50/p95/p99, model sizes; writes `reports/*.md|json`.
- Report sets: (a) frozen dev-42, (b) family-split synthetic validation, (c) real-style benign FP corpus, (d) evasion robustness by obfuscation depth 1–3, (e) per-language breakdown, (f) multi-category "hard" set.
- **Efficiency note** (deliverable): rules-only vs +models vs +tiny-neural; accuracy, FPs, size (MB), latency before/after optimisation (caching, lazy loading, int8, feature pruning).
- Targets: p50 < 10 ms, p95 < 40 ms (no neural), cold start < 3 s, total models < 20 MB (< 50 MB with neural).
- **Honesty discipline:** dev-42 results are reported as-is; any rule motivated by a dev miss is generalised into a family, covered by generated tests, and logged. No dev text in rules/training/tests (a CI test greps for dev ids and long dev substrings).
- Fuzz/robustness tests: random bytes, huge files, deeply nested code, binary, CRLF, tabs, unicode, truncated code, non-code prose, empty string — always a valid response within the time budget.

## 9. Repo layout
```
CodeGuard/
├─ CLAUDE.md  README.md  THIRD_PARTY.md  .env.example  requirements.txt  Dockerfile  Makefile
├─ config/            conventions.yaml  thresholds.json  (hot-reloadable)
├─ rules/             *.yaml behaviour signatures per category + cap_ontology.yaml + api_semantics/*.yaml + host/path/package knowledge
├─ codeguard/
│  ├─ api.py cli.py schema.py pipeline.py intercept.py
│  ├─ langid.py  deobfuscate.py  ir.py
│  ├─ frontends/      python_fe.py bash_fe.py js_fe.py sql_fe.py yaml_fe.py md_fe.py generic_fe.py
│  ├─ analysis/       constprop.py taint.py callgraph.py guards.py loopbounds.py hosts.py paths.py typosquat.py secrets.py
│  ├─ shadow/         world.py (fake fs/net/proc/pkg index) interp_py.py interp_sh.py interp_js.py interp_sql.py stubs/*.py blast.py probes.py defects.py cost.py intent.py
│  ├─ engine/         dsl.py matcher.py fusion.py explain.py (plain-English templates)
│  └─ ml/             features.py ngram.py gbdt.py tinynet.py lm.py identcap.py textcls.py calibrate.py infer.py
├─ gen/               specs/ renderers/ mutations/ twins.py compose.py build_corpus.py
├─ models/            *.npz  MANIFEST.json
├─ data/              dev.jsonl (frozen)  synth_*.jsonl  benign_real/
├─ demo/              intercept_check.py safe_snippet.* unsafe_snippet.* RECORDING.md
├─ eval/              run_eval.py robustness.py
├─ ui/index.html
├─ tests/             per-category + benign-twin + schema + fuzz + "no-dev-leak" tests
├─ docs/              writeup.md (→ PDF 2–3 pp) rule_log.md efficiency.md
└─ reports/
```

## 10. Third-party components (kept minimal) and inspirations
**Dependencies (all permissive):** Python stdlib incl. `ast` (PSF) · NumPy (BSD-3) · scikit-learn (BSD-3, used only as a *training/utility library*; no pretrained models) · optional PyTorch (BSD-style, training only) · optional onnxruntime (MIT) · FastAPI, Starlette, uvicorn, pydantic (MIT/BSD). **No pretrained weights, no external rulesets, no scanner binaries, no network at inference time.** Every parser beyond `ast` (bash, JS, SQL, YAML, Markdown), every rule, every model is ours.
**Inspiration only (credited in README, not imported):** Bandit / Semgrep / CodeQL (source–sink–sanitizer thinking, taint labels), gitleaks / detect-secrets / TruffleHog (credential shapes, entropy), ShellCheck (shell parsing pitfalls), YARA / ClamAV heuristics (behavioural signatures), GuardDog / OSSF package-analysis (malicious package indicators, typosquat heuristics), Falco / Sigma (behaviour rules as data), LLM Guard / Rebuff / prompt-injection taxonomies (AI-targeted instruction categories), MITRE ATT&CK, MITRE ATLAS (AML.T0054), CWE (tag vocabulary). Taxonomies are royalty-free with attribution.
Popularity lists and secret-format notes are written by us from public knowledge (no scraped dataset copied wholesale); record how each list was built in `THIRD_PARTY.md`.

## 11. Two-person split & timeline (assume ~24–36 h; scale as needed)
**A — analysis engine:** IR, Python/bash/JS front-ends, constprop/taint/guards/loopbounds, rule DSL + matcher, fusion/explain.
**B — data/ML/platform:** generator + renderers + twins/mutations, model training + calibration, SQL/YAML/MD front-ends, langid, API/UI/batch, interception demo, eval, docs.
Both: swap and review code, write tests, rehearse demo (everyone can explain everything).

| Phase | Hours | Gate |
|---|---|---|
| P0 Skeleton | 0–2 | schema + `scan()` stub, `/scan` `/batch`, eval harness on dev-42, **interception demo v0**, public URL submitted |
| P1 Engine core | 2–9 | IR + Python front-end + deobfuscation + rule DSL + ontology; all 9 categories hit on Python; benign-proof layer; language ID; **Shadow World v1** (virtual FS/net + Python interpreter with stubs, blast radius, plain-English reasons) |
| P2 Polyglot | 9–16 | bash/SQL shadow interpreters (empty-variable + no-WHERE detection), counterfactual probes, defect checks; bash, JS, SQL, YAML, Markdown front-ends + generic fallback; typosquat/host/path/secret analyzers; AI-instruction scorer v1; generator v1 (python/bash first) with twins |
| P3 Learning | 16–24 | generator across all languages + composition + evasions; train n-gram heads, GBDT, LM, ident→cap, text classifier; calibration + stacker; rule weights from data; efficiency table v1 |
| P4 Hardening | 24–30 | rule induction round(s), robustness/fuzz, latency profiling, hot-reload, UI trace, multi-category hard-set tuning, optional tiny neural |
| P5 Ship | 30–end | README, THIRD_PARTY, write-up PDF (2–3 pp), final reports, demo rehearsal ×3 + recording, tag release, re-verify endpoint from second network |

Scope-cut order: tiny neural → JS full parser (keep token-level) → UI polish → extra languages. **Never cut:** schema validity, interception demo, benign-twin handling/proof layer, README + component list.

## 12. Risks & mitigations
- **FPs on look-alikes** → proof-dominance logic, twins everywhere, cost-weighted thresholds, real-style benign corpus.
- **Label-convention mismatch** → conventions in config + data-driven category heads; check per-category confusion on dev each retrain.
- **Hidden multi-category hard set** → no early exit, composition training, per-category min-support.
- **Emulator bugs/escape or slowness** → stubs only touch in-memory objects, step/time budgets, static rules cross-check every shadow result, shadow failure ⇒ static fallback (fail-closed); fuzz the interpreter.
- **Emulator fidelity gaps (unknown libs)** → opaque `UNKNOWN` values propagate taint, never clear risk; confidence reduced and explained.
- **Parser brittleness on odd inputs** → every front-end has a try/except degrade path to the generic fallback; never "allow" because parsing failed.
- **Latency/ReDoS** → bounded regexes, size caps, per-request budget, models only in ambiguous band.
- **Overfitting to dev** → frozen split, no-dev-leak test, family-level generalisation of any dev-motivated rule.
- **Endpoint availability** → warm process, supervisor, health checks, second tunnel.
- **Scope creep from "all languages"** → generic fallback + shared IR gives breadth cheaply; invest depth in the six named languages.

## 13. Definition of done
- [ ] `/scan` and `/batch` return the exact schema for every input, including garbage
- [ ] All 9 categories detected via IR rules + models; each with unit tests and benign twins
- [ ] Six named languages lowered structurally; generic fallback for others; `code_language` correct on dev
- [ ] Rules are YAML, hot-reloadable; weights come from measured precision
- [ ] All models trained by us; `MANIFEST.json` documents training data + sizes; zero pretrained weights, zero API calls, `.env.example` has no keys
- [ ] Shadow World: Python + bash + SQL interpreters, blast radius, counterfactual probes, defect checks; zero real side effects (test: run all attack fixtures with a filesystem/network audit hook and assert nothing real happened)
- [ ] Every `block` has a plain-English `reason` (what it does / why bad / what would happen); verbose mode exposes shadow observations and `problems[]`
- [ ] `demo/intercept_check.py` passes live; exit code reflects result
- [ ] Reports: dev-42, family-split val, real-style FP, evasion robustness, per-language, efficiency note
- [ ] README (architecture, components + licences, inspirations, assumptions, limitations, AI-assistance disclosure) + 2–3 page write-up
- [ ] Public GitHub repo, endpoint URL submitted early and verified from a second network
- [ ] Demo rehearsed; backup recording saved
