# CodeGuard: workflow, status and how to present

Everything needed to run, check, submit and present the project. Last verified: all checks below were run on the final code.

---------------------------------------------------------------------------------------------------------

## 1. What was asked, and where it is

| Requirement (from the brief) | Status | Where |
|---|---|---|
| Accept `{"code": "..."}`, return `verdict`, `risk_score`, `categories`, `code_language`, `reason`, `vulnerable_lines` | Done | `POST /scan` (`codeguard/api.py`); also `python -m codeguard scan`, and `from codeguard import scan` |
| Cover all nine categories | Done | 187 YAML rules in `rules/` plus analysers; see section 4 |
| Layered CPU-first detector, not a keyword list | Done | language ID, 7 front-ends, abstract interpreter, rule engine, fusion, two small trained models |
| No LLM as judge, no external API | Done | nothing calls a model or a network at inference; `.env.example` has no keys |
| Own trained model | Done (small, honest) | `models/lm_py.npz` (obfuscation signal), `models/text_lr.npz` (instruction text classifier) |
| Interception point proving a block prevents execution | Done | `python demo/intercept_check.py` prints `INTERCEPTION PROOF: PASS` |
| Batch endpoint | Done | `POST /batch`, plus `python -m codeguard batch file.jsonl` |
| Minimal UI / script for the live demo | Done | browser UI at `http://127.0.0.1:8000/` (input, verdict, risk, categories, reason, highlighted lines, latency) |
| Public GitHub repository | **You** | create the repo and push (section 6); no git repo exists yet in this folder |
| Runnable service | Done | `python -m codeguard serve`, `scripts/start_service.bat`, `Dockerfile`; verified by `scripts/endpoint_check.py` |
| Endpoint URL submitted in advance | **You** | needs a public tunnel or host (section 6); `cloudflared` / `ngrok` are not installed on this machine |
| Evaluation on the dev sample + efficiency note | Done | `docs/dev_results.md` (precision, recall, false positives, model sizes, latency, before/after), `docs/efficiency.md`, `reports/dev_report.json`; regenerate with `python eval/make_dev_results.py` |
| README: architecture, every component + licence, assumptions, limitations | Done | `README.md`, `THIRD_PARTY.md` |
| 2-3 page write-up | Written, **you export to PDF** | `docs/writeup.md` |
| Floors: valid schema, live interception demo, no execution outside the demo pair, no hard-coded dev answers | Pass | section 5 |

## 2. Run it (3 commands)

```bash
pip install -r requirements.txt
python -m codeguard serve --port 8000        # service + UI; warm-up takes about 1 second
python demo/intercept_check.py               # interception proof
```

Use `http://127.0.0.1:8000`, not `http://localhost:8000`, in scripts on Windows: `localhost` tries IPv6 first and adds about 2 seconds per
request in Python clients (the server itself answers in under a millisecond). Browsers and curl are not affected.

Quick manual check:

```bash
curl -s 127.0.0.1:8000/health
curl -s 127.0.0.1:8000/scan -H "content-type: application/json" -d '{"code":"def add(a, b):\n    return a + b"}'
curl -s 127.0.0.1:8000/scan -H "content-type: application/json" -d '{"code":"rm -rf /"}'
```

One-click start: `scripts\start_service.bat` (Windows) or `scripts/start_service.sh`. Check a running endpoint, local or public, exactly as the judge will use it:

```bash
python scripts/endpoint_check.py http://127.0.0.1:8000
python scripts/endpoint_check.py https://YOUR-PUBLIC-URL     # from a second network, before you submit the URL
```

It sends probe snippets, validates every response against the fixed schema (also for missing / non-JSON / null bodies and for `/batch`) and prints latency. `PASS` means the endpoint is ready to submit.

## 3. Pre-flight checklist (run before the judges arrive)

| # | Check | Command | Expected |
|---|---|---|---|
| 1 | Service up | `curl -s 127.0.0.1:8000/health` | `{"status":"ok", ... "rules":187}` |
| 2 | Allow case | scan a small pure function | `verdict: allow`, `categories: []` |
| 3 | Block case | scan `rm -rf /` | `block`, `destructive_command`, language `bash` |
| 4 | Garbage input | `curl -d '{"nope":1}'` and `curl -d 'not json'` | valid schema body, no 500 |
| 5 | Batch | `POST /batch` with two items | two results in order |
| 6 | Interception | `python demo/intercept_check.py`, and the UI tab `/#gate` | `INTERCEPTION PROOF: PASS` (both) |
| 7 | Regression | `python tests/run_cases.py` | `203/203 ok  FP=0 FN=0` |
| 8 | Robustness | `python tests/test_robustness.py` | `robustness ok` |
| 9 | Schema | `python tests/test_schema.py` | `0 problems` |
| 10 | Dev sample | `python eval/run_eval.py codeguard_dev.jsonl` | precision 1.0, recall 1.0, 0 FP |
| 11 | From a second network | open the public URL on a phone (mobile data) | UI loads and a scan returns |

## 4. What was built (map of the repository)

```
codeguard/
  api.py, cli.py            HTTP service (/scan /batch /health /metrics, UI), command line
  pipeline.py               sanitise -> language ID -> front-end -> rules -> fusion -> reason
  langid.py                 language identification (python, bash, js/ts, sql, yaml, markdown, php, go, ruby, powershell, dockerfile ...)
  pyfe.py / pylib.py        Python abstract interpreter (also runs JavaScript through our own JS->AST parser, jsparse.py/jsfe.py/jslib.py)
  shfe.py / shparse.py      bash front-end (quotes, expansions, arrays, loops, functions, embedded SQL clients)
  sqlfe.py, yamlfe.py, mdfe.py, genericfe.py   SQL, YAML (CI/compose/k8s), Markdown, other languages
  textscan.py, ml/          secrets, instruction text (AI-targeted), the two small trained models
  knowledge.py              host / path / package / secret classifiers (15,000-name package list)
  engine.py, fusion.py      rule engine (YAML) and noisy-OR fusion
  explain.py                plain-English reason and vulnerable lines
  intercept.py              @guarded, guarded_exec, guard(): scan before run, fail closed
rules/                      187 declarative rules, one file per category
demo/                       intercept_check.py + the safe/unsafe pair
eval/, tests/               evaluation, 203 regression cases, rewrite-stability, robustness, schema tests
reports/                    dev report, blind-run predictions, baselines
docs/                       writeup.md, efficiency.md
```

The nine categories and what detects each:

| Category | Main signals |
|---|---|
| secret_access | credential files, provider key formats (about 220), high-entropy strings (incl. inside URLs), secret environment variables, secrets printed or copied |
| data_exfiltration | secret/file/environment data flowing to an outside host, DNS or ICMP channels, webhooks, injection into SELECT |
| destructive_command | recursive delete of broad paths, tainted shell/eval, DROP/TRUNCATE/unscoped UPDATE, injection into DELETE/UPDATE |
| persistence_or_privesc | cron, systemd, shell rc files, sudoers, setuid, registry Run keys, bind shells |
| obfuscated_execution | decode-then-run, dynamic imports, aliased dangerous modules, unsafe deserialisation |
| dependency_risk | typosquatted names (edit distance vs the 15,000 top PyPI names), VCS/URL installs |
| resource_exhaustion | fork bombs, unbounded loops with spawn, huge loop-multiplied writes and sockets |
| ssrf_network_exfil | metadata service, loopback/private hosts, gopher/file schemes, decoy allow-lists |
| ai_targeted_instructions | comments, docstrings, Markdown/YAML text aimed at a reviewer or model (pattern scorer + text classifier) |

## 5. Honest numbers (use these, do not round them up)

| Measure | Result |
|---|---|
| Public dev sample (42 rows, guided development) | precision 1.00, recall 1.00, 0 false positives, category exact 1.00, language 1.00 |
| First look at brand-new blind files | verdict accuracy 94-97%, exact category sets 75-85% (two files: 60 and 65 snippets) |
| Independent public corpus (45+ labelled vulnerable/safe files from another project) | 42/46 must-flag caught, 40/43 must-allow allowed |
| False positives on real library code | 8.5% of 400 stdlib modules, 7.6% of 250 third-party modules (dual-use code such as dynamic import and eval) |
| Rewrite stability | 1,163 behaviour-preserving rewrites, 0 changed verdicts |
| Latency (library) | median about 2 ms, 95th percentile about 7 ms, 86% of calls under 5 ms; service warm-up about 1 s |
| Model size | 1.2 MB language model + 0.5 MB text model; no GPU |

Expected on the hidden set: roughly 90-95% on verdicts and 78-88% on exact category sets. The weakest point is false positives on
benign code that looks dangerous, and label conventions where the reference data disagrees with itself.

Floors: schema is validated by `tests/test_schema.py` (229 outputs, 0 problems) and bad input never produces a non-schema body;
the analyser never executes code (it only reads and interprets); only `demo/` runs anything, and only the harmless pair; no
dev id or dev snippet appears in rules or training (the rules are written as general behaviours, and rewrite-stability and
fresh blind runs were used to check that).

## 6. What is left (only you can do these)

0. **ngrok is installed (v3.3.1); it only needs your authtoken.** Get it from https://dashboard.ngrok.com (Your Authtoken), then run once in a terminal: `ngrok config add-authtoken YOUR_TOKEN`. Then: window 1 `scripts\start_service.bat`; window 2 `ngrok http 8000`; window 3 `python scripts\public_url.py` (finds the public URL, runs the judge-style schema check on it and prints the address to submit, base + `/scan`). Free-tier ngrok may show a browser warning page to *browsers*; scripts calling the API are not affected, and a client can add the header `ngrok-skip-browser-warning: true` if needed.
1. **Public endpoint.** Run the service on your laptop and expose it (`cloudflared tunnel --url http://127.0.0.1:8000` or `ngrok http 8000`), or deploy the
   `Dockerfile` on a free host. Open it from a phone on mobile data. Send the URL to the organizer before the window opens.
   Keep the laptop awake and plugged in, and keep the terminal open. Start the service about 5 minutes before the window.
2. **GitHub repository.** `git init`, add the project (there is a `.gitignore` that leaves out the 90 MB unused ONNX model), push to a public repo, and put the URL in the README.
3. **Write-up PDF.** Export `docs/writeup.md` (2-3 pages) to PDF.
4. **Demo recording.** Record `python demo/intercept_check.py` plus the UI as a 60-second backup.
5. **Organizer questions worth asking.** Does the answer key label every category a behaviour touches, or only the main one? (Our default is every category; `CODEGUARD_LABELS=primary` switches.) Is the demo pair provided?
6. **Optional, if time remains.** More blind data in other languages, and a wider npm package list.

## 7. How to present to judges (5-6 minutes)

**Opening (20 s).** "AI agents run code they write. CodeGuard decides allow or block before anything runs, in a few milliseconds, on a laptop CPU,
with no LLM and no API call. It also tells you why, in plain English."

**1. Live scan (60 s), in the UI.** Paste three snippets:
- a small pure function: *allow*, risk near 0, "nothing here reads secrets, sends data out...";
- a snippet that reads cloud credentials and posts them to a made-up domain: *block*, `secret_access` + `data_exfiltration`, the exact lines highlighted, the reason in plain words;
- a benign look-alike (parameterised SQL, or `ast.literal_eval`): *allow*. Say: "the same function name, different data flow."

**2. How it decides (60 s).** "It never runs your code. It reads it and interprets it against a model: values carry labels such as user input, environment, secret, decoded;
dangerous calls only record what they would do. Rules are data in YAML and ask *what flows where*, so renaming variables or splitting strings does not hide anything. Safety proofs
(parameterised queries, guards that dominate the call, bounded loops) are what keep benign code allowed."

**3. Show the layers (45 s).** Point at the response's evidence (`?verbose=1`): rule hits, per-category scores, the lines. Mention the two small models we trained (1.7 MB total):
an obfuscation signal and an instruction-text classifier for prompt injection hidden in comments.

**4. Interception proof (60 s). This is a floor, rehearse it.** In the browser UI open the **Interception proof** tab (or go to `http://127.0.0.1:8000/#gate`, which runs it automatically): it draws snippet -> guard -> decision -> marker file for the safe snippet, the unsafe snippet and the `@guarded` function, ending in a green PASS banner. The terminal version is below.  Run `python demo/intercept_check.py` and narrate the three steps: the safe snippet is scanned and runs (a marker file appears);
the unsafe snippet is scanned and blocked, and its marker file never appears; a decorated agent function is gated and its body is never entered. End on the line
`INTERCEPTION PROOF: PASS - blocked code never executed`. If the organizer gives a pair, run it with `--safe` and `--unsafe`.

**5. Numbers, honestly (45 s).** "Perfect on the public sample, which guided development, so we did not trust it. We ran blind tests on code we had not seen: 94-97% on verdicts, 75-85% on exact
category sets, and we fixed what they exposed. On real library code we block about 7-8%, mostly genuine dual-use code. Rewriting code without changing its behaviour changed no verdict in over a thousand rewrites."

**6. Close (20 s).** "Fast (about 2 ms), explainable, no LLM, own parsers and rules, a proven interception point, and honest about its limits."

### Likely questions

| Question | Answer |
|---|---|
| Is this just a keyword list? | No. It tracks data flow with labels, resolves string building and decoding, and removes findings when a safety proof dominates the call. Renaming and noise changed no verdict in 1,163 rewrites. |
| Did you train on the dev sample? | The dev rows are a test set. No dev id or snippet is in the rules or training data. Rules describe behaviours; fresh blind files and rewrites check that. |
| Why not a bigger model? | A MiniLM classifier fine-tuned on our 500-row file recalled 0 of the dev positives: its templates are too narrow. We kept it off and say so. Two small models are used where they validated: obfuscation and instruction text. |
| What is the false-positive rate? | 0 on the dev sample, 8% on real library modules, which are full of legitimate eval and dynamic imports. |
| What does it miss? | Heavily obfuscated code using unknown libraries or runtime-only data; very rare package names; languages without a full front-end are analysed more coarsely. |
| Can it be bypassed with a long file? | Over 200,000 characters it scans the first 150,000 and the last 50,000, so padding cannot hide code. |
| Does it execute anything? | Never. Only the harmless demo pair runs, and only in `demo/`. |
| Why `reason` in plain English? | Because a block is only useful if the person can see what would have happened. |

## 8. If something goes wrong during the demo

| Symptom | Fix |
|---|---|
| UI does not load | check the terminal running `serve`; restart it; use `127.0.0.1`; hard refresh (Ctrl+F5) |
| Each request takes about 2 s from a script | use `127.0.0.1` instead of `localhost` |
| Public URL down | restart the tunnel; keep a second tunnel (ngrok and cloudflared) ready; show the local UI |
| Port 8000 busy | `python -m codeguard serve --port 8010` |
| Interception demo prints FAIL | run `python tests/run_cases.py` and tell the judge; do not run the unsafe file directly |
| Anything slow after a long idle | `curl 127.0.0.1:8000/health` once to wake it, then continue |

## 9. Re-running the evaluations

```bash
python tests/run_cases.py                       # 203 regression cases with benign twins
python eval/benchmark.py --compare reports/baseline_v7   # every labelled set vs the saved baseline
python tests/test_metamorphic.py                # behaviour-preserving rewrites
python tests/test_pdf_extract.py                # a file of snippets (also after a PDF's line wrapping) gives one result per snippet
python tests/test_demo_gate.py                  # the UI's interception proof matches the CLI proof
python tests/stdlib_fp.py --models              # false positives on real standard-library code
python eval/code_lr_eval.py                     # does a trained code classifier add anything? (it does not; not shipped)
```

A new blind file: save the code-only rows, run `scan` on each and write the predictions to `reports/` first; only then compare with the expected outputs.
