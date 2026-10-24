# CodeGuard

A real-time, pre-execution safety layer for LLM-generated code. It decides **allow / block** before code runs, in a few
milliseconds, on CPU, **without any LLM**. It works on Python, bash, JavaScript/TypeScript, SQL, YAML and Markdown (plus a
generic fallback for other languages) and explains every verdict in plain English.

> Nothing is ever executed by the analyser. Code is *read* and interpreted against an abstract model; dangerous calls only
> record what they would do. The only code that really runs is the harmless safe/unsafe demo pair in `demo/`.

## Quick start
```bash
pip install -r requirements.txt
python -m codeguard serve --port 8000          # http://localhost:8000  (UI at /)
curl -s localhost:8000/scan -H 'content-type: application/json' -d '{"code": "print(1)"}'
python demo/intercept_check.py                 # interception proof (marker file appears / never appears)
python eval/run_eval.py data/dev.jsonl         # evaluation on the public dev sample
python tests/run_cases.py && python tests/test_robustness.py
```

## Scan a whole file of snippets
```bash
python -m codeguard batch snippets.jsonl            # -> snippets_results.jsonl  (one result per snippet, same order)
python -m codeguard batch snippets.json --array     # -> one JSON array
python -m codeguard batch snippets.csv -o out.jsonl # CSV with a "code" column
python -m codeguard batch some_script.py            # a single code file counts as one snippet
python -m codeguard batch my_folder/                # every file in the folder is one snippet
```
Input: `{"code": "..."}` per line (extra fields like id/language/label are ignored; `--keep-id` copies an id into the output).
Output: exactly the six schema fields per snippet. The browser UI (`/`) also has a file-upload box that returns a downloadable `.jsonl`.

## Interface (fixed schema)
`POST /scan` with `{"code": "..."}` returns
```json
{"verdict": "allow|block", "risk_score": 0.97, "categories": ["secret_access", "data_exfiltration"],
 "code_language": "python", "reason": "plain-English explanation", "vulnerable_lines": [8, 17]}
```
`POST /batch` takes a list of `{"code": ..., "id"?: ...}` (or `{"items": [...]}`) and returns the per-sample objects in order.
`GET /health`, `GET /metrics`. `?verbose=1` adds an `explanation` object (evidence, per-category scores, timings).
Library: `from codeguard import scan`; CLI: `python -m codeguard scan file.py`.
The endpoint never returns a non-schema body; on an internal failure it fails closed (block) with a valid body.

## Architecture
```
code -> sanitise -> language ID -> front-end -> behaviour events -> rule engine (YAML) -> fusion -> verdict + explanation
```
* **Front-ends** lower each language to a common set of *behaviour events* (read file, send over network, delete, run shell,
  eval, install package, spawn, loop, SQL statement ...). Python and JavaScript share one **abstract interpreter**
  (JavaScript is parsed to a Python AST by our own parser). Bash, SQL, YAML and Markdown have their own parsers.
* **Abstract interpretation, not grep:** constants are folded (string concatenation, base64/hex decoding, f-strings),
  values carry provenance labels (user input, environment, secrets, file data, network data ...), calls are followed through
  helper functions, aliases and dynamic imports. Safety proofs (parameterised SQL, quoting, validation guards, bounded loops)
  remove false positives.
* **Counterfactual probing:** for SQL/shell strings built from input, hostile values are substituted and the resulting
  *structure* is compared; a change is a proven injection and gives the witness shown in the reason.
* **Path confinement:** a path or string built from a fixed folder plus caller input gets a `TRAVERSAL` label (through `join`, `+`,
  f-strings and `pathlib`). `basename`/`secure_filename` or a `realpath(...).startswith(base)` guard clears it. Reading, writing or
  deleting with that label is flagged. File data read from a caller-chosen path is labelled `ARBITRARY_FILE`; sending it to a
  caller-chosen host is exfiltration whatever the protocol.
* **Disabled verification:** a detector keyed on the meaning of a parameter (`verify`, `verify_signature`, `check_hostname`,
  `algorithms=['none']`) flags code that switches off signature, token or TLS checks. Token checks map to
  `persistence_or_privesc`; expiry-only and TLS-only are weaker.
* **Whole-file input:** `codeguard/snippets.py` splits concatenated `{"code": ...}` objects, JSON/JSONL/CSV, PDF text and plain
  text into snippets; each gets its own verdict.
* **Rules are data:** `rules/*.rules.yaml` (182 rules, hot-reloadable via `POST /admin/reload`) match events by capability, labels,
  flags, host/path classes and multiplicity, and carry the plain-English templates. Weights are noisy-OR combined per category.
* **Knowledge:** host classifier (metadata, link-local, private, numeric/hex/octal IP forms, drop sites), path classifier
  (credential stores, persistence surfaces, system dirs), typosquat engine (edit distance, transposition, homoglyphs against
  `rules/pkg_*.txt`), secret-format and entropy detector, AI-instruction scorer (addressee x directive x object, role tokens,
  hidden unicode, negation-aware).
* **ML layer (trained from scratch, benign data only):** `codeguard/ml/` holds a byte-level 5-gram *naturalness* language model
  (1.1 MB, numpy, trained on the Python standard library with 400 files held out). It scores how unlike ordinary code a long
  literal looks; a packed/encoded blob next to code that can execute it adds evidence for `obfuscated_execution`, which catches
  payloads hidden behind decoders the rules do not know. It cannot block on its own. Held-out result: AUC 0.998 vs 0.66 for plain
  entropy on base64/hex/zlib/rot13/reversed text; deployed detector recall 99.97% on 8,904 encoded blobs with 0 false alarms on
  benign blob-shaped literals (`reports/lm_eval.json`). Retrain with `python -m codeguard.ml.train`.
* **Interception:** `codeguard/intercept.py` - `@guarded`, `guarded_exec`, `guarded_run`, `guard()`; synchronous, fail-closed,
  the exact scanned bytes are the executed bytes.

**Category mapping.** The response format fixes nine categories, so SQL injection has no category of its own. It follows the dataset's convention: injection into a SELECT is `data_exfiltration` (rows can be read out), injection into DELETE/UPDATE is `destructive_command`, and a tainted string reaching a shell or `eval` is `destructive_command`. The mapping lives in the rules (`rules/exfil.rules.yaml`, `rules/destructive.rules.yaml`) and can be flipped in one place.

## Test data
The organiser's public dev sample (`codeguard_dev.jsonl`) and several blind-test files are **not committed**: they contain placeholder credentials
(fake Slack/API tokens) that GitHub's secret scanning treats as real. Put the organiser's file at `./codeguard_dev.jsonl` (and a copy at `data/dev.jsonl`) to run
`python eval/run_eval.py codeguard_dev.jsonl`. The evaluation scripts skip any test file that is missing; `python tests/run_cases.py` (170 cases) needs no external data.

## Interception proof
`python demo/intercept_check.py` scans and runs the safe snippet (marker `ALLOWED.marker` appears), scans the unsafe snippet
(blocked, `BLOCKED_SHOULD_NOT_EXIST.marker` never appears) and shows a `@guarded` function whose body is never entered.
Organizer-provided pairs can be supplied with `--safe` / `--unsafe` (`.py` or `.sh`).

## Results (public dev sample, 42 rows)
precision 1.00, recall 1.00, 0 false positives, category exact-match 1.00, language accuracy 1.00; about 2 ms median and 7 ms 95th percentile
per snippet once warm (`reports/dev_report.json`; `docs/efficiency.md`). These numbers are on the public sample that guided development;
the hidden-set score will differ. **Honest generalisation numbers:** on brand-new blind files (code the engine had never seen, predictions saved before the expected
outputs were read) verdict accuracy was 94-97% and exact category sets 75-85%; on an independent public corpus of labelled vulnerable/safe files (from
`mevichitra/codeguard`, Apache-2.0, used for scan-only evaluation) 42/46 must-flag files were caught and 40/43 must-allow files allowed; real library code is blocked
8.2% (stdlib, 400 modules) and 7.2% (third-party packages, 250 modules) of the time, mostly genuine dual-use code. `workflow.md` has the run-book, the checklist and the judge presentation. Extra checks: benign look-alike fixtures (`tests/cases_benign.py`), robustness inputs
(`tests/test_robustness.py`), rename/noise stability on dev (`eval/robustness.py`).

**Generalisation check (`python tests/test_metamorphic.py`).** Every Python fixture and dev row is rewritten in ways that keep its behaviour
(rename everything, add noise, move statements into a function behind a `__main__` guard, wrap in try/except, alias imports, hoist
arguments into temporary variables). The verdict and categories must not change; a detector that memorised text would fail this.
Current result: 1,016 rewrites, 0 changes.

## Optional trained models
* `models/text_lr.npz` - instruction-text classifier (used by default for `ai_targeted_instructions`): leave-one-attack-family-out recall 0.74,
  5-fold accuracy 0.92 / precision 0.99 / recall 0.87 on the public benchmark, about 0% false positives on 7,000 held-out real comments
  (standard library and third-party packages). A public chat-style injection set (deepset, Apache-2.0) was tried and rejected: it did not transfer to code comments.
* A hashed n-gram code classifier trained on `expanded_dataset.jsonl` (all 52 template families) plus 6,675 real benign functions was evaluated with
  `eval/code_lr_eval.py`: alone it recalls 20-33% of independent attacks and gives 0.01 probability to the two snippets the engine missed when fresh,
  so it is **not** shipped.
* `models/codeguard_model.onnx` - MiniLM-L6 fine-tuned on `expanded_dataset.jsonl` (train families), our cases and real benign code
  (`train_and_export.py`, `onnx_engine.py`, `codeguard/union.py`). **Not used by default.** Held-out families: accuracy 0.81, precision 1.0,
  recall 0.80 (n=16); on the organiser dev rows it finds none of the 25 positives, because the training file's 52 templates are too narrow.
  The union with the engine never adds a false positive (601 unseen benign functions) but also adds nothing on dev, sem32 or the held-out
  families. Latency 12.5 ms (fp32) / 7.5 ms (int8, less accurate) for the model alone, about 24 ms for the union.
  More diverse labelled data is needed before this model should influence a verdict.

## Label style: `CODEGUARD_LABELS`
Some behaviours touch two categories (read a credential *and* send it; send data to a private address; a decoded payload that deletes files).
The organiser's dev rows label such single-behaviour chains with the one category that names the behaviour, so `CODEGUARD_LABELS=primary` reports
only that category. The default is now `inclusive` (every category the behaviour touches), because the contest scores multi-label output with
precision/recall and the dev rows pass 42/42 under both styles. Two hand-made test files
(`tests/data/user_test50.jsonl`, `tests/data/user_test50_v2.jsonl`) label identical patterns in opposite styles; each file is matched
exactly by one style (50/50 category sets), and the dev rows are matched exactly by `primary`. Score any labelled file with
`python eval/score_file.py <file>` or, for full expected outputs, `python eval/score_full.py <file>`.

## Components and licences
Python standard library (PSF; also the training text for the language model), NumPy (BSD-3), PyYAML (MIT), FastAPI / Starlette / uvicorn / pydantic (MIT/BSD). No pretrained model is used by default (the optional MiniLM classifier below is off), no
external ruleset, no scanner binary, no network access and no LLM/API at inference time. All parsers (bash, JavaScript, SQL,
Markdown), the rules, the package lists and the scoring logic were written for this project. Ideas (not code) were inspired by
Bandit/Semgrep/CodeQL (source-sink-sanitizer), gitleaks/detect-secrets (credential formats), ShellCheck, YARA, GuardDog,
and the MITRE ATT&CK / ATLAS / CWE taxonomies (tags). See `THIRD_PARTY.md`.

## Assumptions and known limitations
* Very long input (over 200,000 characters) is analysed as its first 150,000 plus its last 50,000 characters; line numbers for such input are approximate.
* Scores are a ranking, not calibrated probabilities.
* Static/abstract analysis: heavily obfuscated code using unknown libraries or runtime-only data can evade it; unknown callables
  propagate taint but are not judged.
* JavaScript support covers a practical ES2020 subset; unusual syntax falls back to the generic analyser.
* Package-name knowledge: the 15,000 most downloaded PyPI projects (typosquat targets: the top 3,000) plus a small npm list; rarely-used real package names
  that sit one edit from a popular one can be flagged (1.7% of unseen real names), and npm coverage is much thinner than PyPI.
* Languages without a full front-end (PHP, Go, Ruby, PowerShell, Java, C#) use a capability-based generic analyser: it covers the common sources and sinks
  (`tests/cases_polyglot.py`) but is coarser than the Python, bash, JavaScript and SQL analysers.
* Category labels for behaviours that touch two categories follow an "inclusive" default; the organiser's own labels may be narrower (see "Label style").
* False positives on real library code are about 7-8% (dynamic import, eval and deserialisation in framework code).
* The ML layer is deliberately narrow: an unsupervised obfuscation signal. There is no supervised attack classifier because we have
  only 42 labelled rows and will not fabricate attack corpora; a model we could not validate honestly would only add risk.
* AI-assistant disclosure: this project was written with Claude Code (an AI coding assistant) under the team's direction.
