# Baseline v1 (frozen)

Outputs for every labelled case are saved in `reports/baseline_v1/` (`outputs.jsonl`, `metrics.json`, `MANIFEST.json` with a hash of
the rules and analysis code). After any change run `python eval/benchmark.py --compare reports/baseline_v1`: it lists every case whose
verdict, categories, language or vulnerable lines moved. Re-freeze only on purpose (`--save`).

## What is measured
| Suite | n | Labels |
|---|---|---|
| dev | 42 | provided by the organisers |
| sem32 | 32 | our reading of the dataset's conventions (`tests/data/sem32.jsonl`); not organiser labels |
| fixtures | 103 | ours: positive cases plus benign look-alikes (`tests/cases_*.py`) |

Result at freeze: precision 1.0, recall 1.0, 0 false positives, 0 misses, category-exact 1.0, language 1.0 on all three suites.
Read this carefully: the fixtures and sem32 informed the rules, so they show that the fixes hold and nothing regressed, not that
unseen code is classified correctly. Only the 42 dev rows were never used to tune a rule; there is no held-out set yet.

Other guards: output-format check (169 outputs), line-number check, rewrite-consistency check (805 rewrites: rename, noise, alias,
hoist, wrap, try/except, PDF-style spacing), robustness, ML, real-code false-positive check (400 standard-library files:
7.5% blocked, mostly genuine `eval`/dynamic-import/`shell=True` uses), interception demo.

## Which changes caused the improvements, and do they generalise
General mechanisms (fire on many variants; each has benign twins):
* provenance labels `TRAVERSAL` / `ARBITRARY_FILE` and path confinement (4 variants of the same flaw, plus safe `basename`/`realpath` twins)
* decode-to-execute flow (12 cases, several decoders, sinks and intermediate variables)
* disabled-verification detector keyed on the meaning of parameter names
* covert-channel, shell-use, forced-recursive-delete rules (3 cases each)
* validation-decoy check: compares the value that is checked with the value that is requested (structural, 2 cases + 3 twins)
* newline/spacing recovery (`unglue.py`, `undouble_spaces`, flat-indent repair): fixes input damage, not detection

Narrow rules, each seen on one case so far (kept because they follow a real pattern, but not yet shown to generalise):
`destructive.tar_extract_unchecked`, `exfil.data_in_dns_name`, `res.unbounded_large_write`, `secret.secret_copied_to_file`,
`secret.secret_shown_or_logged`, `destructive.path_traversal_write`. Heuristic, not evidence-based: `dep.suspicious_package_name`
(a word list) and the typosquat check (about 640 known names).

## Limits
* Scores rank risk; they are not calibrated probabilities.
* Static analysis cannot prove arbitrary code safe. An `allow` verdict means no configured signal fired. Execution must still run
  inside an independent sandbox (filesystem, network, CPU, memory and time limits). `intercept.py` blocks only code that is scanned
  through it; it is not a sandbox.
* A held-out labelled set from the organisers is still needed to measure generalisation.
