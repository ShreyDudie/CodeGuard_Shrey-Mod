# Efficiency note

## Size (what ships and is used by default)
| Component | Size |
|---|---|
| Byte 5-gram naturalness model (`models/lm_py.npz`) | 1.2 MB |
| Instruction-text classifier (`models/text_lr.npz`) | 0.5 MB |
| Rules (187 YAML rules) and lists (secret formats, 15,000 package names) | 0.4 MB |
| Code | 2.2 MB |
| Optional MiniLM ONNX classifier (not used by default, excluded from git) | 90 MB fp32 / 23 MB int8 |

Runtime needs only Python, NumPy, PyYAML, FastAPI, uvicorn, pydantic. No GPU, no network.

## Latency (CPU, one laptop, warm service)
| Measure | Value |
|---|---|
| Service start + warm-up (rules, language model, text model, package index) | about 1.1 s |
| `scan()` per snippet | median about 2 ms, 95th percentile about 7 ms, 86% of calls under 5 ms |
| Server-side time reported by `/metrics` | median under 1 ms |
| HTTP round trip over `127.0.0.1` (includes Python client overhead and a fresh connection) | median about 10 ms |

What made it fast: rule files re-checked at most once a second (was every request, about 1 ms), models and the typosquat index loaded once at start-up, cached syntax-tree walks,
an indexed (symmetric-delete) package-name lookup instead of comparing against every name (a 1,000-name scan took 220 ms; the indexed lookup over 3,000 names takes 0.2 ms),
and input caps (long files are scanned as head + tail).

## Accuracy before / after optimisation and model choices
| Variant | Dev sample (42) | Notes |
|---|---|---|
| Rules + analysis only (no models) | precision 1.00, recall 1.00, 0 FP | `reports/dev_report_nomodels.json` |
| + naturalness model + text classifier (default) | precision 1.00, recall 1.00, 0 FP | `reports/dev_report.json`; the models add recall on encoded blobs and on prompt-injection wording, not on the dev rows |
| MiniLM fine-tuned on `expanded_dataset.jsonl` | found 0 of the dev positives alone | too few distinct templates (103 snippets, 52 families); not shipped |
| Hashed code classifier trained on `expanded_dataset.jsonl` + 6,675 real benign functions (`eval/code_lr_eval.py`) | recalls 20-33% of independent attacks on its own, 0.01 probability on the two snippets the engine missed when fresh | adds nothing to the engine; not shipped |

Generalisation tests (not tuned on): fresh blind files 94-97% verdict accuracy and 75-85% exact category sets; 1,016 behaviour-preserving rewrites with 0 changes;
independent public corpus 42/46 must-flag and 40/43 must-allow; false positives on real code 8.2% (stdlib) and 7.2% (third-party packages).

## Changes that moved the numbers in the last round
| Change | Effect |
|---|---|
| Typosquat list 640 -> 15,000 names with indexed lookup | recall on single-edit typosquats of popular names 56% -> 99%; unusual-but-real unseen names flagged 0.6% -> 1.7% |
| Long docstrings scored in 4-line windows | third-party false positives from instruction rules 9 -> 5 of 250 files |
| Text model trained with 12,781 more benign comments | false positives on 7,000 held-out comments about 0%; recall on unseen attack families 0.77 -> 0.74 |
| Bare shell one-liners recognised as shell | `rm -rf /` and `curl ... | sh` without a shebang were allowed; now blocked |
| Guard-dominated `rm`, literal read-only shell commands, chat webhooks, placeholder keys in comments | removed false positives found on fresh files and the public corpus |
