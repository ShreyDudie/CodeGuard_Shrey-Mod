# Third-party components

| Component | Use | Licence |
|---|---|---|
| Python standard library (`ast`, `tokenize`, `re` ...) | parsing Python, utilities | PSF |
| NumPy | language-model training and scoring | BSD-3 |
| PyYAML | rules loading; YAML composer for CI/compose/k8s analysis | MIT |
| pypdf | reading the text layer of uploaded PDF files (optional) | BSD-3 |
| FastAPI, Starlette | HTTP service | MIT |
| uvicorn | ASGI server | BSD-3 |
| pydantic | FastAPI dependency | MIT |

## Models and data from other projects (read, adapted or used for training; none is called at run time)
| Source | What we took | Licence |
|---|---|---|
| gitleaks (github.com/gitleaks/gitleaks) | ~220 provider credential formats (regex, keywords, entropy) converted to `rules/secret_patterns.json` by `scripts/import_gitleaks.py` | MIT |
| Prompt-Injection-Firewall (github.com/ogulcanaydogan/Prompt-Injection-Firewall) | 110 malicious + 100 benign prompt samples (`data/external/pif_*.json`) to train/evaluate the instruction-text classifier; pattern families informed `textscan.py` | Apache-2.0 |
| hexora (github.com/rushter/hexora) | ideas only: suspicious-callable indirection, behaviour combinations, sensitive environment-variable names, binary-download and install-hook signals; its sample files were used for scan-only evaluation (not copied into this repo) | MIT |
| Bandit (github.com/PyCQA/bandit) | ideas only: unsafe deserialisation, raw-SQL sinks, shell-injection categories; example files used for scan-only evaluation | Apache-2.0 |
| detect-secrets (github.com/Yelp/detect-secrets) | idea only: keyword + entropy secret detection | Apache-2.0 |
| llm-guard, pytector | ideas only: prompt-injection / invisible-text checks | MIT / Apache-2.0 |
| PyT (python-security/pyt), ShellCheck (koalaman/shellcheck) | ideas only (taint-flow and shell-quoting pitfalls); **no code or data copied** because both are GPL | GPL-2.0 / GPL-3.0 |
| sentence-transformers/all-MiniLM-L6-v2 | base weights for the optional fine-tuned ONNX classifier (`train_and_export.py`) | Apache-2.0 |
| onnxruntime, onnx, tokenizers, transformers, PyTorch, scikit-learn, SciPy | training and inference of the optional models (offline training; onnxruntime + tokenizers at inference) | MIT / BSD / Apache-2.0 |

Models trained here: `models/lm_py.npz` (byte 5-gram naturalness model, Python standard library, PSF), `models/text_lr.npz` (hashed n-gram
logistic regression for instruction text; data above plus real stdlib comments), and, when present, `models/codeguard_model*.onnx`
(MiniLM fine-tuned on `expanded_dataset.jsonl` training families, our cases and real benign stdlib functions).
Training data is not redistributed except the two small benchmark files above (with their NOTICE).

No external LLM or API is called at inference time.

Written in-house: shell lexer/parser, JavaScript/TypeScript lexer/parser (to Python AST), SQL tokenizer/classifier, Markdown and YAML
analysers, abstract interpreter, rule engine and all rules, host/path/package/secret classifiers, AI-instruction scorer.

Package-popularity lists (`rules/pkg_pypi.txt`, `rules/pkg_npm.txt`) were compiled by hand from general knowledge of popular
packages; they are used only for edit-distance comparisons.

Taxonomy tags in rule metadata (MITRE ATT&CK, MITRE ATLAS AML.T0054, CWE, OWASP LLM) are public identifiers used with attribution.

## Added in the generalisation round
* `rules/pkg_pypi_top.txt` - names of the 15,000 most downloaded PyPI projects (hugovk/top-pypi-packages, data derived from the PyPI download statistics; snapshot 2026-10-01). Used as the "known legitimate" set; the first 3,000 are also typosquat targets.
* `data/external/deepset_prompt_injections.json` - deepset/prompt-injections (Apache-2.0). Evaluated but NOT used in the shipped text model (it did not transfer to code comments and added a false positive).
* Text model negatives now also include comments/docstrings from installed third-party packages (each under its own permissive licence; used locally for training only, nothing redistributed).
* `mevichitra/codeguard` (github.com/mevichitra/codeguard, Apache-2.0): its labelled benchmark corpus (`benchmarks/corpus/*/tp|tn`) was read and scanned (never executed) as an independent evaluation of 11 vulnerability classes that fall inside our nine categories; its misses and false positives guided the fixes listed in `docs/efficiency.md`. No code or data from it is copied into this repository.
* `cosai-oasis/project-codeguard` and `project-codeguard/rules` (CC-BY-4.0): reviewed. They are secure-coding guidance for AI coding agents (what to write), not a detector for malicious snippets, so nothing was integrated; the rule list was used only as a checklist of vulnerability classes. Attribution recorded here.
* `hugovk/top-pypi-packages` data (monthly PyPI download counts), snapshot 2026-10-01: `rules/pkg_pypi_top.txt`.
