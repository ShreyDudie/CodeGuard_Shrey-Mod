# CodeGuard: architecture and key design decisions

## 1. Problem and stance
AI agents execute code they generate. CodeGuard sits in the hot path and returns allow/block before execution, with no LLM
call and no execution of the code under test. Because the decision must be cheap and explainable, we built a layered,
CPU-only analyser rather than a keyword scanner or a model.

## 2. Pipeline
1. **Sanitise and identify the language** (shebang, syntax probes, weighted features): 100% on the dev sample.
2. **Front-end** lowers the code to *behaviour events*: read file, send over network, delete, run shell, eval, load module,
   deserialise, install package, spawn, loop, SQL statement, privileged change, text aimed at an AI.
3. **Rule engine** matches the events against 187 declarative YAML rules (capability, provenance labels, flags, host and path
   classes, multiplicity). Rules also hold the plain-English templates.
4. **Fusion** combines rule weights per category (noisy-OR), takes the verdict from the strongest category, and builds the
   `reason`, `vulnerable_lines` and risk score.

## 3. Why it generalises
* **Abstract interpretation.** One interpreter handles Python and JavaScript (JavaScript is parsed by our own parser into a Python
  AST). Strings are folded as skeletons with holes for unknown parts, so `'sub'+'process'`, base64 payloads, f-strings and
  helper functions are resolved. Values carry labels (user input, environment, secret, file, network, decoded ...), so a rule
  asks *what flows where*, not which words appear.
* **Safety proofs reduce false positives:** parameterised SQL, quoting, dominating validation guards, bounded pools and loops,
  read-only commands, safe loaders, enforced allowlists, pinned popular packages.
* **Counterfactual probing:** hostile values are substituted into SQL and shell strings; if the structure changes, injection is
  proven and the witness is reported (for example the query that would actually be executed).
* **Semantic checks beyond syntax:** empty-variable deletes (`rm -rf "$DIR/"`), `cd` without checking success, tautological
  WHERE clauses, unbounded loops and fork bombs, loop multiplicity (50,000 sockets), decoy allowlists, typosquats, hidden
  Unicode and encoded instructions.
* **Confinement and verification semantics:** fixed-folder-plus-caller-input paths are tracked as possible traversal until a
  basename, `secure_filename` or `realpath`/`startswith` guard dominates the use; files read from caller-chosen paths and sent to
  caller-chosen hosts are file couriers; parameters that switch off signature/token/TLS verification are recognised by meaning,
  not by library name. Each has a safe twin that stays allowed.
* **Many languages:** bash, SQL, YAML (CI/compose/k8s/ansible), Markdown (fences, hidden comments, beacons) have dedicated
  analysers; other languages use a capability-based generic analyser that reuses the shell and SQL analysers on embedded strings.

**Category mapping.** The response format fixes nine categories, so SQL injection has no category of its own. It follows the dataset's convention: injection into a SELECT is `data_exfiltration` (rows can be read out), injection into DELETE/UPDATE is `destructive_command`, and a tainted string reaching a shell or `eval` is `destructive_command`. The mapping lives in the rules (`rules/exfil.rules.yaml`, `rules/destructive.rules.yaml`) and can be flipped in one place.

## 4. Interception
`@guarded`, `guarded_exec`, `guarded_run` and `guard()` scan synchronously, fail closed, and execute the exact bytes that were
scanned. `demo/intercept_check.py` proves blocking by an observable side effect: the marker file written by the safe snippet exists,
the marker the unsafe snippet would write never appears, and a decorated function body is never entered.

## 5. Evaluation and efficiency
* **Public dev sample (42 rows, guided development):** precision 1.00, recall 1.00, 0 false positives, category exact match 1.00, language 1.00. We did not trust it.
* **Fresh blind files** (predictions saved before the expected outputs were read): 94-97% verdict accuracy and 75-85% exact category sets on two files of 60 and 65
  snippets; the misses were coverage gaps and label conventions, which we fixed generally (guard-dominated deletes, command-line passwords, array loops,
  PowerShell detection, bare shell one-liners, environment dumps) with a benign twin for each. After fixing, a file becomes development data; new files were requested for the next check.
* **Independent public corpus** (labelled vulnerable/safe files from another open-source analyser, scan-only): 42/46 must-flag caught, 40/43 must-allow allowed.
* **Stability:** 1,163 behaviour-preserving rewrites (rename, noise, wrap, alias, hoist) changed no verdict.
* **False positives on real code:** 8.5% of 400 standard-library modules and 7.6% of 250 third-party modules, mostly genuine dual-use code (dynamic import, eval, deserialisation).
* **Latency:** about 2 ms median, 7 ms 95th percentile, 86% of calls under 5 ms; start-up and warm-up about 1 s; models total 1.7 MB (`docs/efficiency.md`).
* **What did not help:** a MiniLM classifier and a hashed code classifier trained on the 500-row `expanded_dataset.jsonl` (103 distinct snippets, 52 families) plus thousands of real benign
  functions recalled only 0-33% of independent attacks, so they are not shipped; an extra public injection dataset lowered precision and was dropped.

## 6. Decisions and limitations
* ML layer: a from-scratch byte 5-gram naturalness model (1.1 MB) trained on benign code only. It flags packed blobs that sit next to
  something able to execute them (AUC 0.998 vs 0.66 for entropy on held-out encoded text; 99.97% blob recall, 0 benign false alarms).
  It is gated by the rules and cannot block alone. We did not train a supervised attack classifier: 42 labelled rows cannot validate one.
* Static analysis cannot see runtime-only data or unknown libraries; those propagate taint but are not judged.
* Package knowledge is a curated list, not live registry data.
* AI assistance: built with Claude Code under the team's direction (disclosed in the README).
