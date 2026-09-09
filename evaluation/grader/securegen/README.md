# SecureGen grading

From the evaluation root:

```bash
python grader/securegen/grade.py --predictions preds.json --tasks tasks.jsonl --output grades/securegen --backend sandbox
python grader/securegen/grade_plans.py --predictions plan_preds.json --tasks tasks.jsonl --output grades/securegen-plans --backend sandbox --cwe-only
```

Inputs are task records (`--tasks`) and prediction records (`--predictions`).
For sampled predictions, supply `--n_samples`. `grade.py` evaluates functional
correctness and security. `grade_plans.py` evaluates generated security tests;
`--cwe-only` selects the CWE-only plan workflow used by the sequence script.

Both entrypoints support Docker and sandbox backends. They write aggregate
`report.json` files and per-task grading artifacts under `--output`. Sandbox access
uses `SANDBOX_BASE_URL` and `SANDBOX_API_KEY`; Docker requires a working daemon.

Implementations and backend helpers live in `src/`. `SECUREGEN_SRC` can override
that directory. Direct entrypoints are `src/grade.py` and `src/grade_security_tests.py`.
