# BaxBench grading

From the evaluation root:

```bash
python grader/baxbench/grade.py --models MODEL_LABEL --results_dir results/baxbench --sandbox_dataset instances.json --ks 1 --output grades/baxbench/report.json
```

Inputs are generated application files in the model/task/sample layout under
`--results_dir` and sandbox image metadata in `--sandbox_dataset`. Use
`--n_samples` for repeated samples and `--ks` for reported pass-at-k values.

Grading runs through the sandbox service and requires `SANDBOX_BASE_URL` and
`SANDBOX_API_KEY`. Cached per-sample `test_results.json` files remain beside the
code; `--output` selects the aggregate report. A grading log is written beside it.

`src/scenarios/` contains registered benchmark tests, `src/scenario_files/` their
fixtures, and `src/env/` the language environments. The sandbox grader,
in-container runner, image helpers, and scoring modules live in `src/`.
`src/grade_sandbox.py` also provides a direct entrypoint.
