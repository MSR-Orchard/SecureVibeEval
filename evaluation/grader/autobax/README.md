# AutoBax grading

From the evaluation root:

```bash
python grader/autobax/grade.py --models MODEL_LABEL --results_dir results/autobax --sandbox_dataset instances.json --spec_type text --safety_prompt generic --include_missing --output grades/autobax/report.json
python grader/autobax/grade_plans.py --instances instances.json --output trajectories/autobax-plans --report grades/autobax-plans/report.json --spec_type text --safety_prompt none
```

`grade.py` reads generated application files from the model/task/sample layout
under `--results_dir`. `--sandbox_dataset` supplies instance/image metadata.
It executes registered functional/security tests through the sandbox service,
using `SANDBOX_BASE_URL` and `SANDBOX_API_KEY`. Cached per-sample test results stay
beside generated code; the aggregate report is written to `--output`.

`grade_plans.py` reads instance metadata and `.traj.json` artifacts from `--output`
and writes `--report`. Its default deterministic plan grading needs no Docker
daemon or sandbox. Optional semantic judging requires explicitly supplied judge
configuration. Both entrypoints accept `--n_samples`.

`src/scenarios/` contains the registered tests, `src/scenario_files/` their fixtures,
and `src/env/` the execution environments. Graders, the in-container runner, and
report helpers live in `src/`. Direct entrypoints are also available under `src/`.
