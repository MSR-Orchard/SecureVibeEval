# SusVibes grading

From the evaluation root:

```bash
SUSVIBES_EVALUATION_LOG_DIR=grades/susvibes python grader/susvibes/grade.py --predictions_path preds.json --dataset_path tasks.jsonl --run_id experiment --backend sandbox
```

Inputs are task records (`--dataset_path`) and predicted patches
(`--predictions_path`, as a list or an instance-keyed object). Select test-log
parsers with `--env_spec_id default` or `--env_spec_id train`.

Both Docker and sandbox backends are supported. Docker needs a working daemon;
sandbox uses `SANDBOX_BASE_URL` and `SANDBOX_API_KEY`. Reports and test logs are
written beneath `SUSVIBES_EVALUATION_LOG_DIR/<run_id>/<strategy>/`, grouped by model.
Without an override, the log root is `grader/susvibes/logs/run_evaluation`.

The `susvibes/` package contains scoring, backends, and default/train parser
metadata. `--agent` is accepted
for sequence-script compatibility; both harnesses use the same prediction format.
The `python -m susvibes.run_evaluation` command is also available when
run from `grader/susvibes/`.
