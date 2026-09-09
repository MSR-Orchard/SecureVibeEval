# Multi-Backend Evaluation Harness

This harness keeps model backends and benchmark datasets as separate choices.
Run commands from the parent `evaluation/` directory after following the
[evaluation setup guide](../README.md). Data defaults to the repository
`data/raw/` directory; set `DATA_DIR` to use another location.

## Layout

The three main directories answer different questions:

- `backends/`: **Which agent CLI runs?** Claude Code, Codex, Copilot, Gemini, or Pi.
  Each integration owns its installation script, credentials, model configuration,
  and command builder.
- `benchmarks/`: **Which tasks run?** SusVibes, SecureGen, AutoBax, or BaxBench.
  Adapters own task interpretation, prompts, and benchmark output formats.
- `execution/`: **Where does the agent run?** Local Docker or a remote sandbox.
  Implementations own workspace setup, command execution, transfer, and cleanup.

```text
harness/
├── backends/
│   ├── claude_code/
│   ├── codex_cli/
│   ├── copilot_cli/
│   ├── gemini_cli/
│   └── pi_cli/
├── benchmarks/
├── execution/
├── common/                    # Shared orchestration, selection, and results
├── cli.py                     # Shared arguments
├── registry.py                # Backend lookup and benchmark defaults
├── run_benchmark.py           # Sequential entry point
├── run_benchmark_parallel.py  # Parallel entry point
└── tests/
```

For example, `--backend pi_cli --benchmark securegen --execution_backend docker`
means “run Pi on SecureGen tasks inside local Docker containers.”


## Benchmarks

Supported adapters:

- `susvibes` - patch-style tasks, default workdir `/project`, captures `git diff`.
- `securegen` - patch-style masked-repo tasks, uses each instance's `cwd`, writes
  `preds.json`.
- `autobax` - AutoBax generation tasks, uses each instance's `code_workdir`,
  and copies generated code to the benchmark results layout.
- `baxbench` - native BaxBench generation tasks, uses the same artifact adapter,
  and copies generated code to the benchmark results layout.

## Examples

Run Pi on SecureGen:

```bash
# From the repository root:
cd evaluation
.venv/bin/python harness/run_benchmark.py \
  --backend pi_cli --benchmark securegen \
  --num_instances 10 --model claude-opus-4.8
```

Run Codex on BaxBench:

```bash
.venv/bin/python harness/run_benchmark.py \
  --backend codex_cli --benchmark baxbench \
  --num_instances 10 --model gpt-5.5
```

Run Claude Code on SusVibes in parallel:

```bash
.venv/bin/python harness/run_benchmark_parallel.py \
  --backend claude_code --benchmark susvibes \
  --num_processes 4 --model claude-sonnet-4-20250514
```

The harness defaults to local Docker. Use `--execution_backend sandbox` with
`SANDBOX_BASE_URL` and `SANDBOX_API_KEY` for the remote sandbox service. Each
backend's `.env.sample` documents its credentials and endpoint variables.

Outputs default to `../results/cli/<benchmark>/<model>/` relative to this
directory. Temporary workspaces default to `../runtime/cli/`.

## Installation and Optional Dependencies

Use the evaluation root's `setup.sh` with Python 3.11 or newer. The CLI harness
can be installed without mini-swe-agent using `INSTALL_MINISWE_AGENT=0 ./setup.sh`.
Docker execution needs a host Docker command and daemon. Copilot also needs
host GitHub CLI authentication (`gh auth login`). Container setup scripts install
the selected agent CLI; they do not install this local `harness` package from PyPI.

SusVibes guardrail prompts and CWE descriptions are bundled. All six strategy
choices are available: `none`, `generic`, `self-selection`, `oracle`,
`feedback-driven`, and `sec-test`. Feedback-driven mode requires `--feedback_tool`;
sec-test mode requires each task's `test_patch`; CWE-based modes use task `cwe_ids`.

CLI dependency versions are recorded in each backend's `package.json` and
`package-lock.json`. The setup scripts install Node 22.23.2 and use `npm ci`.
To update a CLI, edit its exact package version, regenerate the lockfile with
that Node release, and rerun the backend smoke checks. Do not replace pinned
versions with `latest`. System packages remain supplied by the task image or its
OS repositories; use immutable image references when reproducing a run.

## Model Selection and Resume

`--model` selects the actual agent model and the `<model>` results directory.
Precedence is: explicit `--model`, backend model environment variable (including
its `.env` file), then the backend default. The resolved model is passed to
parallel workers. Use `--results_dir` to group experiments independently of
the model identifier.

Both runners resolve benchmark instance IDs before filtering and sharding, then
apply benchmark filters, skip IDs from `--load_from_file`, and apply
`--start_idx` / `--num_instances`. SecureGen uses `base_instance_id` when present.
Resume files may be result lists or dictionaries keyed by instance ID. Prior
records are included in the combined outputs when new tasks are processed.
Sequential runs default to two instances; parallel runs default to all remaining
instances. Parallel workers use the invoking Python interpreter unless
`--python_executable` is supplied.

Backend-specific scripts under `backends/<backend>/` are compatibility entrypoints.
The generic batch scripts default to SusVibes. Pi's `*_baxbench.py` scripts
default to AutoBax; select `--benchmark baxbench` for native BaxBench. Use the
unified entrypoints for new integrations. They also support
`python -m harness.run_benchmark` and `python -m harness.run_benchmark_parallel`
from `evaluation/`.

## Output Layout

```text
evaluation/results/cli/<benchmark>/<model>/
├── <timestamp>[_process<N>]/
│   ├── final_results.json
│   └── intermediate_*.json
├── patches/                       # Captured patches; empty for artifact benchmarks
├── merged_final_results.json      # Parallel runs
├── preds.json                     # Standard prediction manifest
├── baxbench_manifest.json         # AutoBax/BaxBench
└── <results_subdir>/              # Generated AutoBax/BaxBench application code
```

Parallel worker workspaces, temporary instance shards, and run summaries are
stored under `evaluation/runtime/cli/`. Both `results/` and `runtime/` are local
generated artifacts and are ignored by Git.

## Adding A Dataset

Add `benchmarks/<name>.py` with any of these optional hooks:

- `add_benchmark_args(parser)` and `filter_instances(instances, args)`
- `get_container_work_dir(instance)`
- `get_image_name(instance)`
- `get_instance_id(instance, index)`
- `build_prompt(instance, local_work_dir)`
- `postprocess_result(result, instance, workspace, integration, model, benchmark_output_root)`
- `finalize_results(results, results_dir, benchmark_output_root, args, model)`
- `CAPTURE_DIFF = False` for artifact-style benchmarks that do not submit patches.

Then register it in `registry.py`'s `DATASETS` map.

## Adding a Backend

Add a package under `backends/<name>/` with `config.py`, `setup-env.sh`, and
`.env.sample`, plus `package.json` and `package-lock.json` when using npm, then
register its directory name in `registry.BACKENDS`. `BackendConfig` supplies the
model environment key and fallback, environment and command builders, and an
optional `normalize_result(result)` callback for transcript-level failures.
Benchmark prompts belong in `benchmarks/`; new backends do not need their own
prompt copies or runner scripts. Existing setup and credential paths remain in
the backend directories.

## Offline Regression Checks

From `evaluation/`:

```bash
python -B -m unittest discover -s harness/tests -v
```

These tests cover model precedence, compatibility entry points, canonical resume
IDs, worker argument handling, failure normalization, and sequential/parallel
prediction and artifact equivalence across all four benchmarks. Execution and
worker processes are mocked; they do not launch Docker, call the sandbox
service, or access model providers. Live evaluations still require the normal
runtime dependencies and backend credentials.
