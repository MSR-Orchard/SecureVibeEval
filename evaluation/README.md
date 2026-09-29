# SecureVibeEval evaluation

This component runs and grades the SecureGen, AutoBax, BaxBench, and SusVibes
evaluation suites.

## Layout

```text
./                        # Repository root
└── evaluation/
    ├── swe_entry/            # SWE-agent evaluation entrypoints and model configurations
    ├── harness/              # Multi-CLI evaluation backends and adapters
    ├── grader/               # Benchmark grading implementations
    ├── .venv/                # Environment created by setup.sh
    ├── results/              # Generated evaluation and grading outputs
    ├── evaluate.sh
    ├── grade.sh
    ├── requirements.lock
    └── setup.sh
```

The entrypoints live in this directory. The compatible mini-swe-agent source,
including its SecureVibe sandbox integration, is bundled at
`../dependencies/vendor/mini-swe-agent` and installed in editable mode by
`setup.sh`. Its license and source checksum manifest are preserved. Set
`MINISWE_AGENT_DIR` only when intentionally using another compatible checkout.
The CLI harness and graders can also be installed independently.

Generated data, environments, results, logs, model weights, and Docker images
are intentionally excluded from Git.

## Task data

The sequence scripts and CLI harness default to `../data/raw` relative to this
directory. See [the data guide](../data/README.md) for local filenames and roles.
`DATA_DIR` overrides this location.


Set `SECUREVIBE_DATA_REPO` to a Hugging Face dataset repository you are
authorized to use that contains the required task data under `raw/`.
Authenticate if required, then download it to a persistent location:

```bash
hf auth login

SECUREVIBE_DATA_DIR=/path/to/securevibe-data
hf download "${SECUREVIBE_DATA_REPO:?Set SECUREVIBE_DATA_REPO to your dataset repository}" \
  --repo-type dataset \
  --include "raw/**" \
  --include SHA256SUMS \
  --local-dir "${SECUREVIBE_DATA_DIR}"

export DATA_DIR="${SECUREVIBE_DATA_DIR}/raw"

# Downloads retain upstream names; select them explicitly for the sequence scripts.
export SECUREGEN_TASKS="${DATA_DIR}/securegen/tasks_no_leak.jsonl"
export AUTOBAX_GENERIC_INSTANCES="${DATA_DIR}/autobax/autobax_sandbox_generic_security.json"
export AUTOBAX_INSTANCES="${DATA_DIR}/autobax/autobax_sandbox.json"
export BAXBENCH_NATIVE_INSTANCES="${DATA_DIR}/baxbench/baxbench_sandbox.json"
export BAXBENCH_SANDBOX_DATASET="$BAXBENCH_NATIVE_INSTANCES"
export SUSVIBES_INSTANCES="${DATA_DIR}/susvibes/susvibes.run_evaluation_generic_mini_instances.json"
export SUSVIBES_DATASET_PATH="${DATA_DIR}/susvibes/susvibes_dataset.jsonl"
```

The default 200-instance SecureGen evaluation also expects the derived runner
file `securegen_mini_instances.json`. Set
`SECUREGEN_INSTANCES` to its location if it is not placed under
`$DATA_DIR/securegen/`.

The repository's `SHA256SUMS` records the canonical hashes; verify the downloaded
files against it before use. The task images
named by these datasets must also be reachable by the selected sandbox service.

## Setup

Requirements are Python 3.11 or newer, Bash 4.3 or newer for the evaluation
sequence (it uses namerefs), `curl`, and network access. The default macOS Bash
3.2 cannot run that sequence. The host Python packages are pinned in
`requirements.lock`; Python 3.10 cannot resolve that lock.

```bash
# From the repository root:
cd evaluation
./setup.sh

# Alternatively, install only the CLI harness and grading dependencies:
INSTALL_MINISWE_AGENT=0 ./setup.sh
```

The SWE-agent sequence defaults to `sandbox` and requires `SANDBOX_BASE_URL` and
`SANDBOX_API_KEY`.

Host and container dependencies are separate:

- SWE-agent runners import `minisweagent` from the source checkout above.
- CLI Docker execution requires the `docker` command and a running daemon;
  sandbox execution requires service credentials. Copilot additionally requires
  host GitHub CLI (`gh`) authentication because its config calls `gh auth token`.
- CLI setup scripts run inside task containers as root. They install Node and
  the selected CLI; most expect Debian/Ubuntu `apt-get`. Node is pinned to
  22.23.2 and each backend uses `npm ci` with its committed `package-lock.json`.
  The execution adapter stages only those npm manifests alongside the script.
- AutoBax/BaxBench graders install scenario dependencies such as `imageio` and
  `pdfplumber` inside the sandbox. Those are intentionally absent from the host
  lock. Both graders use `grader/sandbox-requirements.lock` (Python >=3.10),
  including pinned transitive dependencies, and stop if installation fails.

## Model endpoint

Configure an OpenAI-compatible endpoint and its served model identifier before
running the sequence scripts. Start or connect to the model service separately.
For example, from `evaluation/`:

```bash
export LOCAL_BASE=http://127.0.0.1:8200/v1
export MODEL=openai/your-model
export OUTPUT_PREFIX=your-model
```

The scripts default to `openai/qwen35-sft` at the example address above if no
overrides are supplied. These defaults do not start a model service.

## Evaluate

```bash
# Resolve and print all commands without starting evaluations
DRY_RUN=1 ./evaluate.sh

# Run all eight suites sequentially
./evaluate.sh

# Run selected suites
RUNS=security-securegen,security-autobax ./evaluate.sh

# Run the functional SecureGen and AutoBax suites with explicit settings
RUNS=func-securegen,func-autobax \
WORKERS=32 \
MODEL=openai/qwen35-sft OUTPUT_PREFIX=qwen35-sft \
LOCAL_BASE=http://127.0.0.1:8200/v1 \
./evaluate.sh

# Use sticky, token-aware routing with a two-rank SGLang server
RUNS=func-securegen,func-autobax,baxbench,susvibes \
WORKERS=32 DP_SIZE=2 SHUFFLE_SEED=0 \
LOCAL_BASE=http://127.0.0.1:8200/v1 \
./evaluate.sh
```

Outputs are written under `results/<OUTPUT_PREFIX>/`. The default is
`OUTPUT_PREFIX=qwen35-sft`, so the expected evaluation output directory is
`results/qwen35-sft/`; it is created when an evaluation runs. `MODEL_LABEL`
defaults to the value of `OUTPUT_PREFIX`. Paths and concurrency can be
overridden using the environment variables defined at the top of the runner.
The evaluation runner validates the inputs required by the runs selected with
`RUNS` during preflight.

### SGLang data-parallel routing

`DP_SIZE` enables client-side SGLang DP-rank affinity in the SecureGen, AutoBax,
native BaxBench, and SusVibes batch runners. It must equal the `--dp-size` used
to launch the model server. For example, `WORKERS=32 DP_SIZE=2` caps each rank
at 16 active trajectories; `DP_SIZE=4` caps each rank at eight. Every model call
in a trajectory stays on its assigned rank, allowing its rank-local prefix/KV
cache to be reused.

When a new trajectory starts, the runner considers only ranks below their cap
and selects the lowest combined live-token and active-trajectory load. It reads
the per-rank `sglang:token_usage` gauges from the server's `/metrics` endpoint.
The metrics URL is derived automatically from `LOCAL_BASE`. For example,
`http://127.0.0.1:8200/v1` becomes
`http://127.0.0.1:8200/metrics`. There is no separate metrics URL setting. If
metrics cannot be read, routing remains sticky and falls back to selecting the
rank with the fewest active trajectories.

`SHUFFLE_SEED` controls deterministic ordering of pending instances after
resume filtering and defaults to `0`. The hash-based ordering is stable across
resumed runs; set a different integer to obtain another ordering.

Omitting `DP_SIZE` preserves normal endpoint routing and sends no explicit DP
rank. Setting `DP_SIZE=1` explicitly pins every trajectory to rank 0. Explicitly
routed requests do not use SGLang's server-side load-balancing method.

## Multi-CLI evaluation

The multi-CLI harness supports Claude Code, Codex, Copilot, Gemini, and Pi on
SecureGen, AutoBax, native BaxBench, and SusVibes. It uses the configured `DATA_DIR`, or the repository data directory by default.
For datasets with upstream filenames, pass the file explicitly with `--jsonl_file`.

```bash
# Sequential example
.venv/bin/python harness/run_benchmark.py \
  --backend codex_cli \
  --benchmark securegen \
  --num_instances 10 \
  --model qwen35-sft

# Parallel example
.venv/bin/python harness/run_benchmark_parallel.py \
  --backend pi_cli \
  --benchmark autobax \
  --num_processes 4 \
  --model qwen35-sft
```

`--model` selects the invoked model as well as its result metadata; when omitted,
the backend environment/configuration supplies the model.

CLI outputs are written under `results/cli/<benchmark>/<model>/`. Runtime
workspaces are written under `runtime/cli/`. See
`harness/README.md` for backend setup and credential details.

## Grade

After evaluation outputs exist, grade all suites with:

```bash
./grade.sh

# Grade the functional SecureGen and AutoBax outputs
RUNS=func-securegen,func-autobax \
WORKERS=32 \
OUTPUT_PREFIX=qwen35-sft \
./grade.sh
```

The grader reads paired outputs under `results/<OUTPUT_PREFIX>/` and writes:

```text
results/<OUTPUT_PREFIX>/grades/
├── securegen/
├── autobax/
├── baxbench/
└── susvibes/
```

Its dry run validates the grading configuration without requiring generated
evaluation outputs:

```bash
DRY_RUN=1 ./grade.sh
```

BaxBench's resumable per-sample `test_results.json` files remain beside the
generated code. Its aggregate report and grader log are written under the
unified grade directory.

The `grader/` directory contains the runtime used by these sequence scripts:

- `securegen/src/`: functional and security-plan graders, Docker/sandbox backends.
- `autobax/src/`: sandbox and security-plan graders, registered scenarios and fixtures.
- `baxbench/src/`: sandbox grader, registered scenarios and fixtures.
- `susvibes/susvibes/`: prediction grading, Docker/sandbox backends, and the default/train test-log parsers.

Evaluation generation uses `swe_entry/` through `evaluate.sh`.
SusVibes grading accepts predictions directly; its default dataset path is
`grader/susvibes/datasets/default/susvibes_dataset.jsonl`, overridable with
`--dataset_path`. The `--agent` option remains accepted for script compatibility.


Public grading entrypoints are `grader/<benchmark>/grade.py` and, for SecureGen
and AutoBax, `grade_plans.py`. See [the grading guide](grader/README.md) for
benchmark inputs, backends, outputs, and regression-test instructions.

## Dependency regression checks

After setup, run these offline checks from the evaluation root:

```bash
.venv/bin/python -B -m unittest discover -s tests -p test_dependencies.py -v
.venv/bin/python -B -m unittest discover -s tests/grading -v
.venv/bin/python -B -m unittest discover -s harness/tests -v
```

They check the vendored source hashes, every guardrail mode, manifest staging,
and grader failure handling without launching task containers or calling models.

## Benchmark resource overrides

Set `BAXBENCH_SANDBOX_MEMORY`, `BAXBENCH_HEAVY_SANDBOX_MEMORY`, and
`BAXBENCH_BOUNDED_FILESEARCH_TRAVERSAL` explicitly when a benchmark run needs
custom memory limits or bounded traversal. Record these settings alongside
results so other users can reproduce the grading configuration.
