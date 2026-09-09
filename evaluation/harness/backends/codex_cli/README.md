# Codex CLI backend

This integration runs Codex CLI on the benchmarks supported by the
[shared harness](../../README.md), using Docker or a remote sandbox.

## Setup

Follow the [evaluation setup guide](../../../README.md), then run these commands
from `evaluation/`:

```bash
cp harness/backends/codex_cli/.env.sample harness/backends/codex_cli/.env
```

Configure `CODEX_API_KEY` and `CODEX_MODEL` in your environment or the
backend `.env` file. See `.env.sample` for endpoint and additional settings.

An explicit `--model` overrides the configured model. Use a model identifier
available through your configured provider.

Docker execution requires a running Docker daemon. Remote execution requires
`SANDBOX_BASE_URL`, `SANDBOX_API_KEY`, and `--execution_backend sandbox`.
The container setup script installs the CLI using the pinned npm lockfile;
it requires root privileges, `apt-get`, and network access in the task image.

## Run

```bash
.venv/bin/python harness/run_benchmark.py \
  --backend codex_cli --benchmark susvibes --num_instances 10

.venv/bin/python harness/run_benchmark_parallel.py \
  --backend codex_cli --benchmark securegen --num_processes 4
```

See the [shared harness guide](../../README.md) for data paths, model selection,
resume behavior, benchmark options, and output formats. Backend-specific batch
scripts are compatibility entrypoints; use the unified runners shown above.
