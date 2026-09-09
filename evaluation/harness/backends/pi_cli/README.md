# Pi CLI backend

This integration runs Pi CLI on the benchmarks supported by the
[shared harness](../../README.md), using Docker or a remote sandbox.

## Setup

Follow the [evaluation setup guide](../../../README.md), then run these commands
from `evaluation/`:

```bash
cp harness/backends/pi_cli/.env.sample harness/backends/pi_cli/.env
```

Configure `PI_PROVIDER`, `PI_MODEL`, `PI_PROXY_BASE_URL`, and `PI_API_KEY`
for your provider. The default configuration expects an independently managed
proxy at `http://127.0.0.1:8080`; the harness does not start that proxy. Set an
address reachable from the task container or remote sandbox.

An explicit `--model` overrides the configured model. Use a model identifier
available through your configured provider.

Docker execution requires a running Docker daemon. Remote execution requires
`SANDBOX_BASE_URL`, `SANDBOX_API_KEY`, and `--execution_backend sandbox`.
The container setup script installs the CLI using the pinned npm lockfile;
it requires root privileges, `apt-get`, and network access in the task image.

## Run

```bash
.venv/bin/python harness/run_benchmark.py \
  --backend pi_cli --benchmark susvibes --num_instances 10

.venv/bin/python harness/run_benchmark_parallel.py \
  --backend pi_cli --benchmark securegen --num_processes 4
```

See the [shared harness guide](../../README.md) for data paths, model selection,
resume behavior, benchmark options, and output formats. Backend-specific batch
scripts are compatibility entrypoints; use the unified runners shown above.
